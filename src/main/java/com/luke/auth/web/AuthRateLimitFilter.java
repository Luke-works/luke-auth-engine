package com.luke.auth.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import com.luke.auth.config.LukeAuthProperties;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Throttles the credential / token-minting endpoints (#25) to blunt credential
 * stuffing, password brute-forcing, and service-key guessing. Per client IP +
 * path, fixed window; over-limit gets a uniform 429 + Retry-After (no detail that
 * would aid enumeration) and is logged for alerting.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class AuthRateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AuthRateLimitFilter.class);

    private static final Set<String> LIMITED_PATHS = Set.of(
            "/auth/login", "/auth/register", "/auth/password", "/service/token");

    /** In-memory (per-instance) or Redis-backed (global) depending on REDIS_URL — see RateLimitConfig (#56). */
    private final RateLimitStore limiter;
    /** Number of TRUSTED reverse proxies in front of this service (Render LB, Cloudflare…).
     *  The leftmost X-Forwarded-For hop is client-authored and spoofable, so with N trusted
     *  proxies the real client is the Nth entry counted from the right. Default 0 keeps the
     *  legacy leftmost behaviour (unchanged for local/single-hop dev); set it to the actual
     *  trusted-proxy count in prod so an attacker can't rotate the key by prepending IPs. */
    private final int trustedProxyHops;

    public AuthRateLimitFilter(RateLimitStore limiter, LukeAuthProperties props) {
        this.limiter = limiter;
        this.trustedProxyHops = Math.max(0, props.getRatelimit().getTrustedProxyHops());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        if ("POST".equalsIgnoreCase(req.getMethod()) && LIMITED_PATHS.contains(req.getServletPath())) {
            String ip = clientIp(req);
            long retryAfter = limiter.retryAfterSeconds(ip + "|" + req.getServletPath(), System.currentTimeMillis());
            if (retryAfter >= 0) {
                log.warn("Rate limit exceeded: ip={} path={} retryAfter={}s", ip, req.getServletPath(), retryAfter);
                res.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                res.setHeader("Retry-After", String.valueOf(retryAfter));
                res.setContentType("application/json");
                res.getWriter().write(
                        "{\"error\":\"Too Many Requests\",\"message\":\"Too many attempts. Please try again later.\"}");
                return;
            }
        }
        chain.doFilter(req, res);
    }

    private String clientIp(HttpServletRequest req) {
        return ClientIp.resolve(req, trustedProxyHops);
    }
}
