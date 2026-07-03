package com.luke.auth.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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

    private final RateLimiter limiter;
    /** Number of TRUSTED reverse proxies in front of this service (Render LB, Cloudflare…).
     *  The leftmost X-Forwarded-For hop is client-authored and spoofable, so with N trusted
     *  proxies the real client is the Nth entry counted from the right. Default 0 keeps the
     *  legacy leftmost behaviour (unchanged for local/single-hop dev); set it to the actual
     *  trusted-proxy count in prod so an attacker can't rotate the key by prepending IPs. */
    private final int trustedProxyHops;

    public AuthRateLimitFilter(
            @Value("${luke.auth.ratelimit.max-requests:10}") int maxRequests,
            @Value("${luke.auth.ratelimit.window-seconds:60}") long windowSeconds,
            @Value("${luke.auth.ratelimit.max-keys:50000}") int maxKeys,
            @Value("${luke.auth.ratelimit.trusted-proxy-hops:0}") int trustedProxyHops) {
        this.limiter = new RateLimiter(maxRequests, windowSeconds * 1000, maxKeys);
        this.trustedProxyHops = Math.max(0, trustedProxyHops);
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

    /** Resolve the client IP from X-Forwarded-For, counting {@code trustedProxyHops}
     *  entries from the RIGHT (the trustworthy end appended by our own proxies) rather
     *  than the spoofable leftmost hop. Falls back to the remote address. */
    private String clientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            String[] hops = xff.split(",");
            if (trustedProxyHops <= 0) {
                return hops[0].trim(); // legacy: leftmost (dev/single-hop)
            }
            // N trusted proxies → the client is the Nth from the right, clamped in-bounds.
            int idx = Math.max(0, hops.length - trustedProxyHops);
            return hops[Math.min(idx, hops.length - 1)].trim();
        }
        return req.getRemoteAddr();
    }
}
