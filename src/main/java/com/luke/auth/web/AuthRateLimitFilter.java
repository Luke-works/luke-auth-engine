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

    public AuthRateLimitFilter(
            @Value("${luke.auth.ratelimit.max-requests:10}") int maxRequests,
            @Value("${luke.auth.ratelimit.window-seconds:60}") long windowSeconds,
            @Value("${luke.auth.ratelimit.max-keys:50000}") int maxKeys) {
        this.limiter = new RateLimiter(maxRequests, windowSeconds * 1000, maxKeys);
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

    /** Behind Render/Cloudflare, the real client is the leftmost X-Forwarded-For hop. */
    private static String clientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            int comma = xff.indexOf(',');
            return (comma > 0 ? xff.substring(0, comma) : xff).trim();
        }
        return req.getRemoteAddr();
    }
}
