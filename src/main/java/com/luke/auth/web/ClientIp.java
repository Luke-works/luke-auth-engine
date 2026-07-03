package com.luke.auth.web;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Resolves the real client IP from {@code X-Forwarded-For}. The leftmost hop is
 * client-authored and spoofable, so with {@code trustedProxyHops} reverse proxies in
 * front (Render LB, Cloudflare…) the real client is the Nth entry counted from the RIGHT.
 * {@code trustedProxyHops <= 0} keeps the legacy leftmost behaviour (local/single-hop dev).
 *
 * <p>Shared by {@link AuthRateLimitFilter} (rate-limit key) and {@code AuditService}
 * (audit-log source IP) so neither can be fooled by a prepended {@code X-Forwarded-For}.
 */
public final class ClientIp {

    private ClientIp() {}

    public static String resolve(HttpServletRequest req, int trustedProxyHops) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            String[] hops = xff.split(",");
            if (trustedProxyHops <= 0) {
                return hops[0].trim(); // legacy: leftmost (dev/single-hop)
            }
            int idx = Math.max(0, hops.length - trustedProxyHops);
            return hops[Math.min(idx, hops.length - 1)].trim();
        }
        return req.getRemoteAddr();
    }
}
