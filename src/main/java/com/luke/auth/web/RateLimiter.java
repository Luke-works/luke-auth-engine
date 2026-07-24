package com.luke.auth.web;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A small fixed-window rate limiter (#25). Per-key: at most {@code maxRequests}
 * hits per {@code windowMillis}; further hits report a Retry-After. In-memory and
 * therefore per-instance — the default, and the fallback for {@link RedisRateLimitStore}
 * when a shared cross-instance limit ({@code REDIS_URL}) isn't configured or Redis is down (#56).
 * The key space is bounded ({@code maxKeys}) with lazy eviction of expired windows.
 */
public class RateLimiter implements RateLimitStore {

    private final int maxRequests;
    private final long windowMillis;
    private final int maxKeys;
    // key -> [windowStartMillis, count]
    private final Map<String, long[]> windows = new ConcurrentHashMap<>();

    public RateLimiter(int maxRequests, long windowMillis, int maxKeys) {
        this.maxRequests = Math.max(1, maxRequests);
        this.windowMillis = Math.max(1, windowMillis);
        this.maxKeys = Math.max(1, maxKeys);
    }

    /**
     * Record a hit for {@code key} at {@code nowMillis}.
     * @return {@code -1} if allowed; otherwise the Retry-After in seconds (&ge; 1).
     */
    @Override
    public long retryAfterSeconds(String key, long nowMillis) {
        long[] out = {-1};
        windows.compute(key, (k, w) -> {
            if (w == null || nowMillis - w[0] >= windowMillis) {
                return new long[] {nowMillis, 1}; // new window
            }
            if (w[1] < maxRequests) {
                w[1]++;
                return w;
            }
            long resetInMillis = (w[0] + windowMillis) - nowMillis;
            out[0] = Math.max(1, (resetInMillis + 999) / 1000); // ceil to seconds, min 1
            return w;
        });
        if (windows.size() > maxKeys) {
            windows.entrySet().removeIf(e -> nowMillis - e.getValue()[0] >= windowMillis);
        }
        return out[0];
    }
}
