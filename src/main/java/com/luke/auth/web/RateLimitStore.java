package com.luke.auth.web;

/**
 * A rate-limit decision for a key (#56). Two implementations: {@link RateLimiter} (in-memory,
 * per-instance — the default and the fallback) and {@link RedisRateLimitStore} (shared across
 * all workers when {@code REDIS_URL} is set).
 */
public interface RateLimitStore {

    /**
     * Record a hit for {@code key} at {@code nowMillis}.
     *
     * @return {@code -1} if the hit is allowed; otherwise the Retry-After in seconds (&ge; 1).
     */
    long retryAfterSeconds(String key, long nowMillis);
}
