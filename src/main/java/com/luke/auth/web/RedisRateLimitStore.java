package com.luke.auth.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A shared, cross-instance fixed-window rate limiter backed by Redis (#56).
 *
 * <p>The count for {@code (key, window-bucket)} is kept in Redis, so the limit is enforced
 * <b>globally</b> across every gateway replica — a horizontally-scaled deployment can't be used
 * to multiply the per-endpoint credential-abuse limit. Same fixed-window semantics as the
 * in-memory {@link RateLimiter}, so behaviour is consistent whether Redis is configured or not.
 *
 * <p><b>Fail-safe:</b> if the Redis call throws (Redis down / network blip), this degrades to the
 * injected in-memory fallback for that hit rather than failing the request open — throttling
 * still happens per-instance until Redis recovers.
 *
 * <p>The atomic increment + first-hit expiry is a tiny server-side script so the window can't
 * leak (an {@code INCR} without a paired {@code PEXPIRE} would live forever); it is provided as a
 * {@link WindowCounter} so the fixed-window logic here is unit-testable without a live Redis.
 */
public class RedisRateLimitStore implements RateLimitStore, AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(RedisRateLimitStore.class);

    /** Atomically increments the bucket's counter (setting its TTL on the first hit) and returns
     *  the new count. Throws on any backend failure so the store can fall back. */
    @FunctionalInterface
    public interface WindowCounter {
        long increment(String bucketKey, long windowMillis);
    }

    private final int maxRequests;
    private final long windowMillis;
    private final WindowCounter counter;
    private final RateLimitStore fallback;
    private final AutoCloseable[] resources;

    public RedisRateLimitStore(int maxRequests, long windowMillis, WindowCounter counter,
                               RateLimitStore fallback, AutoCloseable... resources) {
        this.maxRequests = Math.max(1, maxRequests);
        this.windowMillis = Math.max(1, windowMillis);
        this.counter = counter;
        this.fallback = fallback;
        this.resources = resources;
    }

    @Override
    public long retryAfterSeconds(String key, long nowMillis) {
        long bucket = nowMillis / windowMillis;
        // {key} hash-tag keeps the bucket on one slot under Redis Cluster.
        String bucketKey = "authrl:{" + key + "}:" + bucket;
        long count;
        try {
            count = counter.increment(bucketKey, windowMillis);
        } catch (RuntimeException e) {
            log.warn("Rate-limit Redis call failed; degrading to in-memory for this hit: {}", e.toString());
            return fallback.retryAfterSeconds(key, nowMillis);
        }
        if (count <= maxRequests) {
            return -1;
        }
        long resetInMillis = (bucket + 1) * windowMillis - nowMillis;
        return Math.max(1, (resetInMillis + 999) / 1000); // ceil to seconds, min 1
    }

    @Override
    public void close() {
        for (AutoCloseable r : resources) {
            try {
                if (r != null) {
                    r.close();
                }
            } catch (Exception e) {
                log.debug("Error closing rate-limit Redis resource: {}", e.toString());
            }
        }
    }
}
