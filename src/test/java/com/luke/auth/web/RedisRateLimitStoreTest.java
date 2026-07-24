package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.luke.auth.web.RedisRateLimitStore.WindowCounter;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * #56: the fixed-window logic and the fail-safe fallback of the shared limiter, exercised with a
 * fake counter so it runs anywhere (the real Redis wiring is covered by
 * {@link RedisRateLimitIntegrationTest}).
 */
class RedisRateLimitStoreTest {

    /** A stand-in for Redis INCR+PEXPIRE: counts per bucket key (the bucket number is in the key,
     *  so a new time window is a new key → count resets). */
    private static final class FakeCounter implements WindowCounter {
        final Map<String, Long> counts = new HashMap<>();
        boolean fail = false;

        @Override
        public long increment(String bucketKey, long windowMillis) {
            if (fail) {
                throw new RuntimeException("redis unavailable");
            }
            return counts.merge(bucketKey, 1L, Long::sum);
        }
    }

    private static RateLimitStore lenientFallback() {
        return new RateLimiter(1000, 60_000, 100); // effectively unlimited unless we assert on it
    }

    @Test
    void allowsUpToMaxThenLimits() {
        RedisRateLimitStore s = new RedisRateLimitStore(3, 60_000, new FakeCounter(), lenientFallback());
        long now = 1_000_000L;
        assertEquals(-1, s.retryAfterSeconds("ip|/auth/login", now));
        assertEquals(-1, s.retryAfterSeconds("ip|/auth/login", now));
        assertEquals(-1, s.retryAfterSeconds("ip|/auth/login", now));
        long retryAfter = s.retryAfterSeconds("ip|/auth/login", now); // 4th in the window
        assertTrue(retryAfter >= 1, "over-limit hit must report a Retry-After");
    }

    @Test
    void differentKeysAreIndependent() {
        RedisRateLimitStore s = new RedisRateLimitStore(1, 60_000, new FakeCounter(), lenientFallback());
        long now = 1_000_000L;
        assertEquals(-1, s.retryAfterSeconds("a|/p", now));
        assertEquals(-1, s.retryAfterSeconds("b|/p", now)); // different key — its own window
        assertTrue(s.retryAfterSeconds("a|/p", now) >= 1);  // a is now over
    }

    @Test
    void nextWindowResets() {
        RedisRateLimitStore s = new RedisRateLimitStore(1, 60_000, new FakeCounter(), lenientFallback());
        long now = 60_000L * 5;
        assertEquals(-1, s.retryAfterSeconds("k", now));
        assertTrue(s.retryAfterSeconds("k", now) >= 1, "second hit in the same window is limited");
        assertEquals(-1, s.retryAfterSeconds("k", now + 60_000), "next window allows again");
    }

    @Test
    void fallsBackToInMemoryWhenRedisFails() {
        FakeCounter failing = new FakeCounter();
        failing.fail = true;
        // Fallback with max=2 so we can prove the fallback path is what's deciding.
        RedisRateLimitStore s = new RedisRateLimitStore(1, 60_000, failing, new RateLimiter(2, 60_000, 100));
        long now = 1000L;
        assertEquals(-1, s.retryAfterSeconds("k", now)); // fallback allows (1/2)
        assertEquals(-1, s.retryAfterSeconds("k", now)); // fallback allows (2/2)
        assertTrue(s.retryAfterSeconds("k", now) >= 1, "fallback limit (2) applies when Redis is down");
    }
}
