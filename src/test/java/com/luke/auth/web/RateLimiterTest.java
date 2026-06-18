package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** #25: fixed-window limiter — allows N per window, then reports Retry-After. */
class RateLimiterTest {

    @Test
    void allowsUpToLimitThenThrottles() {
        RateLimiter rl = new RateLimiter(3, 60_000, 1000);
        long t = 1_000;
        assertEquals(-1, rl.retryAfterSeconds("k", t));
        assertEquals(-1, rl.retryAfterSeconds("k", t));
        assertEquals(-1, rl.retryAfterSeconds("k", t));
        long retry = rl.retryAfterSeconds("k", t); // 4th in the window
        assertTrue(retry >= 1, "should be throttled with a Retry-After");
    }

    @Test
    void windowResetsAllowsAgain() {
        RateLimiter rl = new RateLimiter(1, 60_000, 1000);
        long t = 1_000;
        assertEquals(-1, rl.retryAfterSeconds("k", t));
        assertTrue(rl.retryAfterSeconds("k", t) >= 1); // 2nd is blocked
        assertEquals(-1, rl.retryAfterSeconds("k", t + 60_000)); // next window
    }

    @Test
    void keysAreIndependent() {
        RateLimiter rl = new RateLimiter(1, 60_000, 1000);
        long t = 1_000;
        assertEquals(-1, rl.retryAfterSeconds("a", t));
        assertEquals(-1, rl.retryAfterSeconds("b", t)); // different key, own budget
        assertTrue(rl.retryAfterSeconds("a", t) >= 1);
    }
}
