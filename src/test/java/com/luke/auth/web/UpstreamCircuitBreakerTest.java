package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/** The circuit breaker's state machine — deterministic via an injected clock. */
class UpstreamCircuitBreakerTest {

    private static final String K = "http://core";
    private final AtomicLong now = new AtomicLong(0);

    private UpstreamCircuitBreaker breaker(boolean enabled, int threshold, long openSec) {
        return new UpstreamCircuitBreaker(enabled, threshold, openSec, now::get);
    }

    @Test
    void closedInitiallyAllows() {
        assertTrue(breaker(true, 3, 10).allowRequest(K));
    }

    @Test
    void opensAfterThresholdConsecutiveFailuresThenFailsFast() {
        UpstreamCircuitBreaker cb = breaker(true, 3, 10);
        cb.recordFailure(K);
        cb.recordFailure(K);
        assertTrue(cb.allowRequest(K), "still closed below threshold");
        cb.recordFailure(K); // 3rd → open
        assertFalse(cb.allowRequest(K), "open after threshold");
        assertEquals(10, cb.retryAfterSeconds(K));
    }

    @Test
    void aSuccessResetsTheConsecutiveFailureCount() {
        UpstreamCircuitBreaker cb = breaker(true, 3, 10);
        cb.recordFailure(K);
        cb.recordFailure(K);
        cb.recordSuccess(K); // reset — a single blip doesn't accumulate toward opening
        cb.recordFailure(K);
        cb.recordFailure(K);
        assertTrue(cb.allowRequest(K), "two failures after a reset is still below threshold");
    }

    @Test
    void halfOpenProbeAfterCooldownClosesOnSuccess() {
        UpstreamCircuitBreaker cb = breaker(true, 2, 10);
        cb.recordFailure(K);
        cb.recordFailure(K); // open
        assertFalse(cb.allowRequest(K));
        now.addAndGet(10_000); // cooldown elapses
        assertTrue(cb.allowRequest(K), "half-open admits a probe");
        cb.recordSuccess(K); // probe ok → closed
        assertTrue(cb.allowRequest(K));
        assertEquals(0, cb.retryAfterSeconds(K));
    }

    @Test
    void halfOpenProbeFailureReopensImmediately() {
        UpstreamCircuitBreaker cb = breaker(true, 2, 10);
        cb.recordFailure(K);
        cb.recordFailure(K); // open
        now.addAndGet(10_000);
        assertTrue(cb.allowRequest(K), "half-open probe admitted");
        cb.recordFailure(K); // probe fails → re-open
        assertFalse(cb.allowRequest(K), "re-opened after a failed probe");
    }

    @Test
    void stateIsPerUpstream() {
        UpstreamCircuitBreaker cb = breaker(true, 2, 10);
        cb.recordFailure("http://core");
        cb.recordFailure("http://core"); // core opens
        assertFalse(cb.allowRequest("http://core"));
        assertTrue(cb.allowRequest("http://file-proxy"), "a healthy upstream is unaffected");
    }

    @Test
    void disabledAlwaysAllowsAndNeverOpens() {
        UpstreamCircuitBreaker cb = breaker(false, 1, 10);
        cb.recordFailure(K);
        cb.recordFailure(K);
        cb.recordFailure(K);
        assertTrue(cb.allowRequest(K));
        assertEquals(0, cb.retryAfterSeconds(K));
    }
}
