package com.luke.auth.web;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Per-upstream circuit breaker for the engine proxy (D1). When an upstream (core-engine / file-proxy)
 * fails repeatedly, the breaker OPENS and the gateway fails fast with 503 for a short cooldown instead
 * of making every caller wait out the full connect/read timeout on a service that is plainly down —
 * which is exactly how a downstream outage turns into a gateway thread/connection pile-up (and then a
 * gateway outage). After the cooldown one request is allowed through (HALF_OPEN); its success CLOSES the
 * circuit, its failure RE-OPENS it.
 *
 * <p>DEFAULT-LENIENT: it only ever opens after {@code failureThreshold} CONSECUTIVE real failures
 * (timeouts / connection errors / upstream 5xx), so a healthy upstream is never throttled; a single blip
 * resets on the next success. It can be disabled outright with
 * {@code luke.auth.proxy.circuit-breaker.enabled=false}. State is per upstream base-URL, so a sick core
 * never trips the breaker for a healthy file-proxy. A time source is injected for deterministic tests.
 */
@Component
public class UpstreamCircuitBreaker {

    private static final Logger log = LoggerFactory.getLogger(UpstreamCircuitBreaker.class);

    enum State { CLOSED, OPEN, HALF_OPEN }

    private final boolean enabled;
    private final int failureThreshold;
    private final long openMillis;
    private final LongSupplier clock;
    private final Map<String, Breaker> breakers = new ConcurrentHashMap<>();

    @Autowired
    public UpstreamCircuitBreaker(
            @Value("${luke.auth.proxy.circuit-breaker.enabled:true}") boolean enabled,
            @Value("${luke.auth.proxy.circuit-breaker.failure-threshold:5}") int failureThreshold,
            @Value("${luke.auth.proxy.circuit-breaker.open-seconds:15}") long openSeconds) {
        this(enabled, failureThreshold, openSeconds, System::currentTimeMillis);
    }

    /** Test seam: inject a deterministic clock (millis). */
    UpstreamCircuitBreaker(boolean enabled, int failureThreshold, long openSeconds, LongSupplier clock) {
        this.enabled = enabled;
        this.failureThreshold = Math.max(1, failureThreshold);
        this.openMillis = Math.max(0, openSeconds) * 1000L;
        this.clock = clock;
        log.info("UpstreamCircuitBreaker: enabled={} threshold={} open={}s", enabled, this.failureThreshold, openSeconds);
    }

    /** @return true if a request to {@code key} may proceed; false if the circuit is OPEN (fail fast). */
    public boolean allowRequest(String key) {
        if (!enabled) {
            return true;
        }
        return breakers.computeIfAbsent(key, k -> new Breaker()).allow(clock.getAsLong(), openMillis);
    }

    public void recordSuccess(String key) {
        if (!enabled) {
            return;
        }
        Breaker b = breakers.get(key);
        if (b != null) {
            b.onSuccess();
        }
    }

    public void recordFailure(String key) {
        if (!enabled) {
            return;
        }
        breakers.computeIfAbsent(key, k -> new Breaker())
                .onFailure(clock.getAsLong(), failureThreshold, openMillis, key);
    }

    /** Seconds until an OPEN circuit next admits a probe (for a Retry-After header); 0 when not open. */
    public long retryAfterSeconds(String key) {
        Breaker b = breakers.get(key);
        return b == null ? 0 : b.retryAfterSeconds(clock.getAsLong(), openMillis);
    }

    /** One upstream's state. All transitions are synchronized — contention is trivial (a few fields). */
    private static final class Breaker {
        private State state = State.CLOSED;
        private int consecutiveFailures = 0;
        private long openedAt = 0;

        synchronized boolean allow(long now, long openMillis) {
            if (state == State.OPEN) {
                if (now - openedAt >= openMillis) {
                    state = State.HALF_OPEN; // admit a single probe
                    return true;
                }
                return false;
            }
            return true; // CLOSED or HALF_OPEN
        }

        synchronized void onSuccess() {
            state = State.CLOSED;
            consecutiveFailures = 0;
        }

        synchronized void onFailure(long now, int threshold, long openMillis, String key) {
            consecutiveFailures++;
            // A failure while probing (HALF_OPEN) re-opens immediately; otherwise open once the
            // consecutive-failure threshold is crossed.
            if (state == State.HALF_OPEN || consecutiveFailures >= threshold) {
                if (state != State.OPEN) {
                    log.warn("Circuit OPEN for upstream {} after {} consecutive failures; failing fast for {} ms",
                            key, consecutiveFailures, openMillis);
                }
                state = State.OPEN;
                openedAt = now;
            }
        }

        synchronized long retryAfterSeconds(long now, long openMillis) {
            if (state != State.OPEN) {
                return 0;
            }
            long remain = (openedAt + openMillis) - now;
            return remain <= 0 ? 0 : (remain + 999) / 1000;
        }
    }
}
