package com.luke.auth.config;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Reachability of core-engine, the gateway's critical downstream (#26). The capability
 * domain was merged into core-engine, so this one check covers both.
 *
 * <p><b>Lenient by design:</b> any HTTP answer counts as reachable (the gateway can
 * forward), even a 5xx from core's own health — the gateway shouldn't fall out of
 * rotation just because core is momentarily degraded but answering. Only a transport
 * failure (connect refused / timeout) is {@code DOWN}. The probe uses a short timeout and
 * is cached briefly so frequent health polls don't hammer core, and never blocks a
 * request thread. Assigned to the {@code readiness} group only; {@code liveness} is
 * unaffected, so a core blip can never trigger a restart of the gateway.
 */
@Component("coreEngine")
public class CoreEngineHealthIndicator implements HealthIndicator {

    private static final long CACHE_TTL_MILLIS = 10_000;
    private static final Duration PROBE_TIMEOUT = Duration.ofSeconds(2);

    private final String coreHealthUrl;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(PROBE_TIMEOUT).build();

    private record Cached(Health health, long at) {}
    private volatile Cached cache;

    public CoreEngineHealthIndicator(@Value("${luke.auth.core-engine.base-url}") String coreBaseUrl) {
        String base = coreBaseUrl.endsWith("/") ? coreBaseUrl.substring(0, coreBaseUrl.length() - 1) : coreBaseUrl;
        this.coreHealthUrl = base + "/actuator/health";
    }

    @Override
    public Health health() {
        Cached c = cache;
        long now = System.currentTimeMillis();
        if (c != null && now - c.at() < CACHE_TTL_MILLIS) {
            return c.health();
        }
        Health h = probe();
        cache = new Cached(h, now);
        return h;
    }

    private Health probe() {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(coreHealthUrl))
                    .timeout(PROBE_TIMEOUT).GET().build();
            HttpResponse<Void> res = http.send(req, HttpResponse.BodyHandlers.discarding());
            // Got a response ⇒ core is reachable and the gateway can forward. Report the
            // status for observability, but stay UP even on a non-2xx (core answered).
            return Health.up().withDetail("coreEngine", "reachable").withDetail("upstreamStatus", res.statusCode()).build();
        } catch (Exception e) {
            // Connection refused / timeout — the gateway genuinely can't reach its downstream.
            return Health.down().withDetail("coreEngine", "unreachable").build();
        }
    }
}
