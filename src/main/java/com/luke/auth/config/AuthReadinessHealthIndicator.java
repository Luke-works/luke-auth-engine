package com.luke.auth.config;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Readiness gate for the gateway's core job (#26): can this instance actually
 * authenticate anyone? It is {@code DOWN} when the WorkOS verifier initialised
 * fail-closed (no JWKS decoder — bad/missing WorkOS config) or the act-as signing
 * key isn't ready. Assigned to the {@code readiness} group, so an orchestrator stops
 * routing to an instance that would 401 every request — without restarting it
 * (restart is driven by {@code liveness}, which never depends on this).
 */
@Component("authReadiness")
public class AuthReadinessHealthIndicator implements HealthIndicator {

    private final WorkosTokenVerifier verifier;
    private final GatewayKeys keys;

    public AuthReadinessHealthIndicator(WorkosTokenVerifier verifier, GatewayKeys keys) {
        this.verifier = verifier;
        this.keys = keys;
    }

    @Override
    public Health health() {
        boolean workosReady = verifier.isConfigured();
        boolean signingReady = keys.isReady();
        Health.Builder b = (workosReady && signingReady) ? Health.up() : Health.down();
        b.withDetail("workosVerifier", workosReady ? "configured" : "not-configured");
        b.withDetail("signingKey", signingReady ? "ready" : "missing");
        return b.build();
    }
}
