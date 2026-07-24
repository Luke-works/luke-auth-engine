package com.luke.auth.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;

/**
 * #26 — the liveness/readiness split must keep an instance ALIVE (so the platform
 * doesn't restart it) even when it can't do its job, while readiness accurately
 * reports not-ready. In this test there is no WorkOS config, so the gateway can
 * authenticate no one: liveness is UP, readiness is DOWN.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class HealthProbesTest {

    @Autowired
    private TestRestTemplate rest;

    @Test
    void livenessIsUpEvenWhenDependenciesAreNot() {
        // Render health-checks THIS path — it must stay UP as long as the process runs,
        // so a WorkOS/core-engine blip can never trigger a restart.
        ResponseEntity<String> r = rest.getForEntity("/actuator/health/liveness", String.class);
        assertEquals(200, r.getStatusCode().value());
        assertTrue(r.getBody() != null && r.getBody().contains("UP"));
    }

    @Test
    void readinessIsDownWhenTheGatewayCannotAuthenticate() {
        // No WorkOS decoder configured in test ⇒ authReadiness DOWN ⇒ readiness group DOWN.
        // The instance stays alive (previous test) but is correctly withheld from routing.
        ResponseEntity<String> r = rest.getForEntity("/actuator/health/readiness", String.class);
        assertEquals(503, r.getStatusCode().value());
    }

    @Test
    void publicProbeDoesNotLeakComponentDetails() {
        // show-details is now 'when-authorized' — an anonymous caller sees the status but
        // not the internal component breakdown (which named WorkOS/core/keys).
        ResponseEntity<String> r = rest.getForEntity("/actuator/health", String.class);
        String body = r.getBody() == null ? "" : r.getBody();
        assertTrue(!body.contains("workosVerifier") && !body.contains("coreEngine"),
                "anonymous health must not expose component details: " + body);
    }
}
