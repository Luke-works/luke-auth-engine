package com.luke.auth.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/**
 * Prod fail-fast (#35, extending #33/#27): the gateway must not boot in a hardened posture
 * unless WorkOS credentials, strict token validation, a stable signing key, non-local CORS
 * and dev-mode-off ALL hold — and must never fail a dev/qa boot. Mirrors {@link DevModeGuardTest}.
 */
class AuthHardeningGuardTest {

    /** Everything a production deploy is required to set. */
    private static LukeAuthProperties hardenedProps() {
        LukeAuthProperties p = new LukeAuthProperties();
        p.getWorkos().setClientId("client_123");
        p.getWorkos().setApiKey("sk_live_123");
        p.getWorkos().setStrictValidation(true);
        p.getWorkos().setIssuer("https://api.workos.com");
        p.getWorkos().setAudience("client_123");
        p.getGateway().setRequireStableKey(true);
        return p;
    }

    private static LukeCorsProperties cors(String origins) {
        LukeCorsProperties c = new LukeCorsProperties();
        c.setAllowedOrigins(origins);
        return c;
    }

    private static MockEnvironment prod() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        return env;
    }

    @Test
    void devWithoutHardeningBootsRegardlessOfConfig() {
        // No 'prod' profile and require-hardened=false → never throws. This is the constraint
        // that keeps dev/qa (no WorkOS creds, ephemeral key, localhost CORS) alive.
        assertDoesNotThrow(() -> new AuthHardeningGuard(
                new LukeAuthProperties(), cors("http://localhost:*"), new MockEnvironment()));
    }

    @Test
    void prodProfileWithLenientFlagsFailsFast() {
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> new AuthHardeningGuard(new LukeAuthProperties(), cors("http://localhost:*"), prod()));
        assertTrue(ex.getMessage().contains("strict-validation"));
        assertTrue(ex.getMessage().contains("require-stable-key"));
        assertTrue(ex.getMessage().contains("client-id"));
        assertTrue(ex.getMessage().contains("api-key"));
        assertTrue(ex.getMessage().contains("allowed-origins"));
    }

    @Test
    void requireHardenedFlagAloneFailsFastWhenLenient() {
        LukeAuthProperties p = new LukeAuthProperties();
        p.setRequireHardened(true);
        assertThrows(IllegalStateException.class,
                () -> new AuthHardeningGuard(p, cors("https://app.lukeflow.com"), new MockEnvironment()));
    }

    @Test
    void fullyConfiguredProdBoots() {
        assertDoesNotThrow(() -> new AuthHardeningGuard(
                hardenedProps(), cors("https://app.lukeflow.com"), prod()));
    }

    @Test
    void prodRejectsLocalhostCors() {
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> new AuthHardeningGuard(hardenedProps(),
                        cors("https://app.lukeflow.com,http://localhost:5173"), prod()));
        assertTrue(ex.getMessage().contains("allowed-origins"));
    }

    @Test
    void prodRejectsWildcardCors() {
        assertThrows(IllegalStateException.class,
                () -> new AuthHardeningGuard(hardenedProps(), cors("*"), prod()));
        assertThrows(IllegalStateException.class,
                () -> new AuthHardeningGuard(hardenedProps(), cors("https://*"), prod()));
    }

    /** strict-validation on but issuer/audience unset fails EVERY token closed at runtime. */
    @Test
    void prodRejectsStrictValidationWithoutIssuerOrAudience() {
        LukeAuthProperties p = hardenedProps();
        p.getWorkos().setIssuer("");
        p.getWorkos().setAudience("");
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> new AuthHardeningGuard(p, cors("https://app.lukeflow.com"), prod()));
        assertTrue(ex.getMessage().contains("issuer"));
        assertTrue(ex.getMessage().contains("audience"));
    }

    @Test
    void prodRejectsDevMode() {
        LukeAuthProperties p = hardenedProps();
        p.setDevMode(true);
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> new AuthHardeningGuard(p, cors("https://app.lukeflow.com"), prod()));
        assertTrue(ex.getMessage().contains("dev-mode"));
    }

    @Test
    void wildcardDetectionDoesNotFlagLegitimateSubdomainPattern() {
        // "https://*.lukeflow.com" is a normal Spring origin PATTERN, not an open wildcard —
        // it must stay allowed in prod or every tenant subdomain deploy breaks.
        assertDoesNotThrow(() -> new AuthHardeningGuard(
                hardenedProps(), cors("https://*.lukeflow.com"), prod()));
    }
}
