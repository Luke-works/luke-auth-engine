package com.luke.auth.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * #33: issuer/audience enforcement. Strict mode fails CLOSED (no decoder built →
 * every token rejected) when issuer or audience is unset; lenient mode still
 * builds an expiry-checking decoder. NimbusJwtDecoder fetches JWKS lazily, so
 * init() builds a decoder without any network call.
 */
class WorkosTokenVerifierTest {

    /** Build a verifier and run @PostConstruct init() with the given config. */
    private Object decoderOf(boolean strict, String issuer, String audience, String clientId) {
        WorkosTokenVerifier v = new WorkosTokenVerifier();
        ReflectionTestUtils.setField(v, "apiBaseUrl", "https://api.workos.com");
        ReflectionTestUtils.setField(v, "clientId", clientId);
        ReflectionTestUtils.setField(v, "jwksUrl", "");
        ReflectionTestUtils.setField(v, "issuer", issuer);
        ReflectionTestUtils.setField(v, "audience", audience);
        ReflectionTestUtils.setField(v, "strictValidation", strict);
        ReflectionTestUtils.invokeMethod(v, "init");
        return ReflectionTestUtils.getField(v, "decoder");
    }

    @Test
    void strictWithoutIssuerFailsClosed() {
        assertNull(decoderOf(true, "", "aud", "client_123"));
    }

    @Test
    void strictWithoutAudienceFailsClosed() {
        assertNull(decoderOf(true, "https://issuer", "", "client_123"));
    }

    @Test
    void strictFullyConfiguredBuildsDecoder() {
        assertNotNull(decoderOf(true, "https://issuer", "aud", "client_123"));
    }

    @Test
    void lenientStillBuildsDecoderWithoutIssuer() {
        assertNotNull(decoderOf(false, "", "", "client_123"));
    }

    @Test
    void audienceAllowedAcceptsMatchAndRejectsMismatch() {
        assertTrue(WorkosTokenVerifier.audienceAllowed(List.of("a", "b"), "b"));
        assertFalse(WorkosTokenVerifier.audienceAllowed(List.of("a"), "b"));
        assertFalse(WorkosTokenVerifier.audienceAllowed(null, "b"));
        assertTrue(WorkosTokenVerifier.audienceAllowed(null, "")); // no audience required
    }
}
