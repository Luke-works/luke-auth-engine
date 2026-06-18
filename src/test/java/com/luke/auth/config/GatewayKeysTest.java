package com.luke.auth.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * #27: signing-key hardening. require-stable-key fails fast on a missing key;
 * a configured previous-public-key is published in the JWKS for rotation overlap.
 */
class GatewayKeysTest {

    private GatewayKeys configured(String privPem, String prevPubPem, boolean requireStable) {
        GatewayKeys k = new GatewayKeys();
        ReflectionTestUtils.setField(k, "privateKeyPem", privPem);
        ReflectionTestUtils.setField(k, "previousPublicKeyPem", prevPubPem);
        ReflectionTestUtils.setField(k, "requireStableKey", requireStable);
        ReflectionTestUtils.setField(k, "issuer", "luke-auth-engine");
        ReflectionTestUtils.setField(k, "audience", "luke-core-engine");
        ReflectionTestUtils.setField(k, "ttlSeconds", 60L);
        ReflectionTestUtils.invokeMethod(k, "init");
        return k;
    }

    @SuppressWarnings("unchecked")
    private int jwksSize(GatewayKeys k) {
        return ((List<Object>) k.publicJwkSetJson().get("keys")).size();
    }

    @Test
    void requireStableKeyWithoutPemFailsFast() {
        assertThrows(IllegalStateException.class, () -> configured("", "", true));
    }

    @Test
    void ephemeralPublishesSingleKey() {
        assertEquals(1, jwksSize(configured("", "", false)));
    }

    @Test
    void previousPublicKeyIsPublishedForRotationOverlap() throws Exception {
        assertEquals(2, jwksSize(configured("", publicPem(), false)));
    }

    private static String publicPem() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        return "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getEncoder().encodeToString(kp.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----";
    }
}
