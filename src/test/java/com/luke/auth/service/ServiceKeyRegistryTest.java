package com.luke.auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** #39: service keys may be hashed at rest, carry expiry + scope, and self-revoke. */
class ServiceKeyRegistryTest {

    private static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void resolvesLegacyPlaintextKey() {
        ServiceKeyRegistry r = new ServiceKeyRegistry("s3cret=svc:order-bot");
        ServiceKeyRegistry.Resolved hit = r.resolve("s3cret");
        assertNotNull(hit);
        assertEquals("svc:order-bot", hit.userId());
        assertNull(r.resolve("wrong"));
    }

    @Test
    void resolvesHashedKeyButNotItsHashString() {
        String raw = "real-secret-value";
        ServiceKeyRegistry r = new ServiceKeyRegistry(sha256(raw) + "=svc:billing;scope=emails");
        ServiceKeyRegistry.Resolved hit = r.resolve(raw); // present the RAW key
        assertNotNull(hit);
        assertEquals("svc:billing", hit.userId());
        assertEquals("emails", hit.scope());
        // keyId is the hash prefix (non-secret), never the raw key.
        assertEquals(sha256(raw).substring(0, 8), hit.keyId());
        // Presenting the hash string itself must NOT authenticate.
        assertNull(r.resolve(sha256(raw)));
    }

    @Test
    void expiredKeyIsRejected() {
        ServiceKeyRegistry r = new ServiceKeyRegistry("s3cret=svc:bot;exp=1000000000"); // 2001
        assertNull(r.resolve("s3cret"), "a key past its exp must self-revoke without redeploy");
    }

    @Test
    void unexpiredKeyWithFutureExpiryResolves() {
        ServiceKeyRegistry r = new ServiceKeyRegistry("s3cret=svc:bot;exp=4102444800"); // 2100
        assertNotNull(r.resolve("s3cret"));
    }

    @Test
    void blankAndUnknownReturnNull() {
        ServiceKeyRegistry r = new ServiceKeyRegistry("s3cret=svc:bot");
        assertNull(r.resolve(null));
        assertNull(r.resolve(""));
        assertNull(r.resolve("nope"));
    }
}
