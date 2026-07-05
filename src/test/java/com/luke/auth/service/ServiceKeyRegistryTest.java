package com.luke.auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** #39: service keys may be hashed at rest, carry expiry + scope, self-revoke, revoke live, and meter usage. */
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

    @Test
    void revokedKeyIsRejectedLiveWithoutRestart() {
        ServiceKeyRegistry r = new ServiceKeyRegistry("s3cret=svc:bot");
        ServiceKeyRegistry.Resolved hit = r.resolve("s3cret");
        assertNotNull(hit, "key resolves before revocation");
        String keyId = hit.keyId();

        boolean known = r.revoke(keyId); // same live instance, no reconstruction/redeploy
        assertTrue(known, "revoking a configured keyId reports known=true");
        assertTrue(r.isRevoked(keyId));
        assertNull(r.resolve("s3cret"), "a revoked keyId is rejected on the very next resolve");

        assertTrue(r.unrevoke(keyId));
        assertFalse(r.isRevoked(keyId));
        assertNotNull(r.resolve("s3cret"), "un-revoke restores the key live");
    }

    @Test
    void revokingUnknownKeyIdIsHarmlessAndReportsNotKnown() {
        ServiceKeyRegistry r = new ServiceKeyRegistry("s3cret=svc:bot");
        assertFalse(r.revoke("deadbeef"), "unknown keyId reports known=false");
        assertTrue(r.isRevoked("deadbeef"), "but is still added to the revocation set");
        assertNotNull(r.resolve("s3cret"), "revoking an unrelated id doesn't affect other keys");
    }

    @Test
    void lastUsedAndIssuanceCountUpdateOnSuccessfulResolve() {
        ServiceKeyRegistry r = new ServiceKeyRegistry("s3cret=svc:bot");
        String keyId = r.resolve("s3cret").keyId();

        ServiceKeyRegistry.Usage u1 = r.usage(keyId);
        assertEquals(1, u1.issuanceCount(), "one successful resolve ⇒ count 1");
        assertTrue(u1.lastUsedEpochSec() > 0, "last-used timestamp is set");

        r.resolve("s3cret");
        r.resolve("s3cret");
        assertEquals(3, r.usage(keyId).issuanceCount(), "counter is monotonic across resolves");

        // A failed resolve must NOT meter anything.
        r.resolve("wrong-key");
        assertEquals(3, r.usage(keyId).issuanceCount(), "failed attempts don't increment issuance");
    }

    @Test
    void usageForNeverUsedKeyIsZero() {
        ServiceKeyRegistry r = new ServiceKeyRegistry("s3cret=svc:bot");
        ServiceKeyRegistry.Usage u = r.usage("nope");
        assertEquals(0, u.issuanceCount());
        assertEquals(0, u.lastUsedEpochSec());
    }

    @Test
    void secretSourceIsPluggable() {
        // A secret-manager-backed source would supply the same raw material.
        ServiceKeyRegistry.SecretSource fromStore = () -> "s3cret=svc:bot;scope=forms";
        ServiceKeyRegistry r = new ServiceKeyRegistry(fromStore);
        ServiceKeyRegistry.Resolved hit = r.resolve("s3cret");
        assertNotNull(hit);
        assertEquals("svc:bot", hit.userId());
        assertEquals("forms", hit.scope());
    }
}
