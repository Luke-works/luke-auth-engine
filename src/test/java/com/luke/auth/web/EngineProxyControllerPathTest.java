package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Guards the proxy path-canonicalization fix (GHSA-hm7m): traversal is rejected so
 * a request can't masquerade as public ({@code /api/public/...}) while resolving to
 * a protected endpoint downstream.
 */
class EngineProxyControllerPathTest {

    @Test
    void plainPath_isCanonical() {
        assertEquals("/api/public/render/abc",
                EngineProxyController.canonicalPath("/api/public/render/abc"));
    }

    @Test
    void collapsesEmptyAndDotSegments() {
        assertEquals("/api/public/render", EngineProxyController.canonicalPath("/api/public/./render/"));
        assertEquals("/api/public/render", EngineProxyController.canonicalPath("/api//public/render"));
    }

    @Test
    void plainTraversal_isRejected() {
        assertNull(EngineProxyController.canonicalPath("/api/public/../me/permissions"));
    }

    @Test
    void encodedTraversal_isRejected() {
        assertNull(EngineProxyController.canonicalPath("/api/public/%2e%2e/me/permissions"));
    }

    @Test
    void genuinePublicPath_staysPublic() {
        String canonical = EngineProxyController.canonicalPath("/api/public/embed/xyz");
        assertTrue(canonical.startsWith("/api/public/"));
    }

    @Test
    void nullOrMalformed_isRejected() {
        assertNull(EngineProxyController.canonicalPath(null));
    }
}
