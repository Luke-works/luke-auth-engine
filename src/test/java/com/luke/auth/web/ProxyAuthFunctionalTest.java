package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

/**
 * Functional test of the gateway proxy (real HTTP; no DB). Proves a protected path
 * requires a token, a public path is forwarded WITHOUT auth, and CORS preflight is
 * let through. (The traversal-rejection logic is unit-tested in
 * {@link EngineProxyControllerPathTest}.)
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ProxyAuthFunctionalTest {

    @Autowired
    private TestRestTemplate rest;

    @Test
    void protectedPath_withoutToken_isUnauthorized() {
        assertEquals(401, rest.getForEntity("/api/me/permissions", String.class)
                .getStatusCode().value());
    }

    @Test
    void documentsPath_withoutToken_isUnauthorized() {
        // /api/documents/** is the byte tier (luke-file-proxy) but is NOT public — it must still pass
        // the auth gate so the gateway can inject the vouched X-User-Id. No token → 401.
        assertEquals(401, rest.getForEntity("/api/documents/some-id/content", String.class)
                .getStatusCode().value());
    }

    @Test
    void corsPreflight_isAllowed() {
        ResponseEntity<String> r = rest.exchange(
                "/api/me/permissions", HttpMethod.OPTIONS, HttpEntity.EMPTY, String.class);
        assertEquals(200, r.getStatusCode().value());
    }

    @Test
    void publicPath_isForwardedNotBlocked() {
        // A /api/public/** path is treated as public, so it is NOT rejected with 401.
        // (The downstream engine isn't running in the test, so it surfaces as a 5xx —
        // which proves the gateway tried to forward it unauthenticated rather than
        // blocking it at the auth gate.)
        ResponseEntity<String> r = rest.getForEntity("/api/public/embed/some-token", String.class);
        assertNotEquals(401, r.getStatusCode().value());
    }
}
