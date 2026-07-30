package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertNotNull;

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
    void publicDocumentsPath_isForwardedNotBlocked() {
        // /api/public/documents/** is the token-authorized embed upload surface — public (no WorkOS
        // token), so it must NOT be rejected with 401 (it forwards; the embed token is the auth).
        assertNotEquals(401, rest.getForEntity("/api/public/documents?token=x&processRef=y", String.class)
                .getStatusCode().value());
    }

    @Test
    void corsPreflight_isAllowed() {
        ResponseEntity<String> r = rest.exchange(
                "/api/me/permissions", HttpMethod.OPTIONS, HttpEntity.EMPTY, String.class);
        assertEquals(200, r.getStatusCode().value());
    }

    @Test
    void corsPreflight_forAMutation_carriesTheAllowHeaders() {
        // A real preflight: Origin + Access-Control-Request-Method (what a browser sends before a
        // PATCH). Must come back with Allow-Origin/Allow-Methods or the browser blocks the PATCH.
        HttpHeaders h = new HttpHeaders();
        h.set(HttpHeaders.ORIGIN, "http://localhost:5173");
        h.set(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "PATCH");
        h.set(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "authorization,content-type,x-tenant-id");
        ResponseEntity<String> r = rest.exchange(
                "/api/form-definitions/abc", HttpMethod.OPTIONS, new HttpEntity<>(h), String.class);
        assertEquals("http://localhost:5173",
                r.getHeaders().getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN),
                "preflight must be answered with the caller's origin");
        assertNotNull(r.getHeaders().getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS));
        // Explicitly ordering the filter must not ALSO leave it auto-registered: a duplicated
        // Allow-Origin header is itself a CORS failure in the browser.
        assertEquals(1, r.getHeaders().get(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN).size(),
                "exactly one Allow-Origin header — the filter must be registered once");
    }

    @Test
    void unauthorized_stillCarriesCorsHeaders() {
        // An expired/invalid access token gets a 401 — the UI's refresh-on-401 retry depends on
        // READING that 401. Without CORS headers the browser blocks the response entirely, the
        // fetch rejects as a network/CORS error, and the retry never runs.
        HttpHeaders h = new HttpHeaders();
        h.set(HttpHeaders.ORIGIN, "http://localhost:5173");
        h.setBearerAuth("expired.jwt.value");
        ResponseEntity<String> r = rest.exchange(
                "/api/form-definitions", HttpMethod.GET, new HttpEntity<>(h), String.class);
        assertEquals(401, r.getStatusCode().value());
        assertEquals("http://localhost:5173",
                r.getHeaders().getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN),
                "a 401 must still be CORS-readable by the browser");
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
