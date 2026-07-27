package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * #57 — proves an authenticated request BODY streams through the proxy to the upstream verbatim
 * (the proxy disables multipart parsing precisely so it can forward the raw stream). Uses a JDK
 * HttpServer as the stub "core-engine" and dev-mode (X-Dev-User) for auth so no WorkOS is needed.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "luke.auth.dev-mode=true")
@ActiveProfiles("dev") // DevModeGuard requires the dev profile when dev-mode is on
class ProxyBodyForwardingTest {

    private static final AtomicReference<String> RECEIVED_BODY = new AtomicReference<>();
    private static final AtomicReference<String> RECEIVED_ACTAS = new AtomicReference<>();
    private static final AtomicReference<Headers> RECEIVED_HEADERS = new AtomicReference<>();
    private static final HttpServer UPSTREAM = startUpstream();

    @Autowired
    private TestRestTemplate rest;

    @DynamicPropertySource
    static void coreUrl(DynamicPropertyRegistry r) {
        r.add("luke.auth.core-engine.base-url", () -> "http://localhost:" + UPSTREAM.getAddress().getPort());
    }

    @AfterAll
    static void stop() {
        UPSTREAM.stop(0);
    }

    @Test
    void authenticatedBodyStreamsThroughToUpstreamVerbatim() {
        String payload = "{\"stream\":\"" + "x".repeat(5000) + "\"}"; // > default buffer, exercises streaming
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        h.set("X-Dev-User", "dev-user-1"); // dev-mode stand-in for a verified WorkOS user

        ResponseEntity<String> r = rest.postForEntity("/api/echo", new HttpEntity<>(payload, h), String.class);

        assertEquals(200, r.getStatusCode().value(), "proxy forwarded and returned the upstream 200");
        assertEquals(payload, RECEIVED_BODY.get(), "upstream received the body byte-for-byte");
        // And the gateway vouched for the user with a minted act-as token (never the raw dev header).
        assertTrue(RECEIVED_ACTAS.get() != null && RECEIVED_ACTAS.get().startsWith("Bearer "),
                "upstream received a minted act-as Bearer token");
    }

    @Test
    void stripsSpoofedIdentityHeadersAndDoesNotRelayInfraHeaders() {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        h.set("X-Dev-User", "dev-user-1");
        // A malicious client tries to inject identity/trust headers to impersonate a user/service.
        h.set("X-User-Id", "victim");
        h.set("X-Internal-Key", "guessed-secret");
        h.set("X-Gateway-Auth", "guessed-vouch");
        h.set("X-Correlation-Id", "trace-xyz");

        ResponseEntity<String> r = rest.postForEntity("/api/echo", new HttpEntity<>("{}", h), String.class);

        assertEquals(200, r.getStatusCode().value());
        // The gateway is the SOLE identity asserter — spoofed identity/trust headers never reach upstream.
        assertNull(RECEIVED_HEADERS.get().getFirst("X-User-Id"), "spoofed X-User-Id must be stripped");
        assertNull(RECEIVED_HEADERS.get().getFirst("X-Internal-Key"), "spoofed X-Internal-Key must be stripped");
        // A forged gateway-vouch is stripped (and not re-stamped here, since no secret is configured).
        assertNull(RECEIVED_HEADERS.get().getFirst("X-Gateway-Auth"), "spoofed X-Gateway-Auth must be stripped");
        // The correlation id IS forwarded so one trace spans the gateway → engine hop.
        assertEquals("trace-xyz", RECEIVED_HEADERS.get().getFirst("X-Correlation-Id"));
        // Upstream infra headers must not be relayed back to the browser.
        assertFalse(r.getHeaders().containsKey("cf-ray"), "cf-ray must not be relayed");
        assertFalse(r.getHeaders().containsKey("Set-Cookie"), "Set-Cookie must not be relayed");
    }

    @Test
    void stampsGatewayVouchedClientIpAndStripsAForgedOne() {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        h.set("X-Dev-User", "dev-user-1");
        // A client tries to forge the vouched-IP header AND spoof a left-most X-Forwarded-For hop.
        h.set("X-Real-Client-IP", "6.6.6.6");            // forgery — must be stripped, never forwarded
        h.set("X-Forwarded-For", "1.2.3.4, 10.0.0.1");   // the gateway resolves the real client from this

        ResponseEntity<String> r = rest.postForEntity("/api/echo", new HttpEntity<>("{}", h), String.class);

        assertEquals(200, r.getStatusCode().value());
        String vouched = RECEIVED_HEADERS.get().getFirst("X-Real-Client-IP");
        // The gateway is the SOLE asserter of the client IP: it re-stamps X-Real-Client-IP from the real
        // request, so core's public limiters get a gateway-vouched value and never the client's forgery.
        assertNotNull(vouched, "gateway must stamp a vouched X-Real-Client-IP for core's public limiters");
        assertNotEquals("6.6.6.6", vouched, "the client-forged X-Real-Client-IP must be stripped, not forwarded");
    }

    private static HttpServer startUpstream() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/api/echo", ex -> {
                try (InputStream in = ex.getRequestBody()) {
                    RECEIVED_BODY.set(new String(in.readAllBytes(), StandardCharsets.UTF_8));
                }
                RECEIVED_ACTAS.set(ex.getRequestHeaders().getFirst("Authorization"));
                RECEIVED_HEADERS.set(ex.getRequestHeaders());
                // Infra headers a real engine's edge (Render/Cloudflare) would add — the proxy must
                // NOT relay these back to the browser (they collide with the gateway's own edge → 502).
                ex.getResponseHeaders().add("cf-ray", "abc123");
                ex.getResponseHeaders().add("Set-Cookie", "sneaky=1");
                byte[] ok = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(200, ok.length);
                ex.getResponseBody().write(ok);
                ex.close();
            });
            server.start();
            return server;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
