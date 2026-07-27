package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * D1 — when the upstream engine keeps returning 5xx, the proxy's circuit breaker OPENS and subsequent
 * calls fail fast with 503 + Retry-After WITHOUT hitting the upstream, instead of piling every caller up
 * behind the full timeout. Threshold is lowered to 2 for a fast test. Uses a JDK HttpServer stub "core"
 * that always 500s, and dev-mode auth (X-Dev-User) so no WorkOS is needed.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"luke.auth.dev-mode=true",
                "luke.auth.proxy.circuit-breaker.failure-threshold=2",
                "luke.auth.proxy.circuit-breaker.open-seconds=30"})
@ActiveProfiles("dev")
class ProxyCircuitBreakerTest {

    private static final AtomicInteger HITS = new AtomicInteger();
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
    void opensAfterRepeatedUpstream5xxThenFailsFast() {
        HttpHeaders h = new HttpHeaders();
        h.set("X-Dev-User", "dev-user-1");
        HttpEntity<Void> req = new HttpEntity<>(h);

        // The first two calls reach the failing upstream and relay its 500.
        for (int i = 0; i < 2; i++) {
            ResponseEntity<String> r = rest.exchange("/api/echo", HttpMethod.GET, req, String.class);
            assertEquals(500, r.getStatusCode().value(), "upstream 5xx relayed while circuit closed");
        }
        assertEquals(2, HITS.get());

        // Circuit is now OPEN: the next call fails fast with 503 + Retry-After and never touches upstream.
        ResponseEntity<String> r = rest.exchange("/api/echo", HttpMethod.GET, req, String.class);
        assertEquals(503, r.getStatusCode().value(), "circuit open → fast 503");
        assertEquals(2, HITS.get(), "upstream must NOT be hit while the circuit is open");
        assertTrue(r.getHeaders().containsKey(HttpHeaders.RETRY_AFTER), "503 carries a Retry-After");
    }

    private static HttpServer startUpstream() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/api/echo", ex -> {
                HITS.incrementAndGet();
                try (InputStream in = ex.getRequestBody()) {
                    in.readAllBytes();
                }
                byte[] body = "{\"error\":\"boom\"}".getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(500, body.length);
                ex.getResponseBody().write(body);
                ex.close();
            });
            server.start();
            return server;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
