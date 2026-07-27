package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
 * When GATEWAY_VOUCH_SECRET is configured, the gateway stamps X-Gateway-Auth = the secret on every
 * forward (proof-of-origin so core can lock its public surface to gateway-only), and a client-forged
 * value is replaced with the real one — never trusted through. Uses a JDK HttpServer as the stub
 * "core-engine" and dev-mode (X-Dev-User) for auth so no WorkOS is needed.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"luke.auth.dev-mode=true", "GATEWAY_VOUCH_SECRET=vouch-s3cret"})
@ActiveProfiles("dev")
class ProxyGatewayVouchTest {

    private static final AtomicReference<Headers> RECEIVED = new AtomicReference<>();
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
    void stampsTheConfiguredVouchAndReplacesAClientForgedOne() {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        h.set("X-Dev-User", "dev-user-1");
        h.set("X-Gateway-Auth", "forged"); // a client tries to present the proof-of-origin itself

        ResponseEntity<String> r = rest.postForEntity("/api/echo", new HttpEntity<>("{}", h), String.class);

        assertEquals(200, r.getStatusCode().value());
        // Upstream (core) receives the gateway's configured secret, NOT the client's forgery.
        assertEquals("vouch-s3cret", RECEIVED.get().getFirst("X-Gateway-Auth"));
    }

    private static HttpServer startUpstream() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/api/echo", ex -> {
                try (InputStream in = ex.getRequestBody()) {
                    in.readAllBytes();
                }
                RECEIVED.set(ex.getRequestHeaders());
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
