package com.luke.auth.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

/**
 * #29 — the central SecurityFilterChain must apply consistent security response headers
 * on every response, and must NOT set X-Frame-Options (the public embed page has to stay
 * iframable; its per-tenant frame-ancestors CSP is the clickjacking control).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SecurityHeadersTest {

    @Autowired
    private TestRestTemplate rest;

    @Test
    void securityHeadersArePresentOnEveryResponse() {
        HttpHeaders h = rest.getForEntity("/actuator/health/liveness", String.class).getHeaders();
        assertEquals("nosniff", h.getFirst("X-Content-Type-Options"));
        assertEquals("no-referrer", h.getFirst("Referrer-Policy"));
    }

    @Test
    void frameOptionsIsNotSetSoTheEmbedPageStaysFrameable() {
        ResponseEntity<String> r = rest.getForEntity("/actuator/health/liveness", String.class);
        assertNull(r.getHeaders().getFirst("X-Frame-Options"),
                "X-Frame-Options must be absent — a blanket DENY would break the public embed page");
    }
}
