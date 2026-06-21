package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/**
 * #21: the proxy caps request body size and rejects oversized uploads with 413, instead
 * of buffering unbounded bytes into heap. Max is set tiny here so a normal body trips it.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "luke.auth.proxy.max-request-bytes=10")
class EngineProxyBodyLimitTest {

    @Autowired
    private TestRestTemplate rest;

    private HttpEntity<String> json(String body) {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        return new HttpEntity<>(body, h);
    }

    @Test
    void oversizedRequestRejectedWith413() {
        // 100-byte body > 10-byte limit → rejected before any upstream call. Public path so
        // the size guard (not auth) is what stops it.
        ResponseEntity<String> r = rest.postForEntity(
                "/api/public/embed/x", json("x".repeat(100)), String.class);
        assertEquals(413, r.getStatusCode().value());
    }

    @Test
    void withinLimitRequestIsNotSizeRejected() {
        // A 1-byte body is under the limit, so it is forwarded (the engine isn't up in the
        // test, so it surfaces as a 5xx — the point is it is NOT a 413).
        ResponseEntity<String> r = rest.postForEntity(
                "/api/public/embed/x", json("x"), String.class);
        assertNotEquals(413, r.getStatusCode().value());
    }
}
