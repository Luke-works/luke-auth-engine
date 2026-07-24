package com.luke.auth.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;

/**
 * #59 — the OpenAPI document is served (unauthenticated, on the allowlist) and covers the
 * gateway's real surface.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OpenApiDocsTest {

    @Autowired
    private TestRestTemplate rest;

    @Test
    void openApiSpecIsServedAndDescribesTheSurface() {
        ResponseEntity<String> r = rest.getForEntity("/v3/api-docs", String.class);
        assertEquals(200, r.getStatusCode().value(), "spec is on the public allowlist");
        String spec = r.getBody() == null ? "" : r.getBody();
        assertTrue(spec.contains("\"openapi\""), "is an OpenAPI document");
        assertTrue(spec.contains("luke-auth-engine"), "carries our document metadata");
        // Real endpoints are present.
        for (String path : new String[] {"/auth/login", "/auth/register", "/session", "/service/token"}) {
            assertTrue(spec.contains(path), "spec should document " + path);
        }
    }
}
