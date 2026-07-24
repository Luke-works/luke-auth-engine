package com.luke.auth.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.luke.auth.config.WorkosTokenVerifier;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * #29 — proves the central SecurityFilterChain enforces authenticated-by-default with a
 * canonicalization-aware public allowlist, WITHOUT needing a live WorkOS: the WorkOS verifier
 * is mocked so a "valid" token exercises the real filter → context → controller path.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SecurityEnforcementTest {

    @Autowired
    private TestRestTemplate rest;

    @MockitoBean
    private WorkosTokenVerifier verifier; // the ONLY thing standing in for live WorkOS

    private int status(String path) {
        return rest.getForEntity(path, String.class).getStatusCode().value();
    }

    private int statusWithToken(String path, String token) {
        HttpHeaders h = new HttpHeaders();
        h.setBearerAuth(token);
        ResponseEntity<String> r = rest.exchange(path, HttpMethod.GET, new HttpEntity<>(h), String.class);
        return r.getStatusCode().value();
    }

    @Test
    void protectedPathWithoutTokenIs401() {
        assertEquals(401, status("/api/me/permissions"));
    }

    @Test
    void validTokenIsAuthenticatedAndReachesTheProxy() {
        Jwt jwt = Jwt.withTokenValue("tok").header("alg", "RS256").subject("user_abc")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(300)).build();
        when(verifier.verify(eq("tok"))).thenReturn(jwt);

        // Authenticated → NOT 401. (The engine isn't up in-test, so it surfaces as a 5xx — the
        // point is the chain let it through instead of rejecting it.)
        assertNotEquals(401, statusWithToken("/api/me/permissions", "tok"));
    }

    @Test
    void publicSurfaceIsReachableWithoutToken() {
        assertNotEquals(401, status("/api/public/embed/xyz"));
    }

    @Test
    void encodedTraversalCannotMasqueradeAsPublic() {
        // /api/public/%2e%2e/me canonicalizes to a traversal → NOT on the public allowlist →
        // authentication required → 401 without a token. The defining test for the shared
        // canonicalization (a raw startsWith matcher would have let this through as public).
        assertEquals(401, status("/api/public/%2e%2e/me/permissions"));
    }

    @Test
    void publicControlPlaneGetsAreNotGated() {
        // Unambiguous public GETs return their real 2xx through the chain (no auth needed).
        // The POST-only endpoints (/service/token, /webhooks/workos) are covered by the
        // matcher unit test — a GET to them falls through to the proxy, so status is ambiguous.
        assertEquals(200, status("/.well-known/jwks.json"));
        assertEquals(200, status("/actuator/health/liveness"));
    }
}
