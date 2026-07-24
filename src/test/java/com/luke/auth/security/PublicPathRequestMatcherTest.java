package com.luke.auth.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * #29 — the allowlist that decides what the central chain leaves unauthenticated. The
 * defining case is the encoded traversal: it must NOT be treated as public.
 */
class PublicPathRequestMatcherTest {

    private final PublicPathRequestMatcher matcher = new PublicPathRequestMatcher();

    private HttpServletRequest req(String method, String uri) {
        HttpServletRequest r = Mockito.mock(HttpServletRequest.class);
        Mockito.when(r.getMethod()).thenReturn(method);
        Mockito.when(r.getRequestURI()).thenReturn(uri);
        return r;
    }

    @Test
    void publicSurfacesAreAllowlisted() {
        for (String uri : new String[] {
                "/.well-known/jwks.json",
                "/auth/login", "/auth/register", "/auth/social", "/auth/callback",
                "/auth/refresh", "/auth/logout",
                "/service/token", "/service/keys/1ec1c26b/revoke",
                "/webhooks/workos", "/dev/token",
                "/actuator/health/liveness", "/actuator/health/readiness", "/actuator/info",
                "/api/public/embed/xyz", "/embed/tok123", "/embed-assets/app.js",
        }) {
            assertTrue(matcher.matches(req("GET", uri)), uri + " should be public");
        }
    }

    @Test
    void protectedSurfacesAreNotAllowlisted() {
        for (String uri : new String[] {
                "/api/me/permissions", "/session", "/auth/password", "/auth/account",
                "/auth/org/invitations", "/api/documents/x/content", "/api/email-assets/x",
        }) {
            assertFalse(matcher.matches(req("GET", uri)), uri + " must require auth");
        }
    }

    @Test
    void encodedTraversalIsNotPublic() {
        // The whole point: a raw startsWith("/api/public/") would pass this — the canonicalizer
        // decodes %2e%2e → ".." and refuses it, so it is NOT public.
        assertFalse(matcher.matches(req("GET", "/api/public/%2e%2e/me/permissions")));
        assertFalse(matcher.matches(req("GET", "/api/public/../me/permissions")));
    }

    @Test
    void corsPreflightIsAlwaysAllowed() {
        // Preflight carries no credentials; it must never be gated (it reaches the CorsFilter).
        assertTrue(matcher.matches(req("OPTIONS", "/api/me/permissions")));
    }

    /**
     * Adversarial: anything that isn't unambiguously on the public surface must FAIL CLOSED
     * (treated as protected → require auth). These are the bypasses a matcher must not fall for.
     */
    @Test
    void bypassAttemptsFailClosed() {
        String[] attempts = {
                "/api/PUBLIC/x",              // case variation — startsWith is case-sensitive
                "/api/Public/x",
                "/api/publicx/y",            // prefix without the boundary slash
                "/api/public",               // the bare segment, no trailing resource
                "/api/mypublic/x",           // 'public' not at the start of the segment path
                "/api/public%2f%2e%2e%2fme", // encoded slash + encoded traversal
                "/api/me;/../public/x",      // matrix param + traversal
                "/api/public/../../me",      // double traversal
                "/embedx/tok",               // near-miss on /embed/
                "/api/internal/secrets",     // a genuinely protected internal path
        };
        for (String uri : attempts) {
            assertFalse(matcher.matches(req("GET", uri)), uri + " MUST fail closed (require auth)");
        }
    }
}
