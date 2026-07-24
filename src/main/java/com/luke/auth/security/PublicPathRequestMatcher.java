package com.luke.auth.security;

import com.luke.auth.web.RequestPaths;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Set;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * The gateway's unauthenticated allowlist for the central {@code SecurityFilterChain} (#29).
 *
 * <p>Crucially, the proxy surfaces ({@code /api/public/**}, {@code /embed/**},
 * {@code /embed-assets/**}) are matched on the <b>canonicalized</b> path via
 * {@link RequestPaths#isPublicProxyPath} — NOT a raw {@code startsWith} — so
 * {@code /api/public/%2e%2e/me} can't masquerade as public (the path-traversal defense). The
 * remaining entries are fixed control-plane paths that authenticate by other means: the WorkOS
 * login flows (no token yet), the service-key endpoints ({@code X-Service-Key}), the signature-
 * verified webhook, JWKS, and the health/probe endpoints.
 */
public class PublicPathRequestMatcher implements RequestMatcher {

    /** Exact, fixed public paths (non-proxy). */
    private static final Set<String> EXACT = Set.of(
            "/.well-known/jwks.json",
            "/auth/login", "/auth/register", "/auth/social", "/auth/callback",
            "/auth/refresh", "/auth/logout",
            "/service/token",
            "/webhooks/workos",
            // Dev-only backdoor (mints an act-as token unauthenticated). The bean only exists
            // under the 'dev' profile and DevModeGuard blocks dev-mode elsewhere, so allowlisting
            // it never opens anything in prod — but without it, local /dev/token would 401.
            "/dev/token");

    /** Fixed public prefixes (non-proxy). */
    private static final Set<String> PREFIXES = Set.of(
            "/service/keys/",   // operator key revoke/unrevoke (X-Operator-Token at the controller)
            "/actuator/");      // health/info + liveness/readiness probes

    @Override
    public boolean matches(HttpServletRequest request) {
        // CORS preflight carries no credentials and is handled by the CorsFilter — never gate it.
        if (HttpMethod.OPTIONS.matches(request.getMethod())) {
            return true;
        }
        String uri = request.getRequestURI();
        if (uri == null) {
            return false;
        }
        if (EXACT.contains(uri)) {
            return true;
        }
        for (String prefix : PREFIXES) {
            if (uri.startsWith(prefix)) {
                return true;
            }
        }
        // The proxy public surface — matched on the CANONICAL path (traversal-safe).
        return RequestPaths.isPublicProxyPath(uri);
    }
}
