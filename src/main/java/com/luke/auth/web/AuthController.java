package com.luke.auth.web;

import com.luke.auth.config.WorkosTokenVerifier;
import com.luke.auth.identity.IdentityResolver;
import com.luke.auth.session.PermissionsClient;
import com.luke.auth.session.SessionService;
import com.luke.auth.workos.OnboardingClient;
import com.luke.auth.workos.WorkosClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The consumer front door. luke-auth — not the browser — owns the conversation
 * with WorkOS:
 * <ul>
 *   <li>{@code POST /auth/register} — create the WorkOS identity (+ optional engine provision);</li>
 *   <li>{@code POST /auth/login} — email/password → tokens + session view;</li>
 *   <li>{@code GET  /auth/social} — redirect to WorkOS for social/SSO login;</li>
 *   <li>{@code GET  /auth/callback} — finish the social/SSO redirect;</li>
 *   <li>{@code POST /auth/refresh} — rotate the access token from the refresh cookie;</li>
 *   <li>{@code POST /auth/logout} — clear the refresh cookie (+ end the WorkOS session).</li>
 * </ul>
 *
 * <p>The short-lived <b>access token</b> is returned in the JSON body — the UI
 * holds it and sends it as a Bearer on every request, exactly as the existing
 * {@code /session} and {@code /**} proxy paths expect. The long-lived <b>refresh
 * token</b> is set as an {@code HttpOnly} cookie so JavaScript never sees it.
 * Nothing is stored server-side.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    /** Friendly provider aliases → WorkOS provider values. */
    private static final Map<String, String> PROVIDERS = Map.of(
            "google", "GoogleOAuth",
            "microsoft", "MicrosoftOAuth",
            "github", "GitHubOAuth",
            "apple", "AppleOAuth",
            "authkit", "authkit");

    private static final String REFRESH_COOKIE = "wos_refresh";

    private final WorkosClient workos;
    private final WorkosTokenVerifier verifier;
    private final IdentityResolver identityResolver;
    private final OnboardingClient onboarding;
    private final SessionService sessionService;

    private final String uiCallbackUrl;
    private final boolean cookieSecure;
    private final String cookieSameSite;

    public AuthController(WorkosClient workos,
                          WorkosTokenVerifier verifier,
                          IdentityResolver identityResolver,
                          OnboardingClient onboarding,
                          SessionService sessionService,
                          @Value("${luke.auth.workos.ui-callback-url:http://localhost:5173/sso-callback}") String uiCallbackUrl,
                          @Value("${luke.auth.workos.cookie-secure:true}") boolean cookieSecure,
                          @Value("${luke.auth.workos.cookie-same-site:Lax}") String cookieSameSite) {
        this.workos = workos;
        this.verifier = verifier;
        this.identityResolver = identityResolver;
        this.onboarding = onboarding;
        this.sessionService = sessionService;
        this.uiCallbackUrl = uiCallbackUrl;
        this.cookieSecure = cookieSecure;
        this.cookieSameSite = cookieSameSite;
    }

    public record RegisterRequest(String email, String password, String firstName, String lastName) {}
    public record LoginRequest(String email, String password) {}

    // ── Register ────────────────────────────────────────────────────────────

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
        if (isBlank(req.email()) || isBlank(req.password())) {
            return error(HttpStatus.BAD_REQUEST, "Bad Request", "email and password are required");
        }
        try {
            Map<String, Object> user = workos.createUser(
                    req.email(), req.password(), req.firstName(), req.lastName());
            String workosUserId = String.valueOf(user.get("id"));
            String engineUserId = identityResolver.toEngineUserId(workosUserId);

            // Optional: provision into core-engine now (no-op unless configured).
            try {
                onboarding.provision(engineUserId, req.firstName(), req.lastName(), req.email());
            } catch (OnboardingClient.OnboardingException e) {
                // The identity exists in WorkOS but engine provisioning failed.
                // Surface it rather than silently leaving a half-onboarded user.
                log.error("Provisioning failed after WorkOS user creation for {}", engineUserId, e);
                return error(HttpStatus.BAD_GATEWAY, "Provisioning failed", e.getMessage());
            }

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("userId", engineUserId);
            body.put("workosUserId", workosUserId);
            body.put("verifyRequired", !Boolean.TRUE.equals(user.get("email_verified")));
            return ResponseEntity.status(HttpStatus.CREATED).body(body);
        } catch (WorkosClient.WorkosException e) {
            return error(HttpStatus.valueOf(normalize(e.status())), "Registration failed", e.getMessage());
        }
    }

    // ── Login (email/password) ───────────────────────────────────────────────

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req, HttpServletRequest request,
                                   HttpServletResponse response) {
        if (isBlank(req.email()) || isBlank(req.password())) {
            return error(HttpStatus.BAD_REQUEST, "Bad Request", "email and password are required");
        }
        try {
            Map<String, Object> auth = workos.authenticateWithPassword(req.email(), req.password());
            return sessionResponse(auth, request.getHeader("X-Tenant-Id"), response);
        } catch (WorkosClient.WorkosException e) {
            // e.g. invalid credentials, or email_verification_required.
            return error(HttpStatus.valueOf(normalize(e.status())), "Login failed", e.getMessage());
        }
    }

    // ── Social / SSO (redirect out, then back to /auth/callback) ─────────────

    @GetMapping("/social")
    public ResponseEntity<?> social(@RequestParam String provider,
                                    @RequestParam(required = false) String state) {
        String workosProvider = PROVIDERS.getOrDefault(provider.toLowerCase(), provider);
        String url = workos.authorizationUrl(workosProvider, state);
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(url)).build();
    }

    @GetMapping("/callback")
    public ResponseEntity<?> callback(@RequestParam(required = false) String code,
                                      @RequestParam(required = false) String error,
                                      HttpServletResponse response) {
        if (error != null || code == null) {
            String to = uiCallbackUrl + "#error=" + (error == null ? "missing_code" : error);
            return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(to)).build();
        }
        try {
            Map<String, Object> auth = workos.authenticateWithCode(code);
            String accessToken = String.valueOf(auth.get("access_token"));
            setRefreshCookie(response, str(auth.get("refresh_token")));

            Jwt jwt = verifier.verify(accessToken);
            String sid = jwt.getClaimAsString("sid");
            // Hand the SPA its access token via the URL fragment (kept out of
            // server logs / Referer); the UI then calls /session as usual.
            String to = uiCallbackUrl + "#access_token=" + accessToken + (sid != null ? "&sid=" + sid : "");
            return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(to)).build();
        } catch (Exception e) {
            log.warn("Social callback failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(uiCallbackUrl + "#error=callback_failed")).build();
        }
    }

    // ── Refresh ──────────────────────────────────────────────────────────────

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@CookieValue(value = REFRESH_COOKIE, required = false) String refreshToken,
                                     HttpServletRequest request, HttpServletResponse response) {
        if (isBlank(refreshToken)) {
            return error(HttpStatus.UNAUTHORIZED, "Unauthorized", "Missing refresh token");
        }
        try {
            Map<String, Object> auth = workos.authenticateWithRefreshToken(refreshToken);
            return sessionResponse(auth, request.getHeader("X-Tenant-Id"), response);
        } catch (WorkosClient.WorkosException e) {
            clearRefreshCookie(response);
            return error(HttpStatus.UNAUTHORIZED, "Unauthorized", "Could not refresh session");
        }
    }

    // ── Logout ───────────────────────────────────────────────────────────────

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        clearRefreshCookie(response);
        // Best-effort: end the WorkOS session too, if the caller passed its token.
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        String logoutUrl = null;
        if (header != null && header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            try {
                Jwt jwt = verifier.verify(header.substring(7).trim());
                String sid = jwt.getClaimAsString("sid");
                if (sid != null) logoutUrl = workos.logoutUrl(sid);
            } catch (Exception ignored) {
                // already expired / invalid — cookie is cleared, nothing more to do
            }
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", true);
        if (logoutUrl != null) body.put("workosLogoutUrl", logoutUrl);
        return ResponseEntity.ok(body);
    }

    // ────────────────────────────────────────────────────────────────────────

    /**
     * Turn a WorkOS authenticate result into the UI response: verify the access
     * token, derive the engine user id, ask {@link SessionService} for the merged
     * roles/capabilities view, set the refresh cookie, and return everything.
     */
    private ResponseEntity<?> sessionResponse(Map<String, Object> auth, String tenant,
                                              HttpServletResponse response) {
        String accessToken = str(auth.get("access_token"));
        if (accessToken == null) {
            return error(HttpStatus.BAD_GATEWAY, "Bad Gateway", "WorkOS returned no access token");
        }
        setRefreshCookie(response, str(auth.get("refresh_token")));

        Jwt jwt = verifier.verify(accessToken); // fresh token — must validate
        String engineUserId = identityResolver.toEngineUserId(jwt.getSubject());
        String sid = jwt.getClaimAsString("sid");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("accessToken", accessToken);
        body.put("sid", sid);
        try {
            body.put("session", sessionService.session(engineUserId, tenant));
        } catch (SessionService.TenantForbiddenException e) {
            return error(HttpStatus.FORBIDDEN, "Forbidden", e.getMessage());
        } catch (PermissionsClient.UpstreamException e) {
            return error(HttpStatus.BAD_GATEWAY, "Bad Gateway", e.getMessage());
        } catch (Exception e) {
            return error(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Error", e.getMessage());
        }
        return ResponseEntity.ok(body);
    }

    private void setRefreshCookie(HttpServletResponse response, String refreshToken) {
        if (isBlank(refreshToken)) return;
        response.addHeader(HttpHeaders.SET_COOKIE, cookie(refreshToken, 60L * 60 * 24 * 30));
    }

    private void clearRefreshCookie(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, cookie("", 0));
    }

    private String cookie(String value, long maxAgeSeconds) {
        StringBuilder sb = new StringBuilder(REFRESH_COOKIE).append('=').append(value)
                .append("; Path=/auth")
                .append("; HttpOnly")
                .append("; Max-Age=").append(maxAgeSeconds)
                .append("; SameSite=").append(cookieSameSite);
        if (cookieSecure) sb.append("; Secure");
        return sb.toString();
    }

    private static boolean isBlank(String s) { return s == null || s.isBlank(); }

    private static String str(Object o) { return o == null ? null : String.valueOf(o); }

    /** Clamp an upstream status into a sane client-facing code. */
    private static int normalize(int status) {
        if (status >= 400 && status < 600) return status;
        return HttpStatus.BAD_GATEWAY.value();
    }

    private ResponseEntity<Map<String, String>> error(HttpStatus status, String title, String message) {
        return ResponseEntity.status(status).body(Map.of("error", title, "message", message));
    }
}
