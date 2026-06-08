package com.luke.auth.web;

import com.luke.auth.config.GatewayKeys;
import com.luke.auth.config.WorkosTokenVerifier;
import com.luke.auth.identity.IdentityResolver;
import com.luke.auth.session.PermissionsClient;
import com.luke.auth.session.SessionService;
import com.luke.auth.workos.OnboardingClient;
import com.luke.auth.workos.WorkosClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
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
    private final GatewayKeys gatewayKeys;
    private final CoreAdminClient coreAdmin;

    private final String uiCallbackUrl;
    private final boolean cookieSecure;
    private final String cookieSameSite;

    public AuthController(WorkosClient workos,
                          WorkosTokenVerifier verifier,
                          IdentityResolver identityResolver,
                          OnboardingClient onboarding,
                          SessionService sessionService,
                          GatewayKeys gatewayKeys,
                          CoreAdminClient coreAdmin,
                          @Value("${luke.auth.workos.ui-callback-url:http://localhost:5173/sso-callback}") String uiCallbackUrl,
                          @Value("${luke.auth.workos.cookie-secure:true}") boolean cookieSecure,
                          @Value("${luke.auth.workos.cookie-same-site:Lax}") String cookieSameSite) {
        this.workos = workos;
        this.verifier = verifier;
        this.identityResolver = identityResolver;
        this.onboarding = onboarding;
        this.sessionService = sessionService;
        this.gatewayKeys = gatewayKeys;
        this.coreAdmin = coreAdmin;
        this.uiCallbackUrl = uiCallbackUrl;
        this.cookieSecure = cookieSecure;
        this.cookieSameSite = cookieSameSite;
    }

    public record RegisterRequest(String email, String password, String firstName, String lastName) {}
    public record LoginRequest(String email, String password) {}
    public record ProfileRequest(String firstName, String lastName) {}
    public record PasswordRequest(String currentPassword, String newPassword) {}
    public record InviteRequest(String firstName, String lastName, String email) {}
    public record AddMemberRequest(String email, String role, String accessLevel) {}

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
            body.put("user", userView(user));
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

    // ── Account management (authenticated; acts on the token's WorkOS user) ──

    @PatchMapping("/profile")
    public ResponseEntity<?> updateProfile(@RequestBody ProfileRequest req, HttpServletRequest request) {
        String userId = requireWorkosUserId(request);
        if (userId == null) return error(HttpStatus.UNAUTHORIZED, "Unauthorized", "Missing or invalid token");
        Map<String, Object> fields = new LinkedHashMap<>();
        if (req.firstName() != null) fields.put("first_name", req.firstName());
        if (req.lastName() != null) fields.put("last_name", req.lastName());
        if (fields.isEmpty()) return error(HttpStatus.BAD_REQUEST, "Bad Request", "Nothing to update");
        try {
            Map<String, Object> updated = workos.updateUser(userId, fields);
            return ResponseEntity.ok(Map.of("user", userView(updated)));
        } catch (WorkosClient.WorkosException e) {
            return error(HttpStatus.valueOf(normalize(e.status())), "Update failed", e.getMessage());
        }
    }

    @PostMapping("/password")
    public ResponseEntity<?> changePassword(@RequestBody PasswordRequest req, HttpServletRequest request) {
        String userId = requireWorkosUserId(request);
        if (userId == null) return error(HttpStatus.UNAUTHORIZED, "Unauthorized", "Missing or invalid token");
        if (isBlank(req.newPassword())) return error(HttpStatus.BAD_REQUEST, "Bad Request", "newPassword is required");
        try {
            // Verify the current password by re-authenticating (needs the user's email).
            String email = str(workos.getUser(userId).get("email"));
            if (email == null) return error(HttpStatus.BAD_GATEWAY, "Bad Gateway", "Could not resolve user");
            if (!isBlank(req.currentPassword())) {
                try {
                    workos.authenticateWithPassword(email, req.currentPassword());
                } catch (WorkosClient.WorkosException e) {
                    return error(HttpStatus.FORBIDDEN, "Forbidden", "Current password is incorrect");
                }
            }
            workos.updateUser(userId, Map.of("password", req.newPassword()));
            return ResponseEntity.ok(Map.of("ok", true));
        } catch (WorkosClient.WorkosException e) {
            return error(HttpStatus.valueOf(normalize(e.status())), "Password change failed", e.getMessage());
        }
    }

    @DeleteMapping("/account")
    public ResponseEntity<?> deleteAccount(HttpServletRequest request, HttpServletResponse response) {
        Jwt jwt = verifiedJwt(request);
        if (jwt == null) return error(HttpStatus.UNAUTHORIZED, "Unauthorized", "Missing or invalid token");
        String workosUserId = jwt.getSubject();
        String engineUserId = identityResolver.toEngineUserId(workosUserId);

        // 1. Cascade engine-side cleanup FIRST (it needs the identity to still exist).
        //    If it fails, abort and leave the WorkOS user so the delete can be retried.
        try {
            CoreAdminClient.CoreResponse core = coreAdmin.deleteAccount(mintActAs(engineUserId));
            if (core.status() / 100 != 2) {
                return error(HttpStatus.BAD_GATEWAY, "Delete failed",
                        "Could not clean up the engine account (status " + core.status() + ")");
            }
        } catch (CoreAdminClient.CoreException e) {
            return error(HttpStatus.BAD_GATEWAY, "Delete failed", e.getMessage());
        }

        // 2. Now remove the WorkOS identity.
        try {
            workos.deleteUser(workosUserId);
        } catch (WorkosClient.WorkosException e) {
            return error(HttpStatus.valueOf(normalize(e.status())), "Delete failed", e.getMessage());
        }
        clearRefreshCookie(response);
        return ResponseEntity.ok(Map.of("ok", true));
    }

    // ── Org admin: invite teammates + add existing users to the org ──────────
    //    Every call requires the caller to be a tenant-admin of X-Tenant-Id.

    @PostMapping("/org/invitations")
    public ResponseEntity<?> invite(@RequestBody InviteRequest req, HttpServletRequest request) {
        AdminCaller caller = requireTenantAdmin(request);
        if (caller.error != null) return caller.error;
        if (isBlank(req.email())) return error(HttpStatus.BAD_REQUEST, "Bad Request", "email is required");
        try {
            Map<String, Object> inv = workos.sendInvitation(req.email().trim(), caller.workosUserId);
            return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("ok", true, "invitation", invitationView(inv)));
        } catch (WorkosClient.WorkosException e) {
            return error(HttpStatus.valueOf(normalize(e.status())), "Invite failed", e.getMessage());
        }
    }

    @GetMapping("/org/invitations")
    public ResponseEntity<?> listInvitations(HttpServletRequest request) {
        AdminCaller caller = requireTenantAdmin(request);
        if (caller.error != null) return caller.error;
        try {
            Object data = workos.listInvitations(null).get("data");
            List<Map<String, Object>> views = new ArrayList<>();
            if (data instanceof List<?> list) {
                for (Object o : list) {
                    if (o instanceof Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> m = (Map<String, Object>) o;
                        views.add(invitationView(m));
                    }
                }
            }
            return ResponseEntity.ok(Map.of("invitations", views));
        } catch (WorkosClient.WorkosException e) {
            return error(HttpStatus.valueOf(normalize(e.status())), "Could not list invitations", e.getMessage());
        }
    }

    @PostMapping("/org/invitations/{id}/revoke")
    public ResponseEntity<?> revokeInvitation(@PathVariable String id, HttpServletRequest request) {
        AdminCaller caller = requireTenantAdmin(request);
        if (caller.error != null) return caller.error;
        try {
            workos.revokeInvitation(id);
            return ResponseEntity.ok(Map.of("ok", true));
        } catch (WorkosClient.WorkosException e) {
            return error(HttpStatus.valueOf(normalize(e.status())), "Revoke failed", e.getMessage());
        }
    }

    @PostMapping("/org/members")
    public ResponseEntity<?> addMember(@RequestBody AddMemberRequest req, HttpServletRequest request) {
        AdminCaller caller = requireTenantAdmin(request);
        if (caller.error != null) return caller.error;
        if (isBlank(req.email())) return error(HttpStatus.BAD_REQUEST, "Bad Request", "email is required");

        Map<String, Object> invitee;
        try {
            invitee = workos.findUserByEmail(req.email().trim());
        } catch (WorkosClient.WorkosException e) {
            return error(HttpStatus.valueOf(normalize(e.status())), "Lookup failed", e.getMessage());
        }
        if (invitee == null) {
            return error(HttpStatus.NOT_FOUND, "Not Found",
                    "No user with that email yet. Send them an invite first.");
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", identityResolver.toEngineUserId(str(invitee.get("id"))));
        body.put("firstName", invitee.get("first_name"));
        body.put("lastName", invitee.get("last_name"));
        body.put("email", invitee.get("email"));
        body.put("role", isBlank(req.role()) ? "tenant-user" : req.role());
        body.put("accessLevel", req.accessLevel());

        CoreAdminClient.CoreResponse core;
        try {
            core = coreAdmin.createOrgUser(mintActAs(caller.engineUserId), caller.tenant, body);
        } catch (CoreAdminClient.CoreException e) {
            return error(HttpStatus.BAD_GATEWAY, "Bad Gateway", e.getMessage());
        }
        return ResponseEntity.status(core.status())
                .contentType(MediaType.APPLICATION_JSON)
                .body(core.body().length == 0 ? new byte[0] : core.body());
    }

    // ────────────────────────────────────────────────────────────────────────

    /** A verified caller who is a tenant-admin of their active tenant, or an {@code error} to return. */
    private record AdminCaller(String workosUserId, String engineUserId, String tenant, ResponseEntity<?> error) {}

    private AdminCaller requireTenantAdmin(HttpServletRequest request) {
        Jwt jwt = verifiedJwt(request);
        if (jwt == null) {
            return new AdminCaller(null, null, null,
                    error(HttpStatus.UNAUTHORIZED, "Unauthorized", "Missing or invalid token"));
        }
        String tenant = request.getHeader("X-Tenant-Id");
        if (isBlank(tenant)) {
            return new AdminCaller(null, null, null,
                    error(HttpStatus.BAD_REQUEST, "Bad Request", "X-Tenant-Id is required"));
        }
        String engineUserId = identityResolver.toEngineUserId(jwt.getSubject());
        boolean admin;
        try {
            Map<String, Object> session = sessionService.session(engineUserId, tenant);
            admin = Boolean.TRUE.equals(session.get("tenantAdmin"));
        } catch (Exception e) {
            admin = false;
        }
        if (!admin) {
            return new AdminCaller(null, null, null,
                    error(HttpStatus.FORBIDDEN, "Forbidden", "Requires org owner (tenant-admin)"));
        }
        return new AdminCaller(jwt.getSubject(), engineUserId, tenant, null);
    }

    /** Mint an act-as token, converting the checked signing exception into a CoreException. */
    private String mintActAs(String engineUserId) {
        try {
            return gatewayKeys.mintActAsToken(engineUserId);
        } catch (Exception e) {
            throw new CoreAdminClient.CoreException("Could not mint act-as token: " + e.getMessage());
        }
    }

    /** Verify the Bearer access token and return the {@link Jwt}, or null if missing/invalid. */
    private Jwt verifiedJwt(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) return null;
        try {
            return verifier.verify(header.substring(7).trim());
        } catch (Exception e) {
            return null;
        }
    }

    /** Map a WorkOS invitation object to the UI-facing shape. */
    private static Map<String, Object> invitationView(Map<String, Object> inv) {
        Map<String, Object> v = new LinkedHashMap<>();
        if (inv == null) return v;
        v.put("id", inv.get("id"));
        v.put("email", inv.get("email"));
        v.put("state", inv.get("state"));
        v.put("expiresAt", inv.get("expires_at"));
        return v;
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

        @SuppressWarnings("unchecked")
        Map<String, Object> wuser = (auth.get("user") instanceof Map) ? (Map<String, Object>) auth.get("user") : null;

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("accessToken", accessToken);
        body.put("sid", sid);
        body.put("user", userView(wuser));
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

    /** Map a WorkOS user object to the UI-facing shape (camelCase, null-safe). */
    private static Map<String, Object> userView(Map<String, Object> u) {
        Map<String, Object> v = new LinkedHashMap<>();
        if (u == null) return v;
        v.put("id", u.get("id"));
        v.put("email", u.get("email"));
        v.put("firstName", u.get("first_name"));
        v.put("lastName", u.get("last_name"));
        v.put("profilePictureUrl", u.get("profile_picture_url"));
        v.put("emailVerified", u.get("email_verified"));
        return v;
    }

    /** Verified WorkOS user id (the access token's {@code sub}) from the Bearer header, or null. */
    private String requireWorkosUserId(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) return null;
        try {
            return verifier.verify(header.substring(7).trim()).getSubject();
        } catch (Exception e) {
            return null;
        }
    }

    /** Clamp an upstream status into a sane client-facing code. */
    private static int normalize(int status) {
        if (status >= 400 && status < 600) return status;
        return HttpStatus.BAD_GATEWAY.value();
    }

    private ResponseEntity<Map<String, String>> error(HttpStatus status, String title, String message) {
        return ResponseEntity.status(status).body(Map.of("error", title, "message", message));
    }
}
