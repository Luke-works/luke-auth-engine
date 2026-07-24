package com.luke.auth.workos;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Thin REST client for the WorkOS User Management API — the authentication
 * system of record. Built on the JDK {@link HttpClient} (no WorkOS SDK
 * dependency, whose Java support is thin) so the dependency surface is unchanged.
 *
 * <p>Two call shapes:
 * <ul>
 *   <li><b>Management</b> calls (e.g. create user) authenticate with the secret
 *       API key as a Bearer header;</li>
 *   <li><b>Authenticate</b> calls send {@code client_id} + {@code client_secret}
 *       (the API key) in the body alongside a {@code grant_type}.</li>
 * </ul>
 *
 * <p>Endpoint paths are centralised here as constants — verify them against the
 * current WorkOS API reference if WorkOS revises the surface.
 */
@Component
public class WorkosClient {

    private static final Logger log = LoggerFactory.getLogger(WorkosClient.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {};

    private static final String USERS_PATH        = "/user_management/users";
    private static final String AUTHENTICATE_PATH = "/user_management/authenticate";
    private static final String AUTHORIZE_PATH    = "/user_management/authorize";
    private static final String LOGOUT_PATH       = "/user_management/sessions/logout";
    private static final String INVITATIONS_PATH  = "/user_management/invitations";

    private final String apiBase;
    private final String clientId;
    private final String apiKey;
    private final String redirectUri;
    private final boolean markEmailVerified;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public WorkosClient(@Value("${luke.auth.workos.api-base-url:https://api.workos.com}") String apiBase,
                        @Value("${luke.auth.workos.client-id:}") String clientId,
                        @Value("${luke.auth.workos.api-key:}") String apiKey,
                        @Value("${luke.auth.workos.redirect-uri:http://localhost:8083/auth/callback}") String redirectUri,
                        @Value("${luke.auth.workos.mark-email-verified-on-register:false}") boolean markEmailVerified,
                        @Value("${luke.auth.dev-mode:false}") boolean devMode) {
        // Auto-verifying email at signup defeats email-ownership proof (anyone could
        // register under an address they don't control). It's a dev-only shortcut, so
        // refuse to boot if it's enabled without dev-mode — it must never reach prod.
        if (markEmailVerified && !devMode) {
            throw new IllegalStateException(
                    "luke.auth.workos.mark-email-verified-on-register=true is a dev-only shortcut and "
                    + "must not be enabled in production (set luke.auth.dev-mode=true to use it locally).");
        }
        this.apiBase = strip(apiBase);
        this.clientId = clientId;
        this.apiKey = apiKey;
        this.redirectUri = redirectUri;
        this.markEmailVerified = markEmailVerified;
    }

    // ── Management: create a user (Bearer API key) ──────────────────────────

    /** Create a WorkOS user. Returns the user object (read {@code "id"} for the user id). */
    public Map<String, Object> createUser(String email, String password, String firstName, String lastName) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", email);
        if (password != null && !password.isBlank()) body.put("password", password);
        if (firstName != null && !firstName.isBlank()) body.put("first_name", firstName);
        if (lastName != null && !lastName.isBlank()) body.put("last_name", lastName);
        // Only when the dev-only shortcut is on (guarded in the constructor) do we
        // pre-verify. With it off — the prod default — email_verified is left unset so
        // WorkOS runs its own email verification and gates password auth on ownership.
        if (markEmailVerified) body.put("email_verified", true);
        return postJson(USERS_PATH, body, /*bearer=*/true);
    }

    /** Fetch a WorkOS user by id (read {@code "email"}, {@code "first_name"}, …). */
    public Map<String, Object> getUser(String userId) {
        return sendJson("GET", USERS_PATH + "/" + userId, null, /*bearer=*/true);
    }

    /** Update a user's mutable fields (e.g. {@code first_name}, {@code last_name}, {@code password}). */
    public Map<String, Object> updateUser(String userId, Map<String, Object> fields) {
        return sendJson("PUT", USERS_PATH + "/" + userId, fields, /*bearer=*/true);
    }

    /** Permanently delete a WorkOS user. */
    public void deleteUser(String userId) {
        sendJson("DELETE", USERS_PATH + "/" + userId, null, /*bearer=*/true);
    }

    /** Look up a WorkOS user by email (exact match). Returns the user object or null. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> findUserByEmail(String email) {
        Map<String, Object> res = sendJson("GET", USERS_PATH + "?email=" + enc(email), null, /*bearer=*/true);
        Object data = res.get("data");
        if (data instanceof java.util.List<?> list && !list.isEmpty() && list.get(0) instanceof Map) {
            return (Map<String, Object>) list.get(0);
        }
        return null;
    }

    // ── Invitations: email a teammate a link to join (set their password) ───

    /** Send a WorkOS invitation email. Returns the invitation object (read {@code "id"}). */
    public Map<String, Object> sendInvitation(String email, String inviterUserId) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", email);
        if (inviterUserId != null && !inviterUserId.isBlank()) body.put("inviter_user_id", inviterUserId);
        return postJson(INVITATIONS_PATH, body, /*bearer=*/true);
    }

    /** List invitations, optionally filtered to a single email. Returns {@code {data:[...], ...}}. */
    public Map<String, Object> listInvitations(String email) {
        String path = INVITATIONS_PATH + "?order=desc&limit=50";
        if (email != null && !email.isBlank()) path += "&email=" + enc(email);
        return sendJson("GET", path, null, /*bearer=*/true);
    }

    /** Revoke a pending invitation. */
    public Map<String, Object> revokeInvitation(String invitationId) {
        return postJson(INVITATIONS_PATH + "/" + invitationId + "/revoke", new LinkedHashMap<>(), /*bearer=*/true);
    }

    // ── Authenticate: password / authorization_code / refresh_token ─────────

    /** Email + password login. Returns {@code {user, access_token, refresh_token, ...}}. */
    public Map<String, Object> authenticateWithPassword(String email, String password) {
        Map<String, Object> body = baseAuth("password");
        body.put("email", email);
        body.put("password", password);
        return postJson(AUTHENTICATE_PATH, body, /*bearer=*/false);
    }

    /** Exchange an authorization code (from the social/SSO redirect) for tokens. */
    public Map<String, Object> authenticateWithCode(String code) {
        Map<String, Object> body = baseAuth("authorization_code");
        body.put("code", code);
        return postJson(AUTHENTICATE_PATH, body, /*bearer=*/false);
    }

    /** Swap a refresh token for a fresh access (and rotated refresh) token. */
    public Map<String, Object> authenticateWithRefreshToken(String refreshToken) {
        Map<String, Object> body = baseAuth("refresh_token");
        body.put("refresh_token", refreshToken);
        return postJson(AUTHENTICATE_PATH, body, /*bearer=*/false);
    }

    // ── Redirect URLs (no HTTP call; built for the browser to follow) ───────

    /**
     * Authorization URL to redirect the browser to for social/SSO login.
     * {@code provider} is a WorkOS provider value (e.g. {@code GoogleOAuth},
     * {@code MicrosoftOAuth}, {@code authkit}).
     */
    public String authorizationUrl(String provider, String state) {
        StringBuilder sb = new StringBuilder(apiBase).append(AUTHORIZE_PATH).append('?')
                .append("client_id=").append(enc(clientId))
                .append("&redirect_uri=").append(enc(redirectUri))
                .append("&response_type=code")
                .append("&provider=").append(enc(provider));
        if (state != null && !state.isBlank()) {
            sb.append("&state=").append(enc(state));
        }
        return sb.toString();
    }

    /** WorkOS-hosted logout URL for a session id (ends the WorkOS session). */
    public String logoutUrl(String sessionId) {
        return apiBase + LOGOUT_PATH + "?session_id=" + enc(sessionId);
    }

    /** Revoke a WorkOS session server-side (does not rely on the browser following a
     *  logout URL). Best-effort: callers should ignore failures. */
    public void revokeSession(String sessionId) {
        postJson("/user_management/sessions/" + enc(sessionId) + "/revoke", new LinkedHashMap<>(), /*bearer=*/true);
    }

    // ────────────────────────────────────────────────────────────────────────

    private Map<String, Object> baseAuth(String grantType) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("client_id", clientId);
        body.put("client_secret", apiKey);
        body.put("grant_type", grantType);
        return body;
    }

    private Map<String, Object> postJson(String path, Map<String, Object> body, boolean bearer) {
        return sendJson("POST", path, body, bearer);
    }

    /** Generic JSON request. {@code body} null → no request body (GET/DELETE). */
    private Map<String, Object> sendJson(String method, String path, Map<String, Object> body, boolean bearer) {
        try {
            HttpRequest.BodyPublisher pub = (body == null)
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofByteArray(MAPPER.writeValueAsBytes(body));
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(apiBase + path))
                    .timeout(Duration.ofSeconds(15))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .method(method, pub);
            if (bearer) {
                b.header("Authorization", "Bearer " + apiKey);
            }
            HttpResponse<byte[]> res = http.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
            Map<String, Object> parsed = (res.body() != null && res.body().length > 0)
                    ? MAPPER.readValue(res.body(), MAP)
                    : Map.of();
            if (res.statusCode() / 100 != 2) {
                Object msg = parsed.getOrDefault("message", parsed.getOrDefault("error", "WorkOS error"));
                throw new WorkosException(res.statusCode(), String.valueOf(msg), parsed);
            }
            return parsed;
        } catch (WorkosException e) {
            throw e;
        } catch (Exception e) {
            // Transport failure (DNS/TLS/timeout). The cause names api.workos.com internals,
            // so it goes to the log; the 502 message stays generic (#37).
            log.warn("WorkOS {} {} failed", method, path, e);
            throw new WorkosException(502, "WorkOS call failed", Map.of());
        }
    }

    private static String enc(String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }

    private static String strip(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /** A WorkOS API call returned a non-2xx; carries the status + parsed error body. */
    public static class WorkosException extends RuntimeException {
        private final int status;
        private final transient Map<String, Object> payload;

        public WorkosException(int status, String message, Map<String, Object> payload) {
            super(message);
            this.status = status;
            this.payload = payload;
        }

        public int status() { return status; }
        public Map<String, Object> payload() { return payload; }

        /** WorkOS error code (e.g. {@code email_verification_required}), if present. */
        public String code() {
            Object c = payload == null ? null : payload.get("code");
            return c == null ? null : String.valueOf(c);
        }
    }
}
