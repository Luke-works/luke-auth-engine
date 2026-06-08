package com.luke.auth.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Authenticated <em>writes</em> to core-engine on behalf of a user, using a minted
 * act-as Bearer token so core enforces that user's own authorization (e.g. that
 * they're a tenant-admin of the target tenant). The read-only counterpart lives in
 * {@link com.luke.auth.session.PermissionsClient}.
 *
 * <p>Calls return the upstream status + raw body so the controller can relay
 * core's own success/error response (including 403/409) straight to the UI.
 */
@Component
public class CoreAdminClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String coreBaseUrl;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public CoreAdminClient(@Value("${luke.auth.core-engine.base-url}") String coreBaseUrl) {
        this.coreBaseUrl = strip(coreBaseUrl);
    }

    /** Upstream core response: HTTP status + raw JSON body (may be empty). */
    public record CoreResponse(int status, byte[] body) {}

    /** {@code POST /api/org/users} as the user (act-as) in the given tenant. */
    public CoreResponse createOrgUser(String actAsToken, String tenantId, Map<String, Object> body) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(coreBaseUrl + "/api/org/users"))
                    .timeout(Duration.ofSeconds(20))
                    .header("Authorization", "Bearer " + actAsToken)
                    .header("X-Tenant-Id", tenantId == null ? "" : tenantId)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(MAPPER.writeValueAsBytes(body)))
                    .build();
            HttpResponse<byte[]> res = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
            return new CoreResponse(res.statusCode(), res.body() == null ? new byte[0] : res.body());
        } catch (Exception e) {
            throw new CoreException("Failed calling core /api/org/users: " + e.getMessage());
        }
    }

    /** {@code DELETE /api/me/account} as the user (act-as) — cascades engine cleanup. */
    public CoreResponse deleteAccount(String actAsToken) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(coreBaseUrl + "/api/me/account"))
                    .timeout(Duration.ofSeconds(30))
                    .header("Authorization", "Bearer " + actAsToken)
                    .DELETE()
                    .build();
            HttpResponse<byte[]> res = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
            return new CoreResponse(res.statusCode(), res.body() == null ? new byte[0] : res.body());
        } catch (Exception e) {
            throw new CoreException("Failed calling core /api/me/account: " + e.getMessage());
        }
    }

    private static String strip(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /** Core was unreachable or the call never completed. */
    public static class CoreException extends RuntimeException {
        public CoreException(String message) { super(message); }
    }
}
