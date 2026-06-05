package com.luke.auth.session;

import com.fasterxml.jackson.core.type.TypeReference;
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
 * Reads the two systems of record on behalf of a user:
 * <ul>
 *   <li>core-engine {@code GET /api/me/permissions} — Camunda roles/tenants/candidate
 *       groups, called with the user's act-as Bearer token;</li>
 *   <li>capability-engine {@code GET /api/my-capabilities} — capability levels,
 *       called with the tenant + user headers.</li>
 * </ul>
 * Pure I/O: no merging or policy here.
 */
@Component
public class PermissionsClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {};
    private static final TypeReference<Map<String, String>> STR_MAP = new TypeReference<>() {};

    private final String coreBaseUrl;
    private final String capabilityBaseUrl;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public PermissionsClient(@Value("${luke.auth.core-engine.base-url}") String coreBaseUrl,
                             @Value("${luke.auth.capability-engine.base-url:http://localhost:8082}") String capabilityBaseUrl) {
        this.coreBaseUrl = strip(coreBaseUrl);
        this.capabilityBaseUrl = strip(capabilityBaseUrl);
    }

    /** Camunda view for the user the act-as token asserts. */
    public Map<String, Object> corePermissions(String actAsToken) {
        HttpRequest req = HttpRequest.newBuilder(URI.create(coreBaseUrl + "/api/me/permissions"))
                .timeout(Duration.ofSeconds(15))
                .header("Authorization", "Bearer " + actAsToken)
                .GET().build();
        return send(req, MAP);
    }

    /**
     * Capability levels for the user in the tenant, e.g. {@code {"FORMS":"read-write"}}.
     * Sends the act-as token (capability-engine derives the user from its verified
     * {@code sub} when token verification is on) plus the headers (used when it is
     * off / local dev). The tenant rides as a header — capability access is
     * grant-gated per (tenant, user), so an unverified tenant grants nothing extra.
     */
    public Map<String, String> capabilities(String tenantId, String userId, String actAsToken) {
        HttpRequest req = HttpRequest.newBuilder(URI.create(capabilityBaseUrl + "/api/my-capabilities"))
                .timeout(Duration.ofSeconds(15))
                .header("Authorization", "Bearer " + actAsToken)
                .header("X-Tenant-Id", tenantId)
                .header("X-User-Id", userId)
                .GET().build();
        return send(req, STR_MAP);
    }

    private <T> T send(HttpRequest req, TypeReference<T> type) {
        try {
            HttpResponse<byte[]> res = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (res.statusCode() / 100 != 2) {
                throw new UpstreamException(req.uri().getPath() + " returned " + res.statusCode());
            }
            return MAPPER.readValue(res.body(), type);
        } catch (UpstreamException e) {
            throw e;
        } catch (Exception e) {
            throw new UpstreamException("Failed calling " + req.uri() + ": " + e.getMessage());
        }
    }

    private static String strip(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /** A source of truth was unreachable or errored. */
    public static class UpstreamException extends RuntimeException {
        public UpstreamException(String message) { super(message); }
    }
}
