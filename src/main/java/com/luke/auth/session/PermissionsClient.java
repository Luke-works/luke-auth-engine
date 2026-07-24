package com.luke.auth.session;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Reads the two systems of record on behalf of a user:
 * <ul>
 *   <li>core-engine {@code GET /api/me/permissions} — Camunda roles/tenants/candidate
 *       groups, called with the user's act-as Bearer token;</li>
 *   <li>core-engine {@code GET /api/my-capabilities} — capability levels (the
 *       capability domain was merged into core-engine), called with tenant + user
 *       headers.</li>
 * </ul>
 * Pure I/O: no merging or policy here.
 */
@Component
public class PermissionsClient {

    private static final Logger log = LoggerFactory.getLogger(PermissionsClient.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {};
    private static final TypeReference<Map<String, String>> STR_MAP = new TypeReference<>() {};

    private final String coreBaseUrl;
    private final int maxAttempts;
    private final long backoffMillis;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public PermissionsClient(@Value("${luke.auth.core-engine.base-url}") String coreBaseUrl,
                             @Value("${luke.auth.upstream.max-attempts:2}") int maxAttempts,
                             @Value("${luke.auth.upstream.retry-backoff-ms:200}") long backoffMillis) {
        this.coreBaseUrl = strip(coreBaseUrl);
        this.maxAttempts = Math.max(1, maxAttempts);
        this.backoffMillis = Math.max(0, backoffMillis);
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
     * Sends the act-as token (the engine derives the user from its verified
     * {@code sub} when token verification is on) plus the headers (used when it is
     * off / local dev). The tenant rides as a header — capability access is
     * grant-gated per (tenant, user), so an unverified tenant grants nothing extra.
     * Served by core-engine since the capability merge (was capability-engine).
     */
    public Map<String, String> capabilities(String tenantId, String userId, String actAsToken) {
        HttpRequest req = HttpRequest.newBuilder(URI.create(coreBaseUrl + "/api/my-capabilities"))
                .timeout(Duration.ofSeconds(15))
                .header("Authorization", "Bearer " + actAsToken)
                .header("X-Tenant-Id", tenantId)
                .header("X-User-Id", userId)
                .GET().build();
        return send(req, STR_MAP);
    }

    private <T> T send(HttpRequest req, TypeReference<T> type) {
        UpstreamException last = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            UpstreamException failure;
            boolean retryable;
            try {
                HttpResponse<byte[]> res = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
                int code = res.statusCode();
                if (code / 100 == 2) {
                    return MAPPER.readValue(res.body(), type);
                }
                // Status is safe to surface; the path names an internal API, so it stays in the log.
                log.warn("Upstream {} returned {}", req.uri(), code);
                failure = new UpstreamException(code, "Upstream returned " + code);
                retryable = code >= 500; // 4xx is deterministic (e.g. 403 unprovisioned) — don't retry
            } catch (Exception e) {
                // The URI names an internal host — keep it in the log, out of the exception
                // message, because callers surface that message to clients (#37).
                log.warn("Upstream call failed: {} — {}", req.uri(), e.toString());
                failure = new UpstreamException(0, "Upstream request did not complete");
                retryable = true; // network/timeout — worth a retry
            }
            last = failure;
            if (!retryable || attempt == maxAttempts) {
                throw failure;
            }
            try {
                Thread.sleep(backoffMillis * attempt); // simple linear backoff
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw failure;
            }
        }
        throw last; // unreachable (loop always returns or throws)
    }

    private static String strip(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /** A source of truth was unreachable or errored. {@code status} is the upstream
     *  HTTP status (0 if the call never completed). */
    public static class UpstreamException extends RuntimeException {
        private final int status;
        public UpstreamException(int status, String message) {
            super(message);
            this.status = status;
        }
        public int status() { return status; }
    }
}
