package com.luke.auth.web;

import com.luke.auth.config.CorrelationIdFilter;
import com.luke.auth.config.GatewayKeys;
import com.luke.auth.config.WorkosTokenVerifier;
import com.luke.auth.identity.IdentityResolver;
import com.luke.auth.session.PermissionsClient;
import com.luke.auth.session.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The transparent reverse proxy — the "guide" that walks every consumer request
 * to {@code luke-core-engine} and vouches for the user.
 *
 * <p>For each request it:
 * <ol>
 *   <li>verifies the caller's WorkOS access token (the wristband),</li>
 *   <li>resolves the WorkOS {@code sub} to an engine userId,</li>
 *   <li>mints a short-lived act-as-user token (the secret badge), and</li>
 *   <li>forwards method + path + query + body + {@code X-Tenant-Id} unchanged,
 *       swapping only the {@code Authorization} header to the minted token.</li>
 * </ol>
 *
 * <p>It is deliberately resource-agnostic: a single wildcard mapping forwards
 * the entire engine API (current and future) opaquely. The powerful act-as-user
 * token never leaves this server — the browser only ever holds its WorkOS token.
 */
@RestController
public class EngineProxyController {

    private static final Logger log = LoggerFactory.getLogger(EngineProxyController.class);

    /** Hop-by-hop / managed request headers we must not copy verbatim between hops.
     *  accept-encoding is dropped so the engine never gzips (no encoding edge cases). */
    private static final Set<String> SKIP_REQUEST_HEADERS = Set.of(
            // Hop-by-hop / restricted headers (RFC 7230). `upgrade`, `connection`, `content-length`,
            // `expect`, `host` are also rejected by the JDK HttpClient — forwarding one 500s the
            // request (a client that sends `Upgrade` would otherwise break every proxied call).
            "host", "authorization", "content-length", "connection", "transfer-encoding",
            "expect", "accept-encoding", "upgrade",
            // Identity / trust headers the downstream engines honor. The gateway is the
            // SOLE asserter of identity (via the minted act-as token), so a client must
            // never be able to inject these to impersonate a user or a trusted service.
            "x-user-id", "x-dev-user", "x-internal-key",
            // Correlation id is re-asserted from the (sanitized) MDC value below, so the
            // raw client header is not copied verbatim.
            "x-correlation-id");

    /** ONLY these upstream response headers are relayed. The engine sits behind its own
     *  Render/Cloudflare edge, so its responses carry infra headers (server, alt-svc,
     *  cf-ray, cf-cache-status, rndr-id, …). Copying those back collides with THIS
     *  service's edge and makes it return 502 — so we allowlist safe content headers only
     *  (CORS is added by this service's own CorsFilter, not relayed from the engine). */
    private static final Set<String> RELAY_RESPONSE_HEADERS = Set.of(
            "content-type", "cache-control", "etag", "last-modified",
            "location", "content-disposition", "www-authenticate", "retry-after",
            // DOCUMENTS downloads (/api/documents/{id}/content) advertise byte ranges for react-pdf.
            "accept-ranges", "content-range",
            // Route B M2: the embed PAGE sets these and they MUST reach the browser to take effect —
            // content-security-policy carries the per-tenant frame-ancestors clickjacking policy.
            "content-security-policy", "x-content-type-options");

    private final WorkosTokenVerifier workosVerifier;
    private final IdentityResolver identityResolver;
    private final GatewayKeys gatewayKeys;
    private final SessionService sessionService;
    private final String coreEngineBaseUrl;
    private final String fileProxyBaseUrl;
    private final HttpClient httpClient;

    private final boolean devMode;

    /** Max bytes accepted for a forwarded request body; larger ones get 413. Default 100 MiB. */
    private final long maxRequestBytes;

    public EngineProxyController(WorkosTokenVerifier workosVerifier,
                                 IdentityResolver identityResolver,
                                 GatewayKeys gatewayKeys,
                                 SessionService sessionService,
                                 @Value("${luke.auth.core-engine.base-url}") String coreEngineBaseUrl,
                                 @Value("${luke.auth.file-proxy.base-url:}") String fileProxyBaseUrl,
                                 @Value("${luke.auth.dev-mode:false}") boolean devMode,
                                 @Value("${luke.auth.proxy.max-request-bytes:104857600}") long maxRequestBytes) {
        this.workosVerifier = workosVerifier;
        this.identityResolver = identityResolver;
        this.gatewayKeys = gatewayKeys;
        this.sessionService = sessionService;
        this.devMode = devMode;
        this.maxRequestBytes = maxRequestBytes;
        this.coreEngineBaseUrl = stripTrailingSlash(coreEngineBaseUrl);
        // The DOCUMENTS byte tier (luke-file-proxy). When unset, /api/documents/** falls through to core
        // unchanged (no behavior change) — set it to send byte traffic to the proxy instead.
        this.fileProxyBaseUrl = fileProxyBaseUrl == null || fileProxyBaseUrl.isBlank()
                ? null : stripTrailingSlash(fileProxyBaseUrl);
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /** Catch-all: forwards every path not claimed by a more specific mapping (JWKS, actuator). */
    @RequestMapping("/**")
    public ResponseEntity<byte[]> proxy(HttpServletRequest request) throws Exception {

        // CORS preflight is handled by CorsFilter; any stray OPTIONS just succeeds.
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return ResponseEntity.ok().build();
        }

        // Reject oversized uploads up front when the client declares the length (#21).
        // Chunked/unknown-length requests are bounded during streaming by MaxSizeInputStream.
        if (request.getContentLengthLong() > maxRequestBytes) {
            return payloadTooLarge();
        }

        // Canonicalize the path first: decode percent-escapes and resolve/refuse
        // any "." or ".." segments. The public/protected decision must match what
        // the engine ultimately resolves — otherwise a raw path like
        // /api/public/../me (or its encoded form /api/public/%2e%2e/me) would be
        // treated as public here yet hit a protected endpoint downstream.
        String canonicalPath = canonicalPath(request.getRequestURI());
        if (canonicalPath == null) {
            return badRequest("Malformed or traversing request path");
        }

        // The unauthenticated surface — a signed embed token (validated downstream) is the auth, so
        // these are forwarded WITHOUT a WorkOS token and WITHOUT an act-as badge:
        //  • /api/public/**     — the public embed render/submit API.
        //  • /embed/{token}     — the public embed PAGE (engine-served HTML carrying the form's
        //                         per-tenant frame-ancestors clickjacking policy). Route B M2.
        //  • /embed-assets/**   — that page's self-contained renderer bundle (static js/css).
        // Scoped to exactly these prefixes — nothing else may be public.
        boolean isPublic = canonicalPath.startsWith("/api/public/")
                || canonicalPath.startsWith("/embed/")
                || canonicalPath.startsWith("/embed-assets/");

        // Route the byte tier (luke-file-proxy) when configured: the authenticated /api/documents/** AND
        // the PUBLIC embed-upload surface /api/public/documents/** (token-authorized, no user), plus the
        // EMAIL ASSET tier — authenticated upload /api/email-assets/** and the PUBLIC image-serve surface
        // /api/public/email-assets/** (assetId-as-bearer, no user; loaded by a recipient's mail client).
        // Everything else — and these when the proxy URL is unset — goes to core-engine.
        boolean toFileProxy = fileProxyBaseUrl != null
                && (canonicalPath.startsWith("/api/documents") || canonicalPath.startsWith("/api/public/documents")
                    || canonicalPath.startsWith("/api/email-assets") || canonicalPath.startsWith("/api/public/email-assets"));
        String baseUrl = toFileProxy ? fileProxyBaseUrl : coreEngineBaseUrl;

        String actAsToken = null;
        String engineUserId = null;
        if (!isPublic) {
            // ── 1. Authenticate: verify the WorkOS wristband ──────────────────
            String workosToken = bearerToken(request);
            if (workosToken != null) {
                try {
                    engineUserId = identityResolver.toEngineUserId(workosVerifier.verify(workosToken).getSubject());
                } catch (JwtException | IllegalArgumentException e) {
                    log.debug("Rejected request: {}", e.getMessage());
                }
            }
            // Dev-mode fallback (local only): an X-Dev-User header stands in for a
            // verified WorkOS token, mirroring /session. Never enable in prod.
            if (engineUserId == null && devMode) {
                String dev = request.getHeader("X-Dev-User");
                if (dev != null && !dev.isBlank()) {
                    engineUserId = dev.trim();
                }
            }
            if (engineUserId == null) {
                return unauthorized(workosToken == null ? "Missing Bearer token" : "Invalid or expired token");
            }

            // ── 2. Assert tenant scope at the trust boundary ──────────────────
            // The gateway injects identity, so it must also vouch for the tenant the
            // caller claims. If the request carries X-Tenant-Id, verify the user is a
            // member (operators may use any tenant) BEFORE minting/forwarding — we do
            // not relay a client tenant header the user can't actually use.
            String requestedTenant = request.getHeader("X-Tenant-Id");
            if (requestedTenant != null && !requestedTenant.isBlank()) {
                try {
                    Map<String, Object> sess = sessionService.session(engineUserId, requestedTenant.trim());
                    if (!requestedTenant.trim().equals(sess.get("tenant"))) {
                        return forbidden("Not a member of tenant '" + requestedTenant.trim() + "'");
                    }
                } catch (SessionService.TenantForbiddenException e) {
                    return forbidden(e.getMessage());
                } catch (PermissionsClient.UpstreamException e) {
                    log.warn("Tenant membership check failed (upstream) for {} / {}: {}",
                            engineUserId, requestedTenant, e.getMessage());
                    return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                            .contentType(MediaType.APPLICATION_JSON)
                            .body("{\"error\":\"Bad Gateway\",\"message\":\"Could not verify tenant access\"}".getBytes());
                }
            }

            // ── 3. Mint the act-as-user badge ─────────────────────────────────
            actAsToken = gatewayKeys.mintActAsToken(engineUserId);
        }

        // ── 4. Forward to the engine, swapping only Authorization ─────────────
        // STREAM the request body instead of readAllBytes() (#21): peak heap no longer
        // scales with (concurrent requests × body size). The body is fed straight from
        // the servlet input stream, capped by MaxSizeInputStream for chunked uploads.
        // (The RESPONSE stays buffered as a byte[] — streaming tiny responses dropped them.)
        URI target = buildTargetUri(request, baseUrl);
        HttpRequest.BodyPublisher bodyPublisher = bodyPublisherFor(request);

        HttpRequest.Builder forward = HttpRequest.newBuilder(target)
                .timeout(Duration.ofSeconds(60))
                .method(request.getMethod(), bodyPublisher);

        copyRequestHeaders(request, forward);
        if (actAsToken != null) forward.header(HttpHeaders.AUTHORIZATION, "Bearer " + actAsToken);
        // The file-proxy reads identity from headers (it does NOT verify the act-as JWT), so the gateway —
        // the sole identity asserter — injects X-User-Id here. The raw client X-User-Id was stripped on
        // the way in (SKIP_REQUEST_HEADERS), so this is always the gateway-vouched value, never spoofable.
        if (toFileProxy && engineUserId != null) forward.header("X-User-Id", engineUserId);
        // Propagate the request's correlation id to core-engine so one trace spans the
        // gateway → engine hop (CorrelationIdFilter set it on the MDC for this thread).
        String correlationId = MDC.get(CorrelationIdFilter.MDC_KEY);
        if (correlationId != null) forward.header(CorrelationIdFilter.HEADER, correlationId);

        HttpResponse<byte[]> upstream;
        try {
            upstream = httpClient.send(forward.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (Exception e) {
            if (isPayloadTooLarge(e)) {
                log.debug("Rejected oversized streamed request body for {} {}", request.getMethod(), target);
                return payloadTooLarge();
            }
            log.error("Upstream engine call failed for {} {}", request.getMethod(), target, e);
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"Bad Gateway\",\"message\":\"Engine unreachable\"}".getBytes());
        }

        // ── 5. Relay the engine's response back to the consumer ───────────────
        return relay(upstream);
    }

    /** Streaming body publisher for the forwarded request, or no-body for empty/bodyless methods. */
    private HttpRequest.BodyPublisher bodyPublisherFor(HttpServletRequest request) {
        boolean bodyless = "GET".equalsIgnoreCase(request.getMethod())
                || "HEAD".equalsIgnoreCase(request.getMethod());
        if (bodyless || request.getContentLengthLong() == 0) {
            return HttpRequest.BodyPublishers.noBody();
        }
        Supplier<InputStream> supplier = () -> {
            try {
                return new MaxSizeInputStream(request.getInputStream(), maxRequestBytes);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        };
        return HttpRequest.BodyPublishers.ofInputStream(supplier);
    }

    // ────────────────────────────────────────────────────────────────────────

    private URI buildTargetUri(HttpServletRequest request, String baseUrl) {
        String path = request.getRequestURI();              // already starts with "/"
        String query = request.getQueryString();
        String url = baseUrl + path + (query != null ? "?" + query : "");
        return URI.create(url);
    }

    private void copyRequestHeaders(HttpServletRequest request, HttpRequest.Builder forward) {
        var names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            if (SKIP_REQUEST_HEADERS.contains(name.toLowerCase())) {
                continue;
            }
            var values = request.getHeaders(name);
            while (values.hasMoreElements()) {
                forward.header(name, values.nextElement());
            }
        }
    }

    private ResponseEntity<byte[]> relay(HttpResponse<byte[]> upstream) {
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(upstream.statusCode());
        for (Map.Entry<String, List<String>> header : upstream.headers().map().entrySet()) {
            String name = header.getKey();
            if (name == null || !RELAY_RESPONSE_HEADERS.contains(name.toLowerCase())) {
                continue;
            }
            for (String value : header.getValue()) {
                builder.header(name, value);
            }
        }
        byte[] payload = upstream.body();
        return builder.body(payload != null ? payload : new byte[0]);
    }

    private ResponseEntity<byte[]> payloadTooLarge() {
        String json = "{\"error\":\"Payload Too Large\",\"message\":\"Request body exceeds the "
                + maxRequestBytes + "-byte limit\"}";
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .contentType(MediaType.APPLICATION_JSON)
                .body(json.getBytes());
    }

    /** True if the throwable (or any cause) is our body-size limit breach. */
    private static boolean isPayloadTooLarge(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof PayloadTooLargeException) {
                return true;
            }
        }
        return false;
    }

    /** Marker for a forwarded request body that exceeded {@code maxRequestBytes}. */
    private static final class PayloadTooLargeException extends IOException {
        PayloadTooLargeException(long limit) {
            super("Request body exceeds the " + limit + "-byte limit");
        }
    }

    /**
     * Caps the number of bytes read from the wrapped stream, throwing
     * {@link PayloadTooLargeException} once the limit is exceeded. Bounds memory + abuse
     * for chunked/unknown-length uploads that have no Content-Length to pre-check (#21).
     */
    private static final class MaxSizeInputStream extends FilterInputStream {
        private final long limit;
        private long count;

        MaxSizeInputStream(InputStream in, long limit) {
            super(in);
            this.limit = limit;
        }

        @Override
        public int read() throws IOException {
            int b = super.read();
            if (b != -1 && ++count > limit) {
                throw new PayloadTooLargeException(limit);
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = super.read(b, off, len);
            if (n > 0) {
                count += n;
                if (count > limit) {
                    throw new PayloadTooLargeException(limit);
                }
            }
            return n;
        }
    }

    private String bearerToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        String token = header.substring(7).trim();
        return token.isEmpty() ? null : token;
    }

    private ResponseEntity<byte[]> unauthorized(String message) {
        String json = "{\"error\":\"Unauthorized\",\"message\":\"" + message + "\"}";
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .contentType(MediaType.APPLICATION_JSON)
                .body(json.getBytes());
    }

    private ResponseEntity<byte[]> forbidden(String message) {
        String json = "{\"error\":\"Forbidden\",\"message\":\"" + message + "\"}";
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_JSON)
                .body(json.getBytes());
    }

    private ResponseEntity<byte[]> badRequest(String message) {
        String json = "{\"error\":\"Bad Request\",\"message\":\"" + message + "\"}";
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body(json.getBytes());
    }

    /**
     * Decode percent-escapes and resolve path segments to a canonical absolute
     * path. Returns {@code null} if the path is malformed or contains any
     * traversal ({@code ..}) segment — including encoded forms like {@code %2e%2e}
     * — so the caller can reject it before the public/protected decision.
     */
    // Package-private (not private) so it can be unit-tested directly. Delegates to the shared
    // canonicalizer the SecurityFilterChain allowlist also uses, so the two can never drift (#29).
    static String canonicalPath(String rawUri) {
        return RequestPaths.canonicalPath(rawUri);
    }

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
