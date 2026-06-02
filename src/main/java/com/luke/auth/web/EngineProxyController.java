package com.luke.auth.web;

import com.luke.auth.config.ClerkTokenVerifier;
import com.luke.auth.config.GatewayKeys;
import com.luke.auth.identity.IdentityResolver;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 *   <li>verifies the caller's Clerk JWT (the wristband),</li>
 *   <li>resolves the Clerk {@code sub} to an engine userId,</li>
 *   <li>mints a short-lived act-as-user token (the secret badge), and</li>
 *   <li>forwards method + path + query + body + {@code X-Tenant-Id} unchanged,
 *       swapping only the {@code Authorization} header to the minted token.</li>
 * </ol>
 *
 * <p>It is deliberately resource-agnostic: a single wildcard mapping forwards
 * the entire engine API (current and future) opaquely. The powerful act-as-user
 * token never leaves this server — the browser only ever holds its Clerk token.
 */
@RestController
public class EngineProxyController {

    private static final Logger log = LoggerFactory.getLogger(EngineProxyController.class);

    /** Hop-by-hop / managed headers we must not copy verbatim between hops. */
    private static final Set<String> SKIP_REQUEST_HEADERS = Set.of(
            "host", "authorization", "content-length", "connection", "transfer-encoding", "expect");
    private static final Set<String> SKIP_RESPONSE_HEADERS = Set.of(
            "transfer-encoding", "content-length", "connection");

    private final ClerkTokenVerifier clerkVerifier;
    private final IdentityResolver identityResolver;
    private final GatewayKeys gatewayKeys;
    private final String coreEngineBaseUrl;
    private final HttpClient httpClient;

    public EngineProxyController(ClerkTokenVerifier clerkVerifier,
                                 IdentityResolver identityResolver,
                                 GatewayKeys gatewayKeys,
                                 @Value("${luke.auth.core-engine.base-url}") String coreEngineBaseUrl) {
        this.clerkVerifier = clerkVerifier;
        this.identityResolver = identityResolver;
        this.gatewayKeys = gatewayKeys;
        this.coreEngineBaseUrl = stripTrailingSlash(coreEngineBaseUrl);
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

        // ── 1. Authenticate: verify the Clerk wristband ───────────────────────
        String engineUserId;
        try {
            String clerkToken = bearerToken(request);
            if (clerkToken == null) {
                return unauthorized("Missing Bearer token");
            }
            Jwt clerk = clerkVerifier.verify(clerkToken);
            engineUserId = identityResolver.toEngineUserId(clerk.getSubject());
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Rejected request: {}", e.getMessage());
            return unauthorized("Invalid or expired token");
        }

        // ── 2. Mint the act-as-user badge ─────────────────────────────────────
        String actAsToken = gatewayKeys.mintActAsToken(engineUserId);

        // ── 3. Forward to the engine, swapping only Authorization ─────────────
        URI target = buildTargetUri(request);
        byte[] body = request.getInputStream().readAllBytes();

        HttpRequest.Builder forward = HttpRequest.newBuilder(target)
                .timeout(Duration.ofSeconds(60))
                .method(request.getMethod(),
                        body.length == 0
                                ? HttpRequest.BodyPublishers.noBody()
                                : HttpRequest.BodyPublishers.ofByteArray(body));

        copyRequestHeaders(request, forward);
        forward.header(HttpHeaders.AUTHORIZATION, "Bearer " + actAsToken);

        HttpResponse<byte[]> upstream;
        try {
            upstream = httpClient.send(forward.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (Exception e) {
            log.error("Upstream engine call failed for {} {}", request.getMethod(), target, e);
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"Bad Gateway\",\"message\":\"Engine unreachable\"}".getBytes());
        }

        // ── 4. Relay the engine's response back to the consumer ───────────────
        return relay(upstream);
    }

    // ────────────────────────────────────────────────────────────────────────

    private URI buildTargetUri(HttpServletRequest request) {
        String path = request.getRequestURI();              // already starts with "/"
        String query = request.getQueryString();
        String url = coreEngineBaseUrl + path + (query != null ? "?" + query : "");
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
            if (name == null || SKIP_RESPONSE_HEADERS.contains(name.toLowerCase())) {
                continue;
            }
            for (String value : header.getValue()) {
                builder.header(name, value);
            }
        }
        byte[] payload = upstream.body();
        return builder.body(payload != null ? payload : new byte[0]);
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

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
