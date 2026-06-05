package com.luke.auth.session;

import com.luke.auth.config.ClerkTokenVerifier;
import com.luke.auth.identity.IdentityResolver;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code GET /session} — the per-login (and per-tenant-switch) endpoint the UI
 * calls to learn who the user is and what they can do. Verifies the Clerk
 * wristband, then hands off to {@link SessionService} to derive + combine.
 *
 * <p>A specific mapping, so it is served here rather than forwarded by the
 * gateway's {@code /**} proxy.
 *
 * <p>The active tenant comes from the {@code X-Tenant-Id} header (the UI's org
 * switcher); {@link SessionService} validates it against the user's memberships.
 */
@RestController
public class SessionController {

    private final ClerkTokenVerifier clerkVerifier;
    private final IdentityResolver identityResolver;
    private final SessionService sessionService;
    private final boolean devMode;

    public SessionController(ClerkTokenVerifier clerkVerifier,
                             IdentityResolver identityResolver,
                             SessionService sessionService,
                             @Value("${luke.auth.dev-mode:false}") boolean devMode) {
        this.clerkVerifier = clerkVerifier;
        this.identityResolver = identityResolver;
        this.sessionService = sessionService;
        this.devMode = devMode;
    }

    @GetMapping("/session")
    public ResponseEntity<?> session(HttpServletRequest request) {
        String engineUserId;
        try {
            engineUserId = authenticate(request);
        } catch (JwtException | IllegalArgumentException e) {
            return error(HttpStatus.UNAUTHORIZED, "Unauthorized", "Invalid or expired token");
        }
        if (engineUserId == null) {
            return error(HttpStatus.UNAUTHORIZED, "Unauthorized", "Missing Bearer token");
        }

        String tenant = request.getHeader("X-Tenant-Id");
        try {
            return ResponseEntity.ok(sessionService.session(engineUserId, tenant));
        } catch (SessionService.TenantForbiddenException e) {
            return error(HttpStatus.FORBIDDEN, "Forbidden", e.getMessage());
        } catch (PermissionsClient.UpstreamException e) {
            return error(HttpStatus.BAD_GATEWAY, "Bad Gateway", e.getMessage());
        } catch (Exception e) {
            return error(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Error", e.getMessage());
        }
    }

    /** Clerk Bearer → engine userId; or, in dev mode only, an X-Dev-User header. */
    private String authenticate(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String token = header.substring(7).trim();
            Jwt clerk = clerkVerifier.verify(token);
            return identityResolver.toEngineUserId(clerk.getSubject());
        }
        if (devMode) {
            String devUser = request.getHeader("X-Dev-User");
            if (devUser != null && !devUser.isBlank()) {
                return devUser.trim(); // literal engine userId, local testing only
            }
        }
        return null;
    }

    private ResponseEntity<Map<String, String>> error(HttpStatus status, String title, String message) {
        return ResponseEntity.status(status).body(Map.of("error", title, "message", message));
    }
}
