package com.luke.auth.service;

import com.luke.auth.audit.AuditService;
import com.luke.auth.config.GatewayKeys;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Service-account token endpoint — the robot equivalent of the WorkOS login.
 *
 * <p>{@code POST /service/token} with header {@code X-Service-Key: <key>} →
 * {@code { token }}: a short-lived act-as token for the key's service userId.
 * The service then calls downstream (core/capability) with that Bearer, exactly
 * as a human's token works — so the whole authorization path is identical; only
 * the ingress differs.
 *
 * <p>A specific mapping, so it is served here, not forwarded by the {@code /**}
 * proxy.
 *
 * <p>#39: live revocation is exposed here via an operator-only endpoint
 * {@code POST /service/keys/{keyId}/revoke} (and {@code /unrevoke}), gated by a
 * constant-time-compared operator token. Revoking a keyId takes effect on the very
 * next {@code /service/token} with NO restart.
 */
@RestController
public class ServiceTokenController {

    private final ServiceKeyRegistry registry;
    private final GatewayKeys gatewayKeys;
    private final AuditService auditService;
    private final long ttlSeconds;
    private final byte[] operatorToken; // constant-time compared; empty ⇒ endpoint disabled

    public ServiceTokenController(ServiceKeyRegistry registry, GatewayKeys gatewayKeys,
                                  AuditService auditService,
                                  @Value("${luke.auth.gateway.ttl-seconds:60}") long ttlSeconds,
                                  @Value("${luke.auth.service.operator-token:}") String operatorToken) {
        this.registry = registry;
        this.gatewayKeys = gatewayKeys;
        this.auditService = auditService;
        this.ttlSeconds = ttlSeconds;
        this.operatorToken = (operatorToken == null ? "" : operatorToken.trim())
                .getBytes(StandardCharsets.UTF_8);
    }

    @PostMapping("/service/token")
    public ResponseEntity<?> token(@RequestHeader(value = "X-Service-Key", required = false) String key,
                                   HttpServletRequest request) throws Exception {
        ServiceKeyRegistry.Resolved resolved = registry.resolve(key);
        if (resolved == null) {
            // An unknown / missing / EXPIRED / REVOKED service key is a security-relevant denial.
            // A failed attempt has no trustworthy keyId (it didn't match a configured key), so we
            // record the DENIED event with keyId="-"; scope/tenant are likewise unknown pre-match.
            auditService.record("service.token", AuditService.DENIED, "-", request);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Unauthorized",
                            "message", "Unknown, missing, expired, or revoked service key"));
        }
        String userId = resolved.userId();
        // Service-token issuance IS an act-as mint for the service identity — audit it,
        // recording the non-secret keyId + scope so a leaked/abused key is identifiable, and
        // meter it (last-used + issuance count are tracked in the registry) (#39).
        ServiceKeyRegistry.Usage usage = registry.usage(resolved.keyId());
        auditService.record("service.token", AuditService.SUCCESS, userId,
                resolved.keyId(), resolved.scope(), request);
        return ResponseEntity.ok(Map.of(
                "token", gatewayKeys.mintActAsToken(userId),
                "tokenType", "Bearer",
                "expiresIn", ttlSeconds,
                "subject", userId,
                "scope", resolved.scope() == null ? "" : resolved.scope(),
                "issuanceCount", usage.issuanceCount()));
    }

    /**
     * Operator-only LIVE revocation of a service key by its (non-secret) keyId — takes effect
     * on the next {@code /service/token} with no restart. Gated by {@code X-Operator-Token}
     * (constant-time compared) against {@code luke.auth.service.operator-token}; if that config
     * is unset the endpoint is disabled (404-equivalent 403) so it can't be driven by default.
     */
    @PostMapping("/service/keys/{keyId}/revoke")
    public ResponseEntity<?> revoke(@PathVariable String keyId,
                                    @RequestHeader(value = "X-Operator-Token", required = false) String token,
                                    HttpServletRequest request) {
        if (!operatorAuthorized(token)) {
            auditService.record("service.key.revoke", AuditService.DENIED, "-", keyId, null, request);
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Forbidden", "message", "Operator token required"));
        }
        boolean known = registry.revoke(keyId);
        auditService.record("service.key.revoke", AuditService.SUCCESS, "operator", keyId, null, request);
        return ResponseEntity.ok(Map.of("keyId", keyId, "revoked", true, "known", known));
    }

    /** Operator-only undo of a live revocation. */
    @PostMapping("/service/keys/{keyId}/unrevoke")
    public ResponseEntity<?> unrevoke(@PathVariable String keyId,
                                      @RequestHeader(value = "X-Operator-Token", required = false) String token,
                                      HttpServletRequest request) {
        if (!operatorAuthorized(token)) {
            auditService.record("service.key.unrevoke", AuditService.DENIED, "-", keyId, null, request);
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Forbidden", "message", "Operator token required"));
        }
        boolean wasRevoked = registry.unrevoke(keyId);
        auditService.record("service.key.unrevoke", AuditService.SUCCESS, "operator", keyId, null, request);
        return ResponseEntity.ok(Map.of("keyId", keyId, "revoked", false, "wasRevoked", wasRevoked));
    }

    /** Constant-time operator-token check. Disabled (always false) when no token is configured. */
    private boolean operatorAuthorized(String presented) {
        if (operatorToken.length == 0) return false; // endpoint disabled unless configured
        if (!StringUtils.hasText(presented)) return false;
        return MessageDigest.isEqual(operatorToken, presented.trim().getBytes(StandardCharsets.UTF_8));
    }
}
