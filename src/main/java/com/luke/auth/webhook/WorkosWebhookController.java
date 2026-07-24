package com.luke.auth.webhook;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.luke.auth.audit.AuditService;
import com.luke.auth.identity.IdentityResolver;
import com.luke.auth.session.SessionService;
import com.luke.auth.workos.OnboardingClient;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Consumes signature-verified WorkOS webhooks for user-lifecycle / directory-sync events (#38).
 *
 * <p><b>On a verified deprovisioning event</b> ({@code user.deleted}) it: (1) invalidates the
 * gateway's cached authorization view for the user immediately, and (2) calls core-engine's
 * operator {@code /api/admin/deprovision-user} to remove their engine membership (#38). WorkOS
 * has already invalidated the deleted user's sessions/refresh tokens, so no separate token
 * revocation call is needed for this event. Disabled (404) until {@code WORKOS_WEBHOOK_SECRET}
 * is set, so dev/qa are unaffected.
 *
 * <p>If the engine deprovision fails (core unreachable), the handler returns 500 so WorkOS
 * retries — the cache invalidation and the engine deprovision are both idempotent, so a retry
 * is safe. Directory-sync ({@code dsync.*}) events still need the WorkOS Directory Sync
 * user→platform-user mapping; they are acknowledged and audited as {@code pending}.
 */
@RestController
public class WorkosWebhookController {

    private static final Logger log = LoggerFactory.getLogger(WorkosWebhookController.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** WorkOS User Management events that mean "this user should lose access." */
    private static final Set<String> DEPROVISION_EVENTS = Set.of("user.deleted");

    private final WorkosWebhookVerifier verifier;
    private final IdentityResolver identityResolver;
    private final SessionService sessionService;
    private final AuditService auditService;
    private final OnboardingClient onboardingClient;

    public WorkosWebhookController(WorkosWebhookVerifier verifier, IdentityResolver identityResolver,
                                   SessionService sessionService, AuditService auditService,
                                   OnboardingClient onboardingClient) {
        this.verifier = verifier;
        this.identityResolver = identityResolver;
        this.sessionService = sessionService;
        this.auditService = auditService;
        this.onboardingClient = onboardingClient;
    }

    @PostMapping("/webhooks/workos")
    public ResponseEntity<Void> receive(@RequestBody(required = false) byte[] body,
                                        @RequestHeader(value = "WorkOS-Signature", required = false) String signature,
                                        HttpServletRequest request) {
        if (!verifier.isEnabled()) {
            // No signing secret configured — the endpoint is closed (cannot be trusted).
            return ResponseEntity.notFound().build();
        }
        if (body == null || !verifier.verify(signature, body, Instant.now().getEpochSecond())) {
            auditService.record("webhook.workos", AuditService.DENIED, "-", null, null, request);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        JsonNode event;
        try {
            event = MAPPER.readTree(body);
        } catch (Exception e) {
            // Signature was valid but the body isn't JSON — ack so WorkOS won't retry, but flag it.
            log.warn("WorkOS webhook: verified signature but unparseable body");
            auditService.record("webhook.workos", AuditService.FAILURE, "-", null, null, request);
            return ResponseEntity.ok().build();
        }

        String type = text(event, "event");
        String workosUserId = text(event.path("data"), "id");

        if (DEPROVISION_EVENTS.contains(type) && workosUserId != null) {
            String engineUserId = identityResolver.toEngineUserId(workosUserId);
            // 1. Drop the cached authorization view NOW (immediate, local, idempotent).
            sessionService.invalidate(engineUserId);
            // 2. Remove the engine membership via the operator endpoint. WorkOS has already
            //    invalidated the deleted user's sessions/refresh tokens, so nothing else to revoke.
            try {
                onboardingClient.deprovision(engineUserId);
                auditService.record("user.deprovision", AuditService.SUCCESS, "workos:webhook", engineUserId, null, request);
                log.info("WorkOS webhook: deprovisioned '{}' (cache invalidated + engine membership removed).", engineUserId);
            } catch (RuntimeException e) {
                // Core unreachable — let WorkOS retry (both steps are idempotent). Audit the gap.
                auditService.record("user.deprovision", AuditService.FAILURE, "workos:webhook", engineUserId, null, request);
                log.error("WorkOS webhook: engine deprovision of '{}' failed — returning 500 so WorkOS retries.", engineUserId, e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
            }
        } else if (type != null && type.startsWith("dsync.")) {
            // Directory-sync events need the user→platform-user mapping decision before we can act.
            auditService.record("webhook.workos.dsync", "pending", "workos:webhook", workosUserId, null, request);
            log.info("WorkOS webhook: dsync event '{}' acknowledged (mapping/deprovisioning pending #38).", type);
        } else {
            log.debug("WorkOS webhook: event '{}' acknowledged, no action.", type);
        }
        return ResponseEntity.ok().build();
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node == null ? null : node.get(field);
        return (v == null || v.isNull()) ? null : v.asText();
    }
}
