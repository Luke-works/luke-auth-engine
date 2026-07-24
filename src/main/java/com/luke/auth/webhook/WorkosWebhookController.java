package com.luke.auth.webhook;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.luke.auth.audit.AuditService;
import com.luke.auth.identity.IdentityResolver;
import com.luke.auth.session.SessionService;
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
 * <p><b>What this does today (the safe, self-contained slice):</b> on a verified
 * deprovisioning event it immediately invalidates the gateway's cached authorization view for
 * that user and audits the event — so a removed user's cached session stops being honored at
 * once, instead of lingering for the cache TTL. Disabled (404) until {@code WORKOS_WEBHOOK_SECRET}
 * is set, so dev/qa are unaffected.
 *
 * <p><b>What still needs an architecture decision (see the issue):</b> removing the user's
 * <em>engine membership</em> and revoking their <em>WorkOS session / refresh token</em>. The
 * stateless gateway holds no operator credential to deprovision an arbitrary user in
 * core-engine, and directory-sync (dsync.*) user→platform-user mapping depends on the WorkOS
 * Directory Sync setup. Those events are acknowledged and audited as {@code pending} rather
 * than silently dropped.
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

    public WorkosWebhookController(WorkosWebhookVerifier verifier, IdentityResolver identityResolver,
                                   SessionService sessionService, AuditService auditService) {
        this.verifier = verifier;
        this.identityResolver = identityResolver;
        this.sessionService = sessionService;
        this.auditService = auditService;
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
            // Fully within the gateway's power: drop the cached authorization view NOW.
            sessionService.invalidate(engineUserId);
            auditService.record("user.deprovision", AuditService.SUCCESS, "workos:webhook", engineUserId, null, request);
            log.info("WorkOS webhook: deprovision '{}' — invalidated session cache. Engine membership "
                    + "removal + token revocation are pending the deprovisioning-path decision (#38).", engineUserId);
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
