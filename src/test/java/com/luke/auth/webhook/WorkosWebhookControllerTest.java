package com.luke.auth.webhook;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.luke.auth.audit.AuditService;
import com.luke.auth.identity.IdentityResolver;
import com.luke.auth.session.SessionService;
import com.luke.auth.workos.OnboardingClient;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * #38 — the webhook endpoint must: stay closed (404) when unconfigured, reject bad signatures
 * (401 + audit), and on a verified deprovisioning event invalidate the user's session cache
 * and audit it. Membership removal is out of scope here (pending the deprovisioning decision).
 */
class WorkosWebhookControllerTest {

    private final WorkosWebhookVerifier verifier = mock(WorkosWebhookVerifier.class);
    private final SessionService sessions = mock(SessionService.class);
    private final AuditService audit = mock(AuditService.class);
    private final OnboardingClient onboarding = mock(OnboardingClient.class);
    private WorkosWebhookController controller;
    private HttpServletRequest req;

    @BeforeEach
    void setUp() {
        controller = new WorkosWebhookController(verifier, new IdentityResolver(), sessions, audit, onboarding);
        req = mock(HttpServletRequest.class);
    }

    private byte[] body(String json) {
        return json.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void disabledEndpointReturns404() {
        when(verifier.isEnabled()).thenReturn(false);
        var r = controller.receive(body("{}"), "sig", req);
        assertEquals(404, r.getStatusCode().value());
        verify(sessions, never()).invalidate(any());
    }

    @Test
    void badSignatureIsUnauthorizedAndAudited() {
        when(verifier.isEnabled()).thenReturn(true);
        when(verifier.verify(any(), any(), anyLong())).thenReturn(false);
        var r = controller.receive(body("{\"event\":\"user.deleted\"}"), "bad", req);
        assertEquals(401, r.getStatusCode().value());
        verify(audit).record(eq("webhook.workos"), eq(AuditService.DENIED), any(), any(), any(), any());
        verify(sessions, never()).invalidate(any());
    }

    @Test
    void userDeletedInvalidatesCacheDeprovisionsEngineAndAudits() {
        when(verifier.isEnabled()).thenReturn(true);
        when(verifier.verify(any(), any(), anyLong())).thenReturn(true);
        when(onboarding.deprovision("workos:user_abc123")).thenReturn(true);

        var r = controller.receive(
                body("{\"event\":\"user.deleted\",\"data\":{\"id\":\"user_abc123\"}}"), "good", req);

        assertEquals(200, r.getStatusCode().value());
        verify(sessions).invalidate("workos:user_abc123");
        verify(onboarding).deprovision("workos:user_abc123"); // engine membership removed
        verify(audit).record(eq("user.deprovision"), eq(AuditService.SUCCESS),
                any(), eq("workos:user_abc123"), any(), any());
    }

    @Test
    void engineDeprovisionFailureReturns500SoWorkOsRetries() {
        when(verifier.isEnabled()).thenReturn(true);
        when(verifier.verify(any(), any(), anyLong())).thenReturn(true);
        when(onboarding.deprovision("workos:user_abc123"))
                .thenThrow(new OnboardingClient.OnboardingException("core down"));

        var r = controller.receive(
                body("{\"event\":\"user.deleted\",\"data\":{\"id\":\"user_abc123\"}}"), "good", req);

        assertEquals(500, r.getStatusCode().value()); // WorkOS will retry; both steps are idempotent
        verify(sessions).invalidate("workos:user_abc123"); // cache still invalidated up front
        verify(audit).record(eq("user.deprovision"), eq(AuditService.FAILURE),
                any(), eq("workos:user_abc123"), any(), any());
    }

    @Test
    void dsyncEventIsAcknowledgedButNotActioned() {
        when(verifier.isEnabled()).thenReturn(true);
        when(verifier.verify(any(), any(), anyLong())).thenReturn(true);

        var r = controller.receive(
                body("{\"event\":\"dsync.user.deleted\",\"data\":{\"id\":\"directory_user_1\"}}"), "good", req);

        assertEquals(200, r.getStatusCode().value());
        // No cache invalidation — dsync→platform-user mapping is pending the #38 decision.
        verify(sessions, never()).invalidate(any());
        verify(audit).record(eq("webhook.workos.dsync"), eq("pending"), any(), any(), any(), any());
    }
}
