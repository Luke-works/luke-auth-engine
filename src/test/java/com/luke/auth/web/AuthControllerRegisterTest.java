package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.luke.auth.audit.AuditService;
import com.luke.auth.config.GatewayKeys;
import com.luke.auth.config.WorkosTokenVerifier;
import com.luke.auth.identity.IdentityResolver;
import com.luke.auth.session.SessionService;
import com.luke.auth.workos.OnboardingClient;
import com.luke.auth.workos.WorkosClient;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Guards #30: if engine provisioning fails AFTER the WorkOS user is created,
 * register must roll the WorkOS user back so it isn't orphaned (which would block
 * re-registration because the email is taken).
 */
class AuthControllerRegisterTest {

    @Test
    void rollsBackWorkosUserWhenProvisioningFails() {
        WorkosClient workos = mock(WorkosClient.class);
        IdentityResolver identityResolver = mock(IdentityResolver.class);
        OnboardingClient onboarding = mock(OnboardingClient.class);

        when(workos.createUser(any(), any(), any(), any())).thenReturn(Map.<String, Object>of("id", "wos_123"));
        when(identityResolver.toEngineUserId("wos_123")).thenReturn("workos:wos_123");
        doThrow(new OnboardingClient.OnboardingException("engine down"))
                .when(onboarding).provision(any(), any(), any(), any());

        AuthController controller = new AuthController(
                workos,
                mock(WorkosTokenVerifier.class),
                identityResolver,
                onboarding,
                mock(SessionService.class),
                mock(GatewayKeys.class),
                mock(CoreAdminClient.class),
                new AuditService(),
                "http://ui/cb", true, "Lax");

        ResponseEntity<?> resp = controller.register(
                new AuthController.RegisterRequest("a@b.com", "pw", "A", "B"),
                new MockHttpServletRequest());

        assertEquals(502, resp.getStatusCode().value());
        verify(workos).deleteUser("wos_123"); // orphan rolled back so retry can succeed
    }
}
