package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.luke.auth.config.GatewayKeys;
import com.luke.auth.config.WorkosTokenVerifier;
import com.luke.auth.identity.IdentityResolver;
import com.luke.auth.session.SessionService;
import com.luke.auth.workos.OnboardingClient;
import com.luke.auth.workos.WorkosClient;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * #36: the SSO callback must NOT carry the access token in the redirect URL.
 * The session is established via the refresh cookie; the redirect is a clean URL.
 */
class AuthControllerCallbackTest {

    @Test
    void callbackDoesNotPutAccessTokenInRedirectUrl() {
        WorkosClient workos = mock(WorkosClient.class);
        when(workos.authenticateWithCode("c"))
                .thenReturn(Map.of("access_token", "tok-secret", "refresh_token", "rt"));

        AuthController controller = new AuthController(
                workos,
                mock(WorkosTokenVerifier.class),
                mock(IdentityResolver.class),
                mock(OnboardingClient.class),
                mock(SessionService.class),
                mock(GatewayKeys.class),
                mock(CoreAdminClient.class),
                new com.luke.auth.audit.AuditService(),
                "http://ui/cb", true, "Lax");

        MockHttpServletResponse response = new MockHttpServletResponse();
        // Matching state + state cookie passes the CSRF check.
        ResponseEntity<?> r = controller.callback("c", "s", null, "s", response);

        assertEquals(302, r.getStatusCode().value());
        String location = r.getHeaders().getLocation().toString();
        assertEquals("http://ui/cb", location);
        assertFalse(location.contains("access_token"), "access token must not be in the redirect URL");
        assertFalse(location.contains("tok-secret"));
        // The session is delivered via the refresh cookie instead.
        assertFalse(response.getHeaders("Set-Cookie").isEmpty());
    }
}
