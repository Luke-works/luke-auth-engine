package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.luke.auth.config.GatewayKeys;
import com.luke.auth.config.WorkosTokenVerifier;
import com.luke.auth.identity.IdentityResolver;
import com.luke.auth.session.SessionService;
import com.luke.auth.workos.OnboardingClient;
import com.luke.auth.workos.WorkosClient;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * #31: addMember must not leak platform-wide email existence — an unknown email is
 * invited and a known one is added, both returning the SAME uniform 200.
 */
class AuthControllerAddMemberTest {

    private final WorkosClient workos = mock(WorkosClient.class);
    private final WorkosTokenVerifier verifier = mock(WorkosTokenVerifier.class);
    private final IdentityResolver idr = mock(IdentityResolver.class);
    private final SessionService sessions = mock(SessionService.class);
    private final GatewayKeys keys = mock(GatewayKeys.class);
    private final CoreAdminClient coreAdmin = mock(CoreAdminClient.class);
    private AuthController controller;
    private HttpServletRequest req;

    @BeforeEach
    void setUp() throws Exception {
        controller = new AuthController(workos, verifier, idr, mock(OnboardingClient.class),
                sessions, keys, coreAdmin, "http://ui/cb", true, "Lax");
        Jwt jwt = mock(Jwt.class);
        when(jwt.getSubject()).thenReturn("workos|admin");
        when(verifier.verify("tok")).thenReturn(jwt);
        when(idr.toEngineUserId("workos|admin")).thenReturn("eng-admin");
        when(sessions.session("eng-admin", "tenantA")).thenReturn(Map.<String, Object>of("tenantAdmin", true));
        when(keys.mintActAsToken(anyString())).thenReturn("act");
        req = mock(HttpServletRequest.class);
        when(req.getHeader("Authorization")).thenReturn("Bearer tok");
        when(req.getHeader("X-Tenant-Id")).thenReturn("tenantA");
    }

    @Test
    void unknownEmailIsInvitedWithUniformResponse() {
        when(workos.findUserByEmail("new@x.com")).thenReturn(null);

        ResponseEntity<?> r = controller.addMember(
                new AuthController.AddMemberRequest("new@x.com", "tenant-user", "READ_WRITE"), req);

        assertEquals(200, r.getStatusCode().value());
        assertEquals(Map.of("ok", true), r.getBody());
        verify(workos).sendInvitation("new@x.com", "workos|admin");
        verify(coreAdmin, never()).createOrgUser(any(), any(), any());
    }

    @Test
    void existingUserIsAddedWithSameUniformResponse() {
        when(workos.findUserByEmail("known@x.com")).thenReturn(Map.<String, Object>of(
                "id", "wos-invitee", "email", "known@x.com", "first_name", "A", "last_name", "B"));
        when(idr.toEngineUserId("wos-invitee")).thenReturn("eng-invitee");
        when(coreAdmin.createOrgUser(any(), eq("tenantA"), any()))
                .thenReturn(new CoreAdminClient.CoreResponse(200, new byte[0]));

        ResponseEntity<?> r = controller.addMember(
                new AuthController.AddMemberRequest("known@x.com", null, "READ"), req);

        assertEquals(200, r.getStatusCode().value());
        assertEquals(Map.of("ok", true), r.getBody()); // identical to the invite path → no oracle
        verify(coreAdmin).createOrgUser(any(), eq("tenantA"), any());
        verify(workos, never()).sendInvitation(anyString(), anyString());
    }
}
