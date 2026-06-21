package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.luke.auth.config.GatewayKeys;
import com.luke.auth.config.WorkosTokenVerifier;
import com.luke.auth.identity.IdentityResolver;
import com.luke.auth.session.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * #40: the proxy must reject a request whose X-Tenant-Id the authenticated user
 * does not belong to — at the gateway, before minting an act-as token or forwarding.
 */
class EngineProxyTenantTest {

    @Test
    void rejectsTenantTheUserDoesNotBelongTo() throws Exception {
        WorkosTokenVerifier verifier = mock(WorkosTokenVerifier.class);
        IdentityResolver idr = mock(IdentityResolver.class);
        GatewayKeys keys = mock(GatewayKeys.class);
        SessionService sessions = mock(SessionService.class);

        Jwt jwt = mock(Jwt.class);
        when(jwt.getSubject()).thenReturn("workos|abc");
        when(verifier.verify("tok")).thenReturn(jwt);
        when(idr.toEngineUserId("workos|abc")).thenReturn("user-1");
        when(sessions.session("user-1", "tenant-B"))
                .thenThrow(new SessionService.TenantForbiddenException("tenant-B"));

        EngineProxyController proxy =
                new EngineProxyController(verifier, idr, keys, sessions, "http://core", false, 104857600L);

        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("GET");
        when(req.getRequestURI()).thenReturn("/api/tasks");
        when(req.getHeader("Authorization")).thenReturn("Bearer tok");
        when(req.getHeader("X-Tenant-Id")).thenReturn("tenant-B");

        ResponseEntity<byte[]> resp = proxy.proxy(req);

        assertEquals(403, resp.getStatusCode().value());
        // Rejected before any act-as token is minted or the request is forwarded.
        verify(keys, never()).mintActAsToken(anyString());
    }
}
