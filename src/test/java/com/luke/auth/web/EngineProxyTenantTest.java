package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.luke.auth.config.GatewayKeys;
import com.luke.auth.config.WorkosTokenVerifier;
import com.luke.auth.identity.IdentityResolver;
import com.luke.auth.session.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
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

        EngineProxyController proxy = new EngineProxyController(
                verifier, idr, keys, sessions, new ObjectMapper(),
                "http://core", null, false, 104857600L, 10L, 60L);

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

    /**
     * A hostile X-Tenant-Id must never break the error body. The old hand-built JSON spliced the
     * raw header into a string literal, so a value containing a quote produced malformed JSON that
     * the UI could not parse; the RFC 7807 body is now serialized via Jackson, which escapes it.
     */
    @Test
    void maliciousTenantHeader_stillYieldsParseableJsonError() throws Exception {
        WorkosTokenVerifier verifier = mock(WorkosTokenVerifier.class);
        IdentityResolver idr = mock(IdentityResolver.class);
        GatewayKeys keys = mock(GatewayKeys.class);
        SessionService sessions = mock(SessionService.class);

        Jwt jwt = mock(Jwt.class);
        when(jwt.getSubject()).thenReturn("workos|abc");
        when(verifier.verify("tok")).thenReturn(jwt);
        when(idr.toEngineUserId("workos|abc")).thenReturn("user-1");
        String hostile = "a\"}<script>";
        // The user is a member of some OTHER tenant, so the requested (hostile) one is rejected —
        // routing through forbidden(...) which interpolates the hostile value into the error detail.
        when(sessions.session("user-1", hostile)).thenReturn(Map.of("tenant", "other"));

        ObjectMapper mapper = new ObjectMapper();
        EngineProxyController proxy = new EngineProxyController(
                verifier, idr, keys, sessions, mapper,
                "http://core", null, false, 104857600L, 10L, 60L);

        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("GET");
        when(req.getRequestURI()).thenReturn("/api/tasks");
        when(req.getHeader("Authorization")).thenReturn("Bearer tok");
        when(req.getHeader("X-Tenant-Id")).thenReturn(hostile);

        ResponseEntity<byte[]> resp = proxy.proxy(req);

        assertEquals(403, resp.getStatusCode().value());
        // The body must be well-formed JSON despite the quote/brace/markup in the tenant value.
        assertDoesNotThrow(() -> mapper.readTree(resp.getBody()));
    }
}
