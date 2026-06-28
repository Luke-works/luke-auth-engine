package com.luke.auth.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.luke.auth.config.GatewayKeys;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Membership decision the proxy now enforces (#40): a UI-supplied tenant must be
 * one the user belongs to; operators may use any.
 */
class SessionServiceMembershipTest {

    private SessionService service(boolean operator, List<String> tenants) throws Exception {
        GatewayKeys keys = mock(GatewayKeys.class);
        PermissionsClient pc = mock(PermissionsClient.class);
        when(keys.mintActAsToken(anyString())).thenReturn("act");
        Map<String, Object> core = new HashMap<>();
        core.put("tenants", tenants);
        core.put("tenantNames", Map.of("tenant-A", "Acme", "tenant-B", "Globex"));
        core.put("operator", operator);
        core.put("roles", Map.of());
        when(pc.corePermissions("act")).thenReturn(core);
        when(pc.capabilities(anyString(), anyString(), anyString())).thenReturn(Map.of());
        return new SessionService(keys, pc, 60, 10000);
    }

    @Test
    void memberTenantIsAccepted() throws Exception {
        Map<String, Object> s = service(false, List.of("tenant-A", "tenant-B")).session("user-1", "tenant-B");
        assertEquals("tenant-B", s.get("tenant"));
    }

    @Test
    void nonMemberTenantIsRejected() throws Exception {
        SessionService svc = service(false, List.of("tenant-A"));
        assertThrows(SessionService.TenantForbiddenException.class, () -> svc.session("user-1", "tenant-B"));
    }

    @Test
    void operatorMayUseAnyTenant() throws Exception {
        Map<String, Object> s = service(true, List.of()).session("op", "tenant-Z");
        assertEquals("tenant-Z", s.get("tenant"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void tenantNamesArePassedThroughForTheSwitcher() throws Exception {
        Map<String, Object> s = service(false, List.of("tenant-A", "tenant-B")).session("user-1", "tenant-A");
        Map<String, String> names = (Map<String, String>) s.get("tenantNames");
        assertEquals("Acme", names.get("tenant-A"));
        assertEquals("Globex", names.get("tenant-B"));
    }
}
