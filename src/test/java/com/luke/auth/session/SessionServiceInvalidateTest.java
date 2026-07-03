package com.luke.auth.session;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.luke.auth.config.GatewayKeys;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * #42: logout/delete must drop the cached session so a stale authorization view
 * isn't honored after the session ends. After invalidate(), the next session()
 * recomputes from the systems of record instead of serving the cache.
 */
class SessionServiceInvalidateTest {

    @Test
    void invalidateForcesRecomputeOnNextSession() throws Exception {
        GatewayKeys keys = mock(GatewayKeys.class);
        PermissionsClient pc = mock(PermissionsClient.class);
        when(keys.mintActAsToken(anyString())).thenReturn("act");
        Map<String, Object> core = new HashMap<>();
        core.put("tenants", List.of("A", "B"));
        core.put("operator", false);
        core.put("roles", Map.of());
        when(pc.corePermissions("act")).thenReturn(core);
        when(pc.capabilities(anyString(), anyString(), anyString())).thenReturn(Map.of());

        SessionService svc = new SessionService(keys, pc, 60, 10_000);

        svc.session("user-1", "A");
        svc.session("user-1", "A"); // served from cache → no second upstream call
        verify(pc, times(1)).corePermissions("act");

        svc.invalidate("user-1");

        svc.session("user-1", "A"); // cache dropped → recomputes
        verify(pc, times(2)).corePermissions("act");
    }
}
