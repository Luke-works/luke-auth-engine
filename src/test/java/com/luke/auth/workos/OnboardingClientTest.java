package com.luke.auth.workos;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * #61: the onboarding client forwards a WorkOS role slug when the caller supplies one, and falls
 * back to the configured {@code default-role} otherwise. core-engine's onboarding endpoint maps the
 * slug to the canonical engine role (see {@code RoleCatalog.fromWorkosSlug}); this pins the auth-side
 * forward contract — a supplied role is passed through verbatim, blank/absent uses the default.
 */
class OnboardingClientTest {

    private OnboardingClient client() {
        // coreBaseUrl, operatorUser, operatorPassword, defaultTenant, defaultRole, defaultAccessLevel
        return new OnboardingClient("http://core.local", "op", "pw", "t-default", "tenant-user", "READ_WRITE");
    }

    @Test
    void suppliedRoleIsForwardedVerbatim() {
        Map<String, Object> body = client().buildOnboardBody("workos:u1", "Jo", "Blow", "jo@acme.com", "process-operator");
        assertEquals("process-operator", body.get("role"));
        assertEquals("t-default", body.get("tenantId"));
        assertEquals("workos:u1", body.get("id"));
        assertEquals("READ_WRITE", body.get("accessLevel"));
    }

    @Test
    void workosBuiltInRoleIsForwardedForTheEngineToMap() {
        // auth-engine does not map slugs — it forwards; core-engine turns `admin` into `tenant-admin`.
        assertEquals("admin", client().buildOnboardBody("workos:u2", "A", "B", "a@acme.com", "admin").get("role"));
    }

    @Test
    void blankOrAbsentRoleFallsBackToDefault() {
        assertEquals("tenant-user", client().buildOnboardBody("workos:u3", "A", "B", "a@acme.com", null).get("role"));
        assertEquals("tenant-user", client().buildOnboardBody("workos:u4", "A", "B", "a@acme.com", "   ").get("role"));
    }
}
