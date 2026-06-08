package com.luke.auth.session;

import com.luke.auth.config.GatewayKeys;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * The translator. Given a verified user (and the org they're acting in), it asks
 * both systems of record what they can do, combines the answers into one view
 * for the UI, and caches it briefly. It holds no rules of its own.
 */
@Service
public class SessionService {

    /** Engine role dimension → short prefix used in the flattened {@code can[]} list. */
    private static final Map<String, String> ROLE_PREFIX = Map.of(
            "tenantUser", "org", "processUser", "process", "taskUser", "task");

    private final GatewayKeys gatewayKeys;
    private final PermissionsClient client;
    private final long cacheTtlMillis;

    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    public SessionService(GatewayKeys gatewayKeys, PermissionsClient client,
                          @Value("${luke.auth.session.cache-ttl-seconds:60}") long cacheTtlSeconds) {
        this.gatewayKeys = gatewayKeys;
        this.client = client;
        this.cacheTtlMillis = cacheTtlSeconds * 1000;
    }

    /**
     * Build the session view for {@code engineUserId} acting in {@code requestedTenant}
     * (nullable → resolve a default). Cached per (user, tenant) for the TTL.
     */
    public Map<String, Object> session(String engineUserId, String requestedTenant) throws Exception {
        String cacheKey = engineUserId + "|" + (requestedTenant == null ? "" : requestedTenant);
        Cached hit = cache.get(cacheKey);
        long now = System.currentTimeMillis();
        if (hit != null && hit.expiresAt > now) {
            return hit.body;
        }

        // 1. Camunda view — called as the user via a minted act-as token.
        String actAs = gatewayKeys.mintActAsToken(engineUserId);
        Map<String, Object> core;
        try {
            core = client.corePermissions(actAs);
        } catch (PermissionsClient.UpstreamException e) {
            // A brand-new (authenticated but not-yet-onboarded) user gets a 403 from
            // core-engine. That is not an error for login — return a minimal session so
            // the user can sign in and then create their organization (self-service).
            if (e.status() == 403) {
                Map<String, Object> empty = unprovisioned(engineUserId);
                cache.put(cacheKey, new Cached(empty, now + cacheTtlMillis));
                return empty;
            }
            throw e;
        }

        @SuppressWarnings("unchecked")
        List<String> tenants = (List<String>) core.getOrDefault("tenants", List.of());
        boolean operator = Boolean.TRUE.equals(core.get("operator"));

        // 2. Resolve + validate the active tenant (UI picks; we verify membership).
        String tenant = resolveTenant(requestedTenant, tenants, operator);

        // 3. Capability view — only meaningful within a tenant. Same act-as token.
        Map<String, String> capabilities = tenant == null ? Map.of() : client.capabilities(tenant, engineUserId, actAs);

        // 4. Merge.
        @SuppressWarnings("unchecked")
        Map<String, String> roles = (Map<String, String>) core.getOrDefault("roles", Map.of());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("userId", engineUserId);
        body.put("provisioned", true);
        body.put("operator", operator);
        body.put("tenantAdmin", Boolean.TRUE.equals(core.get("tenantAdmin")));
        body.put("tenant", tenant);
        body.put("tenants", tenants);
        body.put("roles", roles);
        body.put("candidateGroups", core.getOrDefault("candidateGroups", List.of()));
        body.put("capabilities", capabilities);
        body.put("can", flatten(roles, capabilities));

        cache.put(cacheKey, new Cached(body, now + cacheTtlMillis));
        return body;
    }

    /**
     * Minimal session for an authenticated-but-not-yet-onboarded user: identity only,
     * no tenants/roles/capabilities. {@code provisioned:false} tells the UI to route the
     * user into "create your organization" rather than the app.
     */
    private Map<String, Object> unprovisioned(String engineUserId) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("userId", engineUserId);
        body.put("provisioned", false);
        body.put("operator", false);
        body.put("tenantAdmin", false);
        body.put("tenant", null);
        body.put("tenants", List.of());
        body.put("roles", Map.of());
        body.put("candidateGroups", List.of());
        body.put("capabilities", Map.of());
        body.put("can", List.of());
        return body;
    }

    /** UI-supplied tenant must be one the user belongs to (operators may use any). */
    private String resolveTenant(String requested, List<String> tenants, boolean operator) {
        if (requested != null && !requested.isBlank()) {
            if (operator || tenants.contains(requested)) return requested;
            throw new TenantForbiddenException(requested);
        }
        return tenants.isEmpty() ? null : tenants.get(0);
    }

    /** Flatten roles + capabilities into a simple action list the UI can check directly. */
    private List<String> flatten(Map<String, String> roles, Map<String, String> capabilities) {
        List<String> can = new ArrayList<>();
        roles.forEach((dim, level) -> {
            String prefix = ROLE_PREFIX.get(dim);
            if (prefix == null || "none".equals(level)) return;
            can.add(prefix + ":read");
            if ("read-write".equals(level)) can.add(prefix + ":write");
        });
        capabilities.forEach((code, level) -> {
            String c = code.toLowerCase();
            can.add(c + ":read");
            if ("read-write".equals(level)) can.add(c + ":write");
        });
        return can;
    }

    private record Cached(Map<String, Object> body, long expiresAt) {}

    /** The user asked to act in a tenant they don't belong to. */
    public static class TenantForbiddenException extends RuntimeException {
        public TenantForbiddenException(String tenant) {
            super("Not a member of tenant '" + tenant + "'");
        }
    }
}
