package com.luke.auth.session;

import com.luke.auth.config.GatewayKeys;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.Nullable;
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

    /** Bounded + TTL'd so it can't grow without limit (was an unbounded map). */
    private final BoundedTtlCache<Map<String, Object>> cache;

    /**
     * Single-flight guard (#34): one in-flight computation per (user, tenant) key.
     * Concurrent misses — and concurrent {@code fresh=true} bypasses — for the same key
     * join the one leader's future instead of each storming the upstreams.
     */
    private final ConcurrentHashMap<String, CompletableFuture<Map<String, Object>>> inFlight =
            new ConcurrentHashMap<>();

    /** Incremented once per actual upstream computation — i.e. per storm-unit avoided. */
    @Nullable
    private final Counter upstreamLoads;

    public SessionService(GatewayKeys gatewayKeys, PermissionsClient client,
                          @Value("${luke.auth.session.cache-ttl-seconds:60}") long cacheTtlSeconds,
                          @Value("${luke.auth.session.cache-max-entries:10000}") int cacheMaxEntries,
                          @Nullable MeterRegistry meterRegistry) {
        this.gatewayKeys = gatewayKeys;
        this.client = client;
        this.cache = new BoundedTtlCache<>(cacheMaxEntries, cacheTtlSeconds * 1000);
        this.upstreamLoads = meterRegistry == null ? null : Counter.builder("auth.session.upstream.loads")
                .description("Session views computed from the upstream systems of record (single-flight leaders)")
                .register(meterRegistry);
    }

    /**
     * Build the session view for {@code engineUserId} acting in {@code requestedTenant}
     * (nullable → resolve a default). Cached per (user, tenant) for the TTL.
     */
    public Map<String, Object> session(String engineUserId, String requestedTenant) throws Exception {
        return session(engineUserId, requestedTenant, false);
    }

    /**
     * As {@link #session(String, String)}, but {@code bypassCache} skips the cached
     * entry and recomputes from the systems of record (then refreshes the cache). The
     * UI uses it right after it changes access, so new roles/capabilities reflect
     * immediately instead of after the TTL.
     */
    public Map<String, Object> session(String engineUserId, String requestedTenant, boolean bypassCache) throws Exception {
        String cacheKey = engineUserId + "|" + (requestedTenant == null ? "" : requestedTenant);
        if (!bypassCache) {
            Map<String, Object> hit = cache.get(cacheKey);
            if (hit != null) {
                return hit;
            }
        }

        // Single-flight: the first arrival for this key becomes the leader and computes;
        // every concurrent miss/bypass for the same key joins the leader's future rather
        // than firing its own act-as-mint + corePermissions + capabilities storm (#34).
        CompletableFuture<Map<String, Object>> mine = new CompletableFuture<>();
        CompletableFuture<Map<String, Object>> leader = inFlight.putIfAbsent(cacheKey, mine);
        if (leader != null) {
            return await(leader); // a computation is already running for this key
        }
        try {
            Map<String, Object> result = load(engineUserId, requestedTenant, cacheKey);
            mine.complete(result);
            return result;
        } catch (Throwable t) {
            // Followers waiting on `mine` must see the SAME exception (so the error boundary
            // maps it identically for leader and followers).
            mine.completeExceptionally(t);
            throw t;
        } finally {
            inFlight.remove(cacheKey, mine);
        }
    }

    /** Wait for the leader's computation, re-throwing its original (unwrapped) exception. */
    private Map<String, Object> await(CompletableFuture<Map<String, Object>> leader) throws Exception {
        try {
            return leader.get();
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception ex) {
                throw ex; // e.g. UpstreamException / TenantForbiddenException — mapped by the error boundary
            }
            if (cause instanceof Error err) {
                throw err;
            }
            throw new IllegalStateException("Session computation failed", cause);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw e;
        }
    }

    /** Compute the session view from the systems of record. One call = one upstream storm-unit. */
    private Map<String, Object> load(String engineUserId, String requestedTenant, String cacheKey) throws Exception {
        if (upstreamLoads != null) {
            upstreamLoads.increment();
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
                cache.put(cacheKey, empty);
                return empty;
            }
            throw e;
        }

        @SuppressWarnings("unchecked")
        List<String> tenants = (List<String>) core.getOrDefault("tenants", List.of());
        @SuppressWarnings("unchecked")
        Map<String, String> tenantNames = (Map<String, String>) core.getOrDefault("tenantNames", Map.of());
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
        body.put("tenantNames", tenantNames);
        body.put("roles", roles);
        body.put("candidateGroups", core.getOrDefault("candidateGroups", List.of()));
        body.put("capabilities", capabilities);
        body.put("can", flatten(roles, capabilities));

        cache.put(cacheKey, body);
        return body;
    }

    /**
     * Drop all cached session entries for a user (every tenant). Called on logout /
     * account deletion so a stale cached authorization view is not honored after the
     * session ends. Cache keys are {@code engineUserId + "|" + tenant}.
     */
    public void invalidate(String engineUserId) {
        if (engineUserId != null && !engineUserId.isBlank()) {
            cache.invalidatePrefix(engineUserId + "|");
        }
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
        body.put("tenantNames", Map.of());
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

    /** The user asked to act in a tenant they don't belong to. */
    public static class TenantForbiddenException extends RuntimeException {
        public TenantForbiddenException(String tenant) {
            super("Not a member of tenant '" + tenant + "'");
        }
    }
}
