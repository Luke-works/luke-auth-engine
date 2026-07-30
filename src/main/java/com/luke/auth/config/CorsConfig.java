package com.luke.auth.config;

import java.util.List;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/**
 * CORS now terminates at the gateway — the consumer UI talks to this service,
 * not the engine directly. Mirrors {@code luke-core-engine}'s CORS policy.
 */
@Configuration
public class CorsConfig {

    private final LukeCorsProperties corsProperties;

    public CorsConfig(LukeCorsProperties corsProperties) {
        this.corsProperties = corsProperties;
    }

    @Bean
    public CorsFilter corsFilter() {
        List<String> origins = corsProperties.origins();

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(origins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        // Explicit allowlist rather than "*": with allowCredentials(true) a wildcard
        // header policy needlessly widens what a malicious origin could probe. Only
        // the headers the consumer UI actually sends are permitted. (Identity/trust
        // headers like X-User-Id are intentionally NOT allowed — the gateway asserts
        // identity via the act-as token, and the proxy strips them anyway.)
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept", "X-Tenant-Id"));
        // Response headers the browser JS is allowed to READ cross-origin. Without this, fetch()
        // can't see the correlation id (undercutting the #20/#37 traceability story) nor a download's
        // Content-Disposition filename / byte-range headers the proxy relays for DOCUMENTS + email assets.
        config.setExposedHeaders(List.of(
                "X-Correlation-Id", "Content-Disposition", "Retry-After", "Content-Range", "Accept-Ranges"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        // Public embed/sign surface proxied to core-engine (/api/public/**) plus the embed
        // page and its static bundle (/embed/**, /embed-assets/**). These are unauthenticated
        // (token/HMAC-gated, no cookies) and designed to load from arbitrary third-party sites,
        // so they must accept any origin — WITHOUT credentials. Mirrors core-engine's carve-out.
        // The gateway is the CORS terminator now, so without this the strict allowlist below
        // 403s the embed's own <script type="module"> bundle load (it sends an Origin header
        // even same-origin). Registered before "/**" so it wins the path match. CORS is not an
        // authz control here — the token/HMAC + rate limits are; opening it adds no exposure.
        CorsConfiguration publicConfig = new CorsConfiguration();
        publicConfig.setAllowedOriginPatterns(List.of("*"));
        publicConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        publicConfig.setAllowedHeaders(List.of("Content-Type", "Accept", "X-Tenant-Id"));
        // Same read-access for the public embed/asset surface (e.g. a recipient's mail client reading
        // Content-Disposition / byte-range headers on a served email image).
        publicConfig.setExposedHeaders(List.of(
                "X-Correlation-Id", "Content-Disposition", "Retry-After", "Content-Range", "Accept-Ranges"));
        publicConfig.setAllowCredentials(false);
        publicConfig.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/public/**", publicConfig);
        source.registerCorsConfiguration("/embed-assets/**", publicConfig);
        source.registerCorsConfiguration("/embed/**", publicConfig);
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    /**
     * Order the CORS filter AHEAD of everything that can reject a request — otherwise the
     * rejection is not CORS-readable and the browser reports a bogus CORS failure instead of
     * the real status.
     *
     * <p>Without this the filter is registered as a plain {@code Filter} bean, which Spring Boot
     * orders at {@code LOWEST_PRECEDENCE} — i.e. AFTER the {@code springSecurityFilterChain}
     * (order -100) and after {@link com.luke.auth.web.AuthRateLimitFilter}. Preflights still
     * worked (OPTIONS is on the public allowlist, so it reaches the filter), but every response
     * those layers produce themselves left without {@code Access-Control-Allow-Origin}:
     * <ul>
     *   <li>the 401 for an expired/invalid WorkOS access token, and</li>
     *   <li>the 429 from the credential-endpoint throttle.</li>
     * </ul>
     * The browser then blocks the response, so {@code fetch()} rejects with a network/CORS
     * TypeError rather than resolving with status 401 — which broke the consumer UI's
     * refresh-on-401 retry (it must READ the 401 to know to refresh). The user-visible symptom
     * was intermittent "CORS error" / "Failed to fetch" on ordinary authenticated calls once the
     * short-lived access token aged out — indistinguishable from the API being down.
     *
     * <p>Ordered just after {@link CorrelationIdFilter} (HIGHEST_PRECEDENCE) so rejected requests
     * still carry a correlation id in the logs, and before the rate-limit filter (+20) so its 429
     * is readable too.
     */
    @Bean
    FilterRegistrationBean<CorsFilter> corsFilterRegistration(CorsFilter corsFilter) {
        FilterRegistrationBean<CorsFilter> registration = new FilterRegistrationBean<>(corsFilter);
        registration.setOrder(CORS_FILTER_ORDER);
        return registration;
    }

    /** Before the security chain (-100) and the rate-limit filter; after the correlation-id filter. */
    static final int CORS_FILTER_ORDER = Ordered.HIGHEST_PRECEDENCE + 10;
}
