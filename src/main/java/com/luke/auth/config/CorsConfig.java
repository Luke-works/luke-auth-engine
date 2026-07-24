package com.luke.auth.config;

import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
        publicConfig.setAllowCredentials(false);
        publicConfig.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/public/**", publicConfig);
        source.registerCorsConfiguration("/embed-assets/**", publicConfig);
        source.registerCorsConfiguration("/embed/**", publicConfig);
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}
