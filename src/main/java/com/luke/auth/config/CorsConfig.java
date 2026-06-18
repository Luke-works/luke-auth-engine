package com.luke.auth.config;

import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
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

    @Value("${luke.cors.allowed-origins:http://localhost:*}")
    private String allowedOrigins;

    @Bean
    public CorsFilter corsFilter() {
        List<String> origins = Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();

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

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}
