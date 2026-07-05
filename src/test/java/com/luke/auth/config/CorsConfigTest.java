package com.luke.auth.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/**
 * The gateway terminates CORS. The authenticated surface stays on the strict first-party
 * allowlist with credentials; the public embed/sign surface must accept any origin without
 * credentials, or the embed's module-script bundle load (which sends an Origin header even
 * same-origin) 403s from gateway hosts outside the allowlist (e.g. authdev.lukeflow.com).
 */
class CorsConfigTest {

    private UrlBasedCorsConfigurationSource source() {
        CorsConfig cc = new CorsConfig();
        ReflectionTestUtils.setField(cc, "allowedOrigins", "https://app.example.com");
        CorsFilter filter = cc.corsFilter();
        return (UrlBasedCorsConfigurationSource) ReflectionTestUtils.getField(filter, "configSource");
    }

    @Test
    void catchAllStaysStrictAndCredentialed() {
        CorsConfiguration cfg = source().getCorsConfigurations().get("/**");
        assertNotNull(cfg);
        assertTrue(cfg.getAllowedOriginPatterns().contains("https://app.example.com"));
        assertFalse(cfg.getAllowedOriginPatterns().contains("*"), "authenticated surface must stay on the allowlist");
        assertTrue(Boolean.TRUE.equals(cfg.getAllowCredentials()));
    }

    @Test
    void publicSurfaceAllowsAnyOriginWithoutCredentials() {
        UrlBasedCorsConfigurationSource src = source();
        var patterns = src.getCorsConfigurations().keySet().stream().toList();

        for (String route : new String[] {"/api/public/**", "/embed-assets/**", "/embed/**"}) {
            CorsConfiguration cfg = src.getCorsConfigurations().get(route);
            assertNotNull(cfg, route + " must have its own CORS policy");
            assertTrue(cfg.getAllowedOriginPatterns().contains("*"), route + " must allow any origin");
            assertFalse(Boolean.TRUE.equals(cfg.getAllowCredentials()), route + " must NOT send credentials");
            assertFalse(cfg.getAllowedHeaders().contains("Authorization"), route + " must not accept auth headers");
            assertTrue(patterns.indexOf(route) < patterns.indexOf("/**"),
                    route + " must be registered before the catch-all");
        }
    }
}
