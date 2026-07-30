package com.luke.auth.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.core.Ordered;
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
        LukeCorsProperties props = new LukeCorsProperties();
        props.setAllowedOrigins("https://app.example.com");
        CorsFilter filter = new CorsConfig(props).corsFilter();
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
    void exposesTraceabilityAndDownloadHeadersToBrowserJs() {
        // Both surfaces must let cross-origin fetch() READ these — else the UI can't surface the
        // correlation id in an error report, nor read a download's filename / byte-range headers.
        for (String route : new String[] {"/**", "/api/public/**"}) {
            CorsConfiguration cfg = source().getCorsConfigurations().get(route);
            assertNotNull(cfg);
            assertNotNull(cfg.getExposedHeaders(), route + " must expose response headers");
            assertTrue(cfg.getExposedHeaders().contains("X-Correlation-Id"), route + " must expose the correlation id");
            assertTrue(cfg.getExposedHeaders().contains("Content-Disposition"), route + " must expose the filename");
        }
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

    @Test
    void corsFilterRunsBeforeTheSecurityChainAndTheRateLimiter() {
        // A plain Filter bean is ordered LOWEST_PRECEDENCE — i.e. after the security chain — so
        // its 401 would leave without CORS headers and the browser would report a CORS error
        // instead of a readable 401. Keep it ahead of every layer that can reject a request.
        LukeCorsProperties props = new LukeCorsProperties();
        CorsConfig config = new CorsConfig(props);
        int order = config.corsFilterRegistration(config.corsFilter()).getOrder();

        assertTrue(order < SecurityProperties.DEFAULT_FILTER_ORDER,
                "CORS must run before springSecurityFilterChain (" + SecurityProperties.DEFAULT_FILTER_ORDER + ")");
        assertTrue(order < Ordered.HIGHEST_PRECEDENCE + 20,
                "CORS must run before AuthRateLimitFilter so its 429 is CORS-readable");
        assertTrue(order > Ordered.HIGHEST_PRECEDENCE,
                "CORS must run after CorrelationIdFilter so rejections keep a correlation id");
    }
}
