package com.luke.auth.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * #35: the prod CORS check must reject anything that opens the credentialed API to any site
 * or to the developer's own machine, WITHOUT flagging the bounded subdomain patterns the
 * fleet legitimately uses.
 */
class LukeCorsPropertiesTest {

    @Test
    void openAndLocalOriginsAreInsecure() {
        for (String origin : new String[] {
                "*",
                "https://*",
                "http://*",
                "https://*:8443",
                "http://localhost:5173",
                "https://localhost",
                "http://127.0.0.1:3000",
                "http://[::1]:8080",
        }) {
            assertTrue(LukeCorsProperties.isInsecure(origin), origin + " should be flagged insecure");
        }
    }

    @Test
    void boundedFirstPartyOriginsAreSecure() {
        for (String origin : new String[] {
                "https://app.lukeflow.com",
                "https://*.lukeflow.com",
                "https://consumer.lukeflow.com:8443",
                "https://*.tenant.lukeflow.com",
        }) {
            assertFalse(LukeCorsProperties.isInsecure(origin), origin + " should be allowed");
        }
    }

    @Test
    void hasInsecureOriginScansTheWholeList() {
        LukeCorsProperties c = new LukeCorsProperties();
        c.setAllowedOrigins("https://app.lukeflow.com, http://localhost:5173");
        assertTrue(c.hasInsecureOrigin(), "one bad origin in the list taints it");

        c.setAllowedOrigins("https://app.lukeflow.com, https://*.lukeflow.com");
        assertFalse(c.hasInsecureOrigin());
    }
}
