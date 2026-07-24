package com.luke.auth.config;

import jakarta.validation.constraints.NotBlank;
import java.util.Arrays;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Typed binding for {@code luke.cors.*} (#35). Separate from {@link LukeAuthProperties}
 * because the key lives under {@code luke.cors}, not {@code luke.auth}.
 *
 * <p>The gateway is the fleet's CORS terminator, so this list is a real security control:
 * {@link AuthHardeningGuard} rejects a localhost or wildcard origin under the {@code prod}
 * profile.
 */
@ConfigurationProperties(prefix = "luke.cors")
@Validated
public class LukeCorsProperties {

    /** Comma-separated origin patterns for the credentialed surface. */
    @NotBlank
    private String allowedOrigins = "http://localhost:*";

    public String getAllowedOrigins() { return allowedOrigins; }

    public void setAllowedOrigins(String allowedOrigins) { this.allowedOrigins = allowedOrigins; }

    /** The configured origins, trimmed and de-blanked. */
    public List<String> origins() {
        return Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    /**
     * True when an origin would let any site — or any process on the developer's own
     * machine — call the credentialed API. Unacceptable in production.
     */
    public boolean hasInsecureOrigin() {
        return origins().stream().anyMatch(LukeCorsProperties::isInsecure);
    }

    static boolean isInsecure(String origin) {
        String o = origin.trim().toLowerCase();
        if (o.equals("*")) {
            return true;
        }
        if (o.contains("localhost") || o.contains("127.0.0.1") || o.contains("[::1]")) {
            return true;
        }
        // Only a host of exactly "*" (e.g. "https://*", "https://*:8443") is open to any site.
        // A BOUNDED pattern like "https://*.lukeflow.com" is legitimate and must stay allowed —
        // the fleet uses one for tenant subdomains and the public embed surface.
        return "*".equals(host(o));
    }

    /** The host portion of an origin pattern, without scheme, port or path. */
    private static String host(String origin) {
        int schemeEnd = origin.indexOf("://");
        String rest = schemeEnd < 0 ? origin : origin.substring(schemeEnd + 3);
        int slash = rest.indexOf('/');
        if (slash >= 0) {
            rest = rest.substring(0, slash);
        }
        int colon = rest.lastIndexOf(':');
        return colon >= 0 ? rest.substring(0, colon) : rest;
    }
}
