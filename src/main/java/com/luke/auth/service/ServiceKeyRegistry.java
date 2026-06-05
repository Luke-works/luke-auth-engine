package com.luke.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Maps service-account API keys to engine userIds — the non-Clerk ingress for
 * robots / service accounts (mostly "Process Users").
 *
 * <p>Keys live in config (no DB; auth-engine stays stateless), as a
 * comma-separated list of {@code key=userId} pairs, e.g.
 * {@code LUKE_AUTH_SERVICE_KEYS=s3cret1=svc:order-bot,s3cret2=svc:billing}.
 * The service userId must be provisioned in the engine (like a human) with the
 * right role; auth-engine only authenticates the key and asserts the identity.
 */
@Component
public class ServiceKeyRegistry {

    private static final Logger log = LoggerFactory.getLogger(ServiceKeyRegistry.class);

    private final Map<String, String> keyToUser = new LinkedHashMap<>();

    public ServiceKeyRegistry(@Value("${luke.auth.service.keys:}") String raw) {
        if (raw != null) {
            for (String pair : raw.split(",")) {
                String p = pair.trim();
                int eq = p.indexOf('=');
                if (eq > 0) {
                    keyToUser.put(p.substring(0, eq).trim(), p.substring(eq + 1).trim());
                }
            }
        }
        log.info("ServiceKeyRegistry: {} service key(s) configured", keyToUser.size());
    }

    public boolean isEnabled() {
        return !keyToUser.isEmpty();
    }

    /** Resolve a key to its service userId, or null. Constant-time per entry. */
    public String resolve(String key) {
        if (key == null || key.isBlank()) return null;
        byte[] given = key.getBytes(StandardCharsets.UTF_8);
        String match = null;
        for (Map.Entry<String, String> e : keyToUser.entrySet()) {
            if (MessageDigest.isEqual(e.getKey().getBytes(StandardCharsets.UTF_8), given)) {
                match = e.getValue();
            }
        }
        return match;
    }
}
