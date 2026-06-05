package com.luke.auth.service;

import com.luke.auth.config.GatewayKeys;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Service-account token endpoint — the robot equivalent of the Clerk login.
 *
 * <p>{@code POST /service/token} with header {@code X-Service-Key: <key>} →
 * {@code { token }}: a short-lived act-as token for the key's service userId.
 * The service then calls downstream (core/capability) with that Bearer, exactly
 * as a human's token works — so the whole authorization path is identical; only
 * the ingress differs.
 *
 * <p>A specific mapping, so it is served here, not forwarded by the {@code /**}
 * proxy.
 */
@RestController
public class ServiceTokenController {

    private final ServiceKeyRegistry registry;
    private final GatewayKeys gatewayKeys;
    private final long ttlSeconds;

    public ServiceTokenController(ServiceKeyRegistry registry, GatewayKeys gatewayKeys,
                                  @Value("${luke.auth.gateway.ttl-seconds:60}") long ttlSeconds) {
        this.registry = registry;
        this.gatewayKeys = gatewayKeys;
        this.ttlSeconds = ttlSeconds;
    }

    @PostMapping("/service/token")
    public ResponseEntity<?> token(@RequestHeader(value = "X-Service-Key", required = false) String key)
            throws Exception {
        String userId = registry.resolve(key);
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Unauthorized", "message", "Unknown or missing service key"));
        }
        return ResponseEntity.ok(Map.of(
                "token", gatewayKeys.mintActAsToken(userId),
                "tokenType", "Bearer",
                "expiresIn", ttlSeconds,
                "subject", userId));
    }
}
