package com.luke.auth.web;

import com.luke.auth.config.GatewayKeys;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Publishes the gateway's <em>public</em> signing key as a JWK Set.
 *
 * <p>{@code luke-core-engine} fetches this to verify the act-as-user tokens the
 * gateway mints. No secret is exposed — only the public half of the keypair.
 * This is the engine-facing trust anchor; it is intentionally unauthenticated,
 * exactly like Clerk's own JWKS endpoint.
 */
@RestController
public class JwksController {

    private final GatewayKeys gatewayKeys;

    public JwksController(GatewayKeys gatewayKeys) {
        this.gatewayKeys = gatewayKeys;
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return gatewayKeys.publicJwkSetJson();
    }
}
