package com.luke.auth.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Prod fail-fast for the gateway's two load-bearing auth postures (mirrors the
 * {@link DevModeGuard} pattern). Both {@code luke.auth.workos.strict-validation}
 * and {@code luke.auth.gateway.require-stable-key} default to {@code false} so
 * local/issuer-less dev keeps working — but leaving them off in production means:
 *
 * <ul>
 *   <li>tokens are accepted on signature+expiry only (no issuer/audience binding), so
 *       a token minted for a different WorkOS client/audience under the same key infra
 *       would verify; and</li>
 *   <li>the act-as signing key regenerates on every restart (no stable
 *       {@code GATEWAY_PRIVATE_KEY}), rotating the engine's trust anchor and causing
 *       intermittent auth outages.</li>
 * </ul>
 *
 * <p>When the {@code prod} Spring profile is active (or {@code luke.auth.require-hardened=true}),
 * the app refuses to start unless BOTH are enabled. Dev/qa without the profile are
 * unaffected (the verifier/keys still log their own loud warnings there).
 */
@Component
public class AuthHardeningGuard {

    private static final Logger log = LoggerFactory.getLogger(AuthHardeningGuard.class);

    public AuthHardeningGuard(
            @Value("${luke.auth.workos.strict-validation:false}") boolean strictValidation,
            @Value("${luke.auth.gateway.require-stable-key:false}") boolean requireStableKey,
            @Value("${luke.auth.require-hardened:false}") boolean requireHardened,
            Environment env) {
        boolean prod = Arrays.asList(env.getActiveProfiles()).contains("prod");
        if (!(prod || requireHardened)) {
            return;
        }
        List<String> problems = new ArrayList<>();
        if (!strictValidation) {
            problems.add("luke.auth.workos.strict-validation must be true "
                    + "(WORKOS_STRICT_VALIDATION=true + WORKOS_ISSUER + WORKOS_AUDIENCE)");
        }
        if (!requireStableKey) {
            problems.add("luke.auth.gateway.require-stable-key must be true "
                    + "(GATEWAY_REQUIRE_STABLE_KEY=true + a managed GATEWAY_PRIVATE_KEY)");
        }
        if (!problems.isEmpty()) {
            throw new IllegalStateException(
                    "Refusing to start hardened (prod profile / require-hardened): " + problems
                    + ". Set these before deploying.");
        }
        log.info("Auth hardening verified: strict token validation + stable signing key are enforced.");
    }
}
