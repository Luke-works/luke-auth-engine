package com.luke.auth.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * The single production-configuration gate (#35, extending the original #33/#27 posture check).
 *
 * <p>Every setting below defaults to the lenient value so local, dev and qa — which have no
 * WorkOS credentials, no managed signing key and a localhost UI — keep booting untouched. When
 * the {@code prod} Spring profile is active (or {@code luke.auth.require-hardened=true}), the
 * app refuses to start unless ALL of these hold:
 *
 * <ul>
 *   <li><b>WorkOS credentials present</b> — without them every login fails closed at runtime,
 *       i.e. a "successful" boot that serves nothing.</li>
 *   <li><b>Strict token validation on</b> — otherwise tokens are accepted on signature+expiry
 *       alone, so a token minted for a different WorkOS client under the same key infra would
 *       verify. Requires issuer + audience to actually be set.</li>
 *   <li><b>A stable signing key</b> — an ephemeral key rotates the engine's trust anchor on
 *       every restart, causing intermittent auth outages.</li>
 *   <li><b>No localhost/wildcard CORS</b> — the gateway is the fleet's CORS terminator, and it
 *       serves credentialed requests.</li>
 *   <li><b>Dev-mode off</b> — belt-and-braces beside {@link DevModeGuard}, which independently
 *       requires the {@code dev} profile for the backdoors.</li>
 * </ul>
 *
 * <p>Reads {@link LukeAuthProperties} / {@link LukeCorsProperties} rather than loose
 * {@code @Value} strings, so the invariants and the config they assert cannot drift apart.
 */
@Component
public class AuthHardeningGuard {

    private static final Logger log = LoggerFactory.getLogger(AuthHardeningGuard.class);

    public AuthHardeningGuard(LukeAuthProperties props, LukeCorsProperties cors, Environment env) {
        boolean prod = Arrays.asList(env.getActiveProfiles()).contains("prod");
        if (!(prod || props.isRequireHardened())) {
            return; // dev/qa posture — the individual components still log their own warnings
        }

        List<String> problems = new ArrayList<>();
        LukeAuthProperties.Workos workos = props.getWorkos();
        LukeAuthProperties.Gateway gateway = props.getGateway();

        if (isBlank(workos.getClientId())) {
            problems.add("luke.auth.workos.client-id must be set (WORKOS_CLIENT_ID)");
        }
        if (isBlank(workos.getApiKey())) {
            problems.add("luke.auth.workos.api-key must be set (WORKOS_API_KEY)");
        }
        if (!workos.isStrictValidation()) {
            problems.add("luke.auth.workos.strict-validation must be true "
                    + "(WORKOS_STRICT_VALIDATION=true + WORKOS_ISSUER + WORKOS_AUDIENCE)");
        } else {
            // Strict validation without these fails EVERY token closed at runtime.
            if (isBlank(workos.getIssuer())) {
                problems.add("luke.auth.workos.issuer must be set when strict-validation is on (WORKOS_ISSUER)");
            }
            if (isBlank(workos.getAudience())) {
                problems.add("luke.auth.workos.audience must be set when strict-validation is on (WORKOS_AUDIENCE)");
            }
        }
        if (!gateway.isRequireStableKey()) {
            problems.add("luke.auth.gateway.require-stable-key must be true "
                    + "(GATEWAY_REQUIRE_STABLE_KEY=true + a managed GATEWAY_PRIVATE_KEY)");
        }
        if (cors.hasInsecureOrigin()) {
            problems.add("luke.cors.allowed-origins must not contain localhost or a wildcard "
                    + "(ALLOWED_ORIGINS) — got " + cors.origins());
        }
        if (props.isDevMode()) {
            problems.add("luke.auth.dev-mode must be false (LUKE_AUTH_DEV_MODE) — it enables auth backdoors");
        }

        if (!problems.isEmpty()) {
            throw new IllegalStateException(
                    "Refusing to start hardened (prod profile / require-hardened): " + problems
                    + ". Set these before deploying.");
        }
        log.info("Production config verified: WorkOS credentials, strict token validation, "
                + "stable signing key, non-local CORS, dev-mode off.");
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
