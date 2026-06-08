package com.luke.auth.identity;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Maps a verified WorkOS identity to the engine (CIBSeven) userId.
 *
 * <p>The engine userId IS the WorkOS subject ("sub", e.g. {@code user_2abc...}),
 * namespaced with a {@code workos:} prefix so consumer identities can never
 * collide with operator/service users created directly in CIBSeven (e.g.
 * {@code admin}, {@code camunda-admin} members).
 *
 * <p><b>Contract:</b> this MUST produce the exact same string used when the user
 * is provisioned in the engine (see {@code OnboardingClient}, which posts this id
 * verbatim to core-engine's {@code /api/admin/onboard-user}). The shared rule is:
 * {@code "workos:" + sub}. If they ever diverge, the engine's membership lookup
 * misses and the user is permanently "not provisioned".
 */
@Component
public class IdentityResolver {

    /** Prefix that namespaces WorkOS-sourced identities in the engine. */
    public static final String WORKOS_PREFIX = "workos:";

    /**
     * @param workosSub the verified {@code sub} claim from the WorkOS access token
     * @return the engine userId, e.g. {@code workos:user_2abcXYZ}
     */
    public String toEngineUserId(String workosSub) {
        if (!StringUtils.hasText(workosSub)) {
            throw new IllegalArgumentException("WorkOS subject (sub) is missing");
        }
        return WORKOS_PREFIX + workosSub;
    }
}
