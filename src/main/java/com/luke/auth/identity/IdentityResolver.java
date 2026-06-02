package com.luke.auth.identity;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Maps a verified Clerk identity to the engine (CIBSeven) userId.
 *
 * <p>The engine userId IS the Clerk subject ("sub"), namespaced with a
 * {@code clerk:} prefix so consumer identities can never collide with
 * operator/service users created directly in CIBSeven (e.g. {@code admin},
 * {@code camunda-admin} members).
 *
 * <p><b>Contract:</b> this MUST produce the exact same string that
 * {@code OnboardingController#onboardClerkUser} stored as the user id at
 * onboarding time, or the engine's membership lookup misses and the user is
 * permanently "not provisioned". The shared rule is: {@code "clerk:" + sub}.
 */
@Component
public class IdentityResolver {

    /** Prefix that namespaces Clerk-sourced identities in the engine. */
    public static final String CLERK_PREFIX = "clerk:";

    /**
     * @param clerkSub the verified {@code sub} claim from the Clerk JWT
     * @return the engine userId, e.g. {@code clerk:user_2abcXYZ}
     */
    public String toEngineUserId(String clerkSub) {
        if (!StringUtils.hasText(clerkSub)) {
            throw new IllegalArgumentException("Clerk subject (sub) is missing");
        }
        return CLERK_PREFIX + clerkSub;
    }
}
