package com.luke.auth.security;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * The authenticated caller established by {@link WorkosAuthenticationFilter} and exposed to
 * controllers via the Spring Security context (#29).
 *
 * @param engineUserId  the resolved engine user id ({@code workos:<sub>}, or a literal dev id)
 * @param workosUserId  the WorkOS subject, or {@code null} for a dev-mode caller
 * @param jwt           the verified WorkOS token, or {@code null} for a dev-mode caller
 * @param devMode       true if this principal came from the dev-mode {@code X-Dev-User} fallback
 */
public record WorkosPrincipal(String engineUserId, @Nullable String workosUserId,
                              @Nullable Jwt jwt, boolean devMode) {

    @Override
    public String toString() {
        return engineUserId; // what shows up in logs / SecurityContext#getName
    }
}
