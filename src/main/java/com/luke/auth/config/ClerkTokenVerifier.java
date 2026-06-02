package com.luke.auth.config;

import jakarta.annotation.PostConstruct;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Verifies a Clerk session JWT — the consumer's "wristband".
 *
 * <p>Validates the signature against Clerk's published JWKS, plus issuer and
 * (optionally) audience and expiry. On success it returns the decoded token so
 * the caller can read the {@code sub} claim; on any failure it throws.
 *
 * <p>If {@code luke.auth.clerk.jwks-url} is not configured the verifier is
 * disabled and every verification fails closed — the gateway will not forward
 * unauthenticated traffic to the engine.
 */
@Component
public class ClerkTokenVerifier {

    private static final Logger log = LoggerFactory.getLogger(ClerkTokenVerifier.class);

    @Value("${luke.auth.clerk.jwks-url:}")
    private String jwksUrl;

    @Value("${luke.auth.clerk.issuer:}")
    private String issuer;

    @Value("${luke.auth.clerk.audience:}")
    private String audience;

    private NimbusJwtDecoder decoder;

    @PostConstruct
    void init() {
        if (!StringUtils.hasText(jwksUrl)) {
            log.error("ClerkTokenVerifier: CLERK_JWKS_URL is not set — consumer auth will FAIL CLOSED. "
                    + "Set luke.auth.clerk.jwks-url to your Clerk instance's JWKS endpoint.");
            return;
        }
        NimbusJwtDecoder d = NimbusJwtDecoder.withJwkSetUri(jwksUrl).build();

        // Default validators give us expiry; add issuer if configured.
        if (StringUtils.hasText(issuer)) {
            d.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        } else {
            log.warn("ClerkTokenVerifier: no CLERK_ISSUER set — issuer claim will not be checked.");
        }
        this.decoder = d;
        log.info("ClerkTokenVerifier: verifying Clerk JWTs via JWKS {}", jwksUrl);
    }

    /**
     * Verify the raw Clerk JWT. Returns the decoded token (read {@code getSubject()}
     * for the Clerk user id). Throws {@link JwtException} if invalid/expired or if
     * the verifier is not configured.
     */
    public Jwt verify(String rawToken) {
        if (decoder == null) {
            throw new JwtException("Clerk verifier not configured (CLERK_JWKS_URL missing)");
        }
        Jwt jwt = decoder.decode(rawToken);
        if (StringUtils.hasText(audience)) {
            List<String> aud = jwt.getAudience();
            if (aud == null || !aud.contains(audience)) {
                throw new JwtException("Clerk token audience mismatch");
            }
        }
        return jwt;
    }
}
