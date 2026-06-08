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
 * Verifies a WorkOS access token — the consumer's "wristband".
 *
 * <p>WorkOS mints a standard JWT access token on login (whether the user
 * authenticated with a password, a social provider, or enterprise SSO). This
 * verifier validates the signature against WorkOS's published JWKS, plus issuer
 * and (optionally) audience and expiry. On success it returns the decoded token
 * so the caller can read the {@code sub} (WorkOS user id) and {@code sid}
 * (session id) claims; on any failure it throws.
 *
 * <p>The JWKS endpoint defaults to
 * {@code https://api.workos.com/sso/jwks/<client-id>} when only the client id is
 * configured. If neither {@code luke.auth.workos.jwks-url} nor
 * {@code luke.auth.workos.client-id} is set the verifier is disabled and every
 * verification fails closed — the gateway will not forward unauthenticated
 * traffic to the engine.
 */
@Component
public class WorkosTokenVerifier {

    private static final Logger log = LoggerFactory.getLogger(WorkosTokenVerifier.class);

    @Value("${luke.auth.workos.jwks-url:}")
    private String jwksUrl;

    @Value("${luke.auth.workos.client-id:}")
    private String clientId;

    @Value("${luke.auth.workos.api-base-url:https://api.workos.com}")
    private String apiBaseUrl;

    @Value("${luke.auth.workos.issuer:}")
    private String issuer;

    @Value("${luke.auth.workos.audience:}")
    private String audience;

    private NimbusJwtDecoder decoder;

    @PostConstruct
    void init() {
        String url = StringUtils.hasText(jwksUrl)
                ? jwksUrl
                : (StringUtils.hasText(clientId) ? strip(apiBaseUrl) + "/sso/jwks/" + clientId : null);

        if (url == null) {
            log.error("WorkosTokenVerifier: neither WORKOS_JWKS_URL nor WORKOS_CLIENT_ID is set — consumer auth "
                    + "will FAIL CLOSED. Set luke.auth.workos.client-id (preferred) or luke.auth.workos.jwks-url.");
            return;
        }

        NimbusJwtDecoder d = NimbusJwtDecoder.withJwkSetUri(url).build();

        // Default validators give us expiry; add issuer if configured.
        if (StringUtils.hasText(issuer)) {
            d.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        } else {
            log.warn("WorkosTokenVerifier: no WORKOS_ISSUER set — issuer claim will not be checked.");
        }
        this.decoder = d;
        log.info("WorkosTokenVerifier: verifying WorkOS access tokens via JWKS {}", url);
    }

    /**
     * Verify the raw WorkOS access token. Returns the decoded token — read
     * {@code getSubject()} for the WorkOS user id and {@code getClaimAsString("sid")}
     * for the session id. Throws {@link JwtException} if invalid/expired or if the
     * verifier is not configured.
     */
    public Jwt verify(String rawToken) {
        if (decoder == null) {
            throw new JwtException("WorkOS verifier not configured (WORKOS_CLIENT_ID / WORKOS_JWKS_URL missing)");
        }
        Jwt jwt = decoder.decode(rawToken);
        if (StringUtils.hasText(audience)) {
            List<String> aud = jwt.getAudience();
            if (aud == null || !aud.contains(audience)) {
                throw new JwtException("WorkOS token audience mismatch");
            }
        }
        return jwt;
    }

    private static String strip(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
