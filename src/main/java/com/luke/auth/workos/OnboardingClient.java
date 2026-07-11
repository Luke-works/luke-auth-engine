package com.luke.auth.workos;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Provisions a freshly-registered user into core-engine (FluxNova) by calling
 * the operator-only {@code POST /api/admin/onboard-user} with a configured
 * operator Basic credential. The engine user id is supplied explicitly (the same
 * {@code workos:<sub>} string the gateway asserts at request time), so no
 * core-engine change is required.
 *
 * <p><b>Opt-in:</b> a no-op unless both an operator credential and a default
 * tenant are configured. Consumer self-signup can instead leave this off and let
 * the user create their own organization after first login.
 */
@Component
public class OnboardingClient {

    private static final Logger log = LoggerFactory.getLogger(OnboardingClient.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String coreBaseUrl;
    private final String operatorUser;
    private final String operatorPassword;
    private final String defaultTenant;
    private final String defaultRole;
    private final String defaultAccessLevel;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public OnboardingClient(@Value("${luke.auth.core-engine.base-url}") String coreBaseUrl,
                            @Value("${luke.auth.onboarding.operator-user:}") String operatorUser,
                            @Value("${luke.auth.onboarding.operator-password:}") String operatorPassword,
                            @Value("${luke.auth.onboarding.default-tenant:}") String defaultTenant,
                            @Value("${luke.auth.onboarding.default-role:}") String defaultRole,
                            @Value("${luke.auth.onboarding.default-access-level:READ_WRITE}") String defaultAccessLevel) {
        this.coreBaseUrl = strip(coreBaseUrl);
        this.operatorUser = operatorUser;
        this.operatorPassword = operatorPassword;
        this.defaultTenant = defaultTenant;
        this.defaultRole = defaultRole;
        this.defaultAccessLevel = defaultAccessLevel;
    }

    /** True when an operator credential + default tenant/role are configured. */
    public boolean enabled() {
        return StringUtils.hasText(operatorUser)
                && StringUtils.hasText(defaultTenant)
                && StringUtils.hasText(defaultRole);
    }

    /**
     * Provision {@code engineUserId} into the default tenant/role. No-op (with a
     * debug log) when {@link #enabled()} is false. Throws on a non-2xx so the
     * caller can decide whether a failed provision should fail registration.
     */
    public void provision(String engineUserId, String firstName, String lastName, String email) {
        if (!enabled()) {
            log.debug("Onboarding skipped (no operator/default-tenant configured) for {}", engineUserId);
            return;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", engineUserId);
        body.put("firstName", firstName == null ? "" : firstName);
        body.put("lastName", lastName == null ? "" : lastName);
        body.put("email", email);
        body.put("password", randomUnusablePassword()); // FluxNova needs a value; WorkOS owns auth
        body.put("tenantId", defaultTenant);
        body.put("role", defaultRole);
        body.put("accessLevel", defaultAccessLevel);

        try {
            byte[] json = MAPPER.writeValueAsBytes(body);
            String basic = Base64.getEncoder().encodeToString(
                    (operatorUser + ":" + operatorPassword).getBytes(StandardCharsets.UTF_8));
            HttpRequest req = HttpRequest.newBuilder(URI.create(coreBaseUrl + "/api/admin/onboard-user"))
                    .timeout(Duration.ofSeconds(15))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Basic " + basic)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(json))
                    .build();
            HttpResponse<byte[]> res = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (res.statusCode() / 100 != 2) {
                String msg = res.body() == null ? "" : new String(res.body(), StandardCharsets.UTF_8);
                log.error("Onboarding failed for {} — core-engine returned {} {}", engineUserId, res.statusCode(), msg);
                throw new OnboardingException("Onboarding failed (" + res.statusCode() + ")");
            }
            log.info("Provisioned engine user {} into tenant {} as {}", engineUserId, defaultTenant, defaultRole);
        } catch (OnboardingException e) {
            throw e;
        } catch (Exception e) {
            throw new OnboardingException("Onboarding call failed: " + e.getMessage());
        }
    }

    /** Long random secret so the FluxNova password field is satisfied but never matches. */
    private static String randomUnusablePassword() {
        byte[] bytes = new byte[48];
        new java.security.SecureRandom().nextBytes(bytes);
        return "workos-nologin-" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String strip(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    public static class OnboardingException extends RuntimeException {
        public OnboardingException(String message) { super(message); }
    }
}
