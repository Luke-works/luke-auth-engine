package com.luke.auth.web.error;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.luke.auth.session.PermissionsClient;
import com.luke.auth.session.SessionService;
import com.luke.auth.web.CoreAdminClient;
import com.luke.auth.workos.WorkosClient;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * #37 — the error boundary must (a) never return internal detail, (b) still let the
 * identity provider's own user-facing 4xx text through, and (c) keep the legacy
 * {@code error}/{@code message} keys luke-consumer-ui reads.
 */
class GlobalExceptionHandlerTest {

    /** A hostname/path that must never appear in a response body. */
    private static final String INTERNAL = "http://core-engine.internal:8080/api/me/permissions";

    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new Boom())
            .setControllerAdvice(new GlobalExceptionHandler())
            .build();

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @RestController
    static class Boom {
        @GetMapping("/boom/upstream")
        String upstream() {
            throw new PermissionsClient.UpstreamException(0, "Failed calling " + INTERNAL + ": Connection refused");
        }

        @GetMapping("/boom/core")
        String core() {
            throw new CoreAdminClient.CoreException("Failed calling core " + INTERNAL);
        }

        @GetMapping("/boom/generic")
        String generic() {
            throw new IllegalStateException("NPE at com.luke.auth.Secret.line42 " + INTERNAL);
        }

        @GetMapping("/boom/workos4xx")
        String workos4xx() {
            throw new WorkosClient.WorkosException(422, "Email already in use",
                    Map.of("code", "email_taken"));
        }

        @GetMapping("/boom/workos502")
        String workos502() {
            throw new WorkosClient.WorkosException(502, "WorkOS call failed: unable to resolve api.workos.com",
                    Map.of());
        }

        @GetMapping("/boom/tenant")
        String tenant() {
            throw new SessionService.TenantForbiddenException("acme");
        }

        @GetMapping("/boom/jwt")
        String jwt() {
            throw new JwtException("signature mismatch: expected kid=abc123 got kid=def");
        }
    }

    @Test
    void upstreamFailure_is502_andHidesInternalUri() throws Exception {
        mvc.perform(get("/boom/upstream"))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.message").value(ApiError.UPSTREAM_UNAVAILABLE))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("core-engine.internal"))));
    }

    @Test
    void coreFailure_is502_andHidesInternalUri() throws Exception {
        mvc.perform(get("/boom/core"))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.message").value(ApiError.UPSTREAM_UNAVAILABLE))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("core-engine.internal"))));
    }

    @Test
    void unexpectedException_is500_andLeaksNothing() throws Exception {
        mvc.perform(get("/boom/generic"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.message").value(ApiError.INTERNAL))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("Secret"))));
    }

    /** WorkOS 4xx text is written for the end user — the UI shows it, so it must survive. */
    @Test
    void workosClientError_passesCuratedMessageThrough() throws Exception {
        mvc.perform(get("/boom/workos4xx"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.message").value("Email already in use"))
                .andExpect(jsonPath("$.code").value("email_taken"));
    }

    @Test
    void workosTransportFailure_isSanitized() throws Exception {
        mvc.perform(get("/boom/workos502"))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.message").value(ApiError.IDP_UNAVAILABLE))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("api.workos.com"))));
    }

    @Test
    void tenantForbidden_is403() throws Exception {
        mvc.perform(get("/boom/tenant"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Forbidden"));
    }

    /** Never explain *why* a token failed — that is a forgery oracle. */
    @Test
    void jwtFailure_is401_andGivesNoOracle() throws Exception {
        mvc.perform(get("/boom/jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid or expired token"))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("kid="))));
    }

    /**
     * The response is RFC 7807 AND carries the legacy keys. luke-consumer-ui reads
     * {@code data.message || data.error} — dropping either blanks out every auth error.
     */
    @Test
    void body_isProblemJson_andKeepsLegacyKeysForConsumerUi() throws Exception {
        MDC.put("correlationId", "cid-123");
        mvc.perform(get("/boom/upstream"))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(502))   // RFC 7807
                .andExpect(jsonPath("$.title").exists())      // RFC 7807
                .andExpect(jsonPath("$.detail").exists())     // RFC 7807
                .andExpect(jsonPath("$.error").value("Bad Gateway"))  // legacy contract
                .andExpect(jsonPath("$.message").exists())            // legacy contract
                .andExpect(jsonPath("$.correlationId").value("cid-123"));
    }
}
