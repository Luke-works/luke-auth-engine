package com.luke.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Publishes a machine-readable OpenAPI document for the gateway at {@code /v3/api-docs} (#59) —
 * the auth flows, the session view, the service-token surface, and the {@code /api/**} proxy.
 * springdoc auto-derives operations from the {@code @RestController} mappings; this bean just
 * sets the document metadata. The JSON is exportable for the api-collection.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    OpenAPI authEngineOpenApi() {
        return new OpenAPI().info(new Info()
                .title("luke-auth-engine")
                .version("v1")
                .description("Consumer-facing auth gateway: verifies WorkOS access tokens, mints "
                        + "short-lived act-as tokens, and reverse-proxies to core-engine. "
                        + "Authentication is a WorkOS Bearer token except on the public allowlist "
                        + "(login/register/callback/refresh, /api/public/**, JWKS, health). "
                        + "See docs/API.md for headers, error contract, and the public-passthrough rule.")
                .license(new License().name("Proprietary")));
    }
}
