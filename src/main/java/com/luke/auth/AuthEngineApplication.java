package com.luke.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Luke Auth Engine — the consumer-facing gateway.
 *
 * <p>It sits between {@code luke-consumer-ui} and {@code luke-core-engine}:
 * <ol>
 *   <li>runs the login flows against WorkOS ({@code /auth/*}) and verifies the
 *       caller's WorkOS access token (authentication),</li>
 *   <li>resolves the WorkOS identity to an engine userId,</li>
 *   <li>mints a short-lived, signed "act-as-user" token, and</li>
 *   <li>transparently proxies the request to the engine, which performs
 *       authorization against that user's groups/tenants.</li>
 * </ol>
 *
 * <p>It deliberately knows nothing about engine resources (tasks, process
 * instances, deployments) — it forwards them opaquely.
 */
@SpringBootApplication
@ConfigurationPropertiesScan // picks up LukeAuthProperties / LukeCorsProperties (#35)
public class AuthEngineApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthEngineApplication.class, args);
    }
}
