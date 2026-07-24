package com.luke.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;

/**
 * The gateway's central {@link SecurityFilterChain} (#29).
 *
 * <p><b>What this owns:</b> a stateless, CSRF-free posture and consistent security
 * response headers (HSTS, {@code X-Content-Type-Options}, Referrer-Policy) applied in one
 * place instead of nowhere.
 *
 * <p><b>What this deliberately does NOT own — yet:</b> the authenticated-by-default
 * <em>decision</em>. Authorization stays {@code permitAll} here because the controllers are
 * the correct enforcement point today, and moving that decision into request matchers would
 * be a security <em>regression</em>, not an improvement, for two concrete reasons:
 * <ul>
 *   <li>The proxy decides public-vs-protected on the <b>canonicalized</b> path (percent-decoded,
 *       traversal-resolved — see {@code EngineProxyController#canonicalPath}). That is the exact
 *       defense behind the path-traversal advisory; a raw {@code requestMatchers("/api/public/**")}
 *       matches the un-normalized URI and would let {@code /api/public/%2e%2e/me} look public.</li>
 *   <li>Authentication has three real modes across different endpoints — WorkOS Bearer, the
 *       dev-mode {@code X-Dev-User} fallback, and {@code X-Service-Key} — plus per-request
 *       tenant-scoping and act-as minting that are intrinsic to the proxy.</li>
 * </ul>
 * Migrating enforcement into a WorkOS {@code AuthenticationProvider} (and method-level
 * tenant-admin authorization) is worthwhile, but it must replicate that canonicalization and
 * be proven with a live-WorkOS integration test — which CI cannot run today. Until then this
 * chain adds the header + transport hardening with <b>zero change to who can access what</b>.
 *
 * <p><b>Frame options are intentionally disabled.</b> The only HTML the gateway serves is the
 * public embed page, which MUST be iframable; its per-tenant {@code frame-ancestors} CSP (set
 * downstream by the engine) is the clickjacking control. A blanket {@code X-Frame-Options: DENY}
 * would break embedding and protects nothing else (every other response is JSON/bytes).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Stateless token gateway — no server session, so CSRF (a cookie/session attack)
                // does not apply, and the default login surfaces are noise.
                .csrf(csrf -> csrf.disable())
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable())
                .logout(logout -> logout.disable())
                // The standalone CorsFilter bean (CorsConfig) is the CORS terminator; don't let
                // Spring Security also handle CORS.
                .cors(cors -> cors.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(headers -> headers
                        // See the class note — the embed page must stay frameable.
                        .frameOptions(frame -> frame.disable())
                        // X-Content-Type-Options: nosniff
                        .contentTypeOptions(cto -> {})
                        // HSTS (emitted over HTTPS): pin browsers to TLS for a year, subdomains too.
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31_536_000))
                        .referrerPolicy(rp -> rp.policy(ReferrerPolicy.NO_REFERRER)))
                // Enforcement remains in the controllers (which canonicalize the path). This chain
                // changes headers/posture, not access.
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }
}
