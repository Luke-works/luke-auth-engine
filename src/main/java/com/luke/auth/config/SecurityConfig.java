package com.luke.auth.config;

import com.luke.auth.config.WorkosTokenVerifier;
import com.luke.auth.identity.IdentityResolver;
import com.luke.auth.security.PublicPathRequestMatcher;
import com.luke.auth.security.WorkosAuthenticationFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;

/**
 * The gateway's central {@link SecurityFilterChain} (#29).
 *
 * <p><b>Authenticated-by-default.</b> Every request must be authenticated except an explicit
 * public allowlist ({@link PublicPathRequestMatcher}) — so a newly-added endpoint is protected
 * even if its author forgets a check. Authentication is established centrally by
 * {@link WorkosAuthenticationFilter}, which verifies the WorkOS Bearer token (and, in dev-mode,
 * the {@code X-Dev-User} fallback) into the {@code SecurityContext} using the <b>same</b>
 * {@link WorkosTokenVerifier} the controllers use — so verification behaviour is unchanged; only
 * its location moves. Service-key and signed-webhook endpoints are on the allowlist and
 * authenticate at their own controllers.
 *
 * <p><b>The allowlist is canonicalization-aware.</b> The public proxy surfaces are matched on the
 * percent-decoded, traversal-resolved path (shared {@code RequestPaths}), NOT a raw
 * {@code startsWith}, so {@code /api/public/%2e%2e/me} cannot masquerade as public — the exact
 * defense behind the path-traversal advisory.
 *
 * <p><b>Defense in depth.</b> The controllers keep their own verification (and the proxy its
 * tenant-scoping + act-as minting). That is intentional: the chain is now the authoritative
 * edge gate, and the controller checks remain a second layer. Tenant-admin authorization stays
 * enforced by {@code AuthController#requireTenantAdmin} (a dynamic per-tenant session lookup that
 * a static method-security role can't express).
 *
 * <p>It owns a stateless, CSRF-free posture and consistent security response headers (HSTS,
 * {@code X-Content-Type-Options}, Referrer-Policy) applied in one place instead of nowhere.
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
    SecurityFilterChain securityFilterChain(HttpSecurity http, WorkosTokenVerifier verifier,
                                            IdentityResolver identityResolver,
                                            @Value("${luke.auth.dev-mode:false}") boolean devMode)
            throws Exception {
        // The WorkOS filter authenticates once, centrally, into the SecurityContext (see its
        // javadoc) — using the SAME verifier the controllers use, so behaviour is unchanged.
        var workosFilter = new WorkosAuthenticationFilter(verifier, identityResolver, devMode);

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
                // A stateless API answers an unauthenticated call with 401 (not the servlet
                // default 403) — matching the gateway's existing contract and the UI's handling.
                .exceptionHandling(ex -> ex.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
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
                .addFilterBefore(workosFilter, UsernamePasswordAuthenticationFilter.class)
                // Authenticated-by-default: a new endpoint is protected even if its author forgets
                // a check. The public allowlist is canonicalization-aware (PublicPathRequestMatcher)
                // so a traversal can't sneak onto the public surface.
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(new PublicPathRequestMatcher()).permitAll()
                        .anyRequest().authenticated());
        return http.build();
    }
}
