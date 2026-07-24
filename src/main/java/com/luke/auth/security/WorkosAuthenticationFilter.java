package com.luke.auth.security;

import com.luke.auth.config.WorkosTokenVerifier;
import com.luke.auth.identity.IdentityResolver;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Establishes the authenticated caller in the Spring Security context (#29), so the central
 * {@code SecurityFilterChain} — not each controller — is the authoritative "who is this" gate.
 *
 * <p>It uses the <b>same</b> {@link WorkosTokenVerifier} the controllers use, so verification
 * behaviour is byte-for-byte what production does today; the only change is that it runs once,
 * centrally, and populates the context. It authenticates:
 * <ul>
 *   <li>a WorkOS {@code Authorization: Bearer} access token (the normal path), and</li>
 *   <li>in dev-mode only, the {@code X-Dev-User} fallback header (mirroring the proxy/session).</li>
 * </ul>
 *
 * <p>It never <em>rejects</em> a request — an absent/invalid token simply leaves the context
 * anonymous, and the authorization rules in {@code SecurityConfig} decide access (401 for a
 * protected path, pass-through for the public allowlist). Requests bearing a service key or a
 * signed webhook authenticate at their own controllers and are on the public allowlist, so this
 * filter leaves them untouched.
 */
public class WorkosAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(WorkosAuthenticationFilter.class);
    private static final List<SimpleGrantedAuthority> USER = List.of(new SimpleGrantedAuthority("ROLE_USER"));

    private final WorkosTokenVerifier verifier;
    private final IdentityResolver identityResolver;
    private final boolean devMode;

    public WorkosAuthenticationFilter(WorkosTokenVerifier verifier, IdentityResolver identityResolver,
                                      boolean devMode) {
        this.verifier = verifier;
        this.identityResolver = identityResolver;
        this.devMode = devMode;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            WorkosPrincipal principal = resolve(request);
            if (principal != null) {
                var authentication = new UsernamePasswordAuthenticationToken(principal, null, USER);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        chain.doFilter(request, response);
    }

    private WorkosPrincipal resolve(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String token = header.substring(7).trim();
            if (!token.isEmpty()) {
                try {
                    Jwt jwt = verifier.verify(token);
                    String engineUserId = identityResolver.toEngineUserId(jwt.getSubject());
                    return new WorkosPrincipal(engineUserId, jwt.getSubject(), jwt, false);
                } catch (JwtException | IllegalArgumentException e) {
                    // Invalid/expired — stay anonymous; the chain returns 401 for protected paths.
                    log.debug("WorkOS token rejected: {}", e.getMessage());
                }
            }
        }
        if (devMode) {
            String devUser = request.getHeader("X-Dev-User");
            if (devUser != null && !devUser.isBlank()) {
                return new WorkosPrincipal(devUser.trim(), null, null, true); // LOCAL ONLY
            }
        }
        return null;
    }
}
