package com.luke.auth.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * #57 — end-to-end WorkOS token verification against a REAL JWKS (served by the JDK HttpServer,
 * the same stubbing approach as {@code PermissionsClientRetryTest}), exercising the actual
 * {@code NimbusJwtDecoder} → {@code WorkosAuthenticationFilter} → SecurityFilterChain path that
 * CI otherwise can't cover (no live WorkOS). Runs under **strict validation** so issuer + audience
 * are enforced.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JwksAuthenticationIntegrationTest {

    private static final String ISSUER = "https://test-issuer.example";
    private static final String AUDIENCE = "test-audience";
    private static final String KID_1 = "test-key-1";
    private static final String KID_2 = "test-key-2";

    private static final RSAKey KEY_1 = generateKey(KID_1);
    private static final RSAKey KEY_2 = generateKey(KID_2);       // used for the rotation test
    private static final RSAKey ROGUE = generateKey(KID_1);       // same kid, wrong key → bad signature

    private static final AtomicReference<String> JWKS_JSON =
            new AtomicReference<>(new JWKSet(KEY_1.toPublicJWK()).toString());
    private static final HttpServer JWKS_SERVER = startJwksServer();

    @Autowired
    private TestRestTemplate rest;

    @DynamicPropertySource
    static void workosProps(DynamicPropertyRegistry r) {
        int port = JWKS_SERVER.getAddress().getPort();
        r.add("luke.auth.workos.jwks-url", () -> "http://localhost:" + port + "/jwks");
        r.add("luke.auth.workos.issuer", () -> ISSUER);
        r.add("luke.auth.workos.audience", () -> AUDIENCE);
        r.add("luke.auth.workos.strict-validation", () -> "true");
    }

    @AfterAll
    static void stop() {
        JWKS_SERVER.stop(0);
    }

    // ── the cases ────────────────────────────────────────────────────────────

    @Test
    void validTokenIsAuthenticated() {
        String token = sign(KEY_1, KID_1, ISSUER, AUDIENCE, Instant.now().plusSeconds(300));
        // Authenticated → NOT 401 (engine is down in-test, so a 5xx surfaces — the chain let it in).
        assertNotEquals(401, statusWithBearer(token));
    }

    @Test
    void expiredTokenIsRejected() {
        String token = sign(KEY_1, KID_1, ISSUER, AUDIENCE, Instant.now().minusSeconds(60));
        assertEquals(401, statusWithBearer(token));
    }

    @Test
    void wrongIssuerIsRejected() {
        String token = sign(KEY_1, KID_1, "https://evil.example", AUDIENCE, Instant.now().plusSeconds(300));
        assertEquals(401, statusWithBearer(token));
    }

    @Test
    void wrongAudienceIsRejected() {
        String token = sign(KEY_1, KID_1, ISSUER, "wrong-audience", Instant.now().plusSeconds(300));
        assertEquals(401, statusWithBearer(token));
    }

    @Test
    void tokenSignedByAnUnknownKeyIsRejected() {
        // Correct kid, but signed with a key that is NOT the one the JWKS publishes → bad signature.
        String token = sign(ROGUE, KID_1, ISSUER, AUDIENCE, Instant.now().plusSeconds(300));
        assertEquals(401, statusWithBearer(token));
    }

    @Test
    void keyRotationIsHonored() {
        // Rotate: publish BOTH keys, then present a token signed by the new kid. The decoder must
        // refetch the JWKS on the unknown kid and accept it.
        JWKS_JSON.set(new JWKSet(java.util.List.of(KEY_1.toPublicJWK(), KEY_2.toPublicJWK())).toString());
        String token = sign(KEY_2, KID_2, ISSUER, AUDIENCE, Instant.now().plusSeconds(300));
        assertNotEquals(401, statusWithBearer(token));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private int statusWithBearer(String token) {
        HttpHeaders h = new HttpHeaders();
        h.setBearerAuth(token);
        return rest.exchange("/api/me/permissions", HttpMethod.GET, new HttpEntity<>(h), String.class)
                .getStatusCode().value();
    }

    private static String sign(RSAKey key, String kid, String issuer, String audience, Instant expiresAt) {
        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(),
                    new JWTClaimsSet.Builder()
                            .subject("user_test")
                            .issuer(issuer)
                            .audience(audience)
                            .issueTime(new Date())
                            .expirationTime(Date.from(expiresAt))
                            .build());
            jwt.sign(new RSASSASigner(key.toPrivateKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static RSAKey generateKey(String kid) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair kp = gen.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) kp.getPublic())
                    .privateKey(kp.getPrivate())
                    .keyID(kid)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static HttpServer startJwksServer() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/jwks", ex -> {
                byte[] body = JWKS_JSON.get().getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().add("Content-Type", "application/json");
                ex.sendResponseHeaders(200, body.length);
                ex.getResponseBody().write(body);
                ex.close();
            });
            server.start();
            return server;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
