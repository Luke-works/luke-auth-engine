package com.luke.auth.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * The gateway's signing key — the "secret badge" the engine trusts.
 *
 * <p>Holds an RSA keypair. The <em>private</em> key signs short-lived
 * "act-as-user" tokens ({@link #mintActAsToken}); the <em>public</em> key is
 * published as a JWK Set ({@link #publicJwkSetJson}) so {@code luke-core-engine}
 * can verify those tokens without sharing any secret.
 *
 * <p>If {@code luke.auth.gateway.private-key} is set (PEM, PKCS#8), it is loaded;
 * otherwise an ephemeral keypair is generated at startup. Ephemeral keys are
 * fine for local dev but rotate on every restart — set the env var in shared
 * environments so the engine's cached JWKS stays valid across deploys.
 */
@Component
public class GatewayKeys {

    private static final Logger log = LoggerFactory.getLogger(GatewayKeys.class);

    @Value("${luke.auth.gateway.private-key:}")
    private String privateKeyPem;

    /** PEM X.509 public key of the PREVIOUS signing key, published alongside the
     *  current one during a rotation overlap (nullable). */
    @Value("${luke.auth.gateway.previous-public-key:}")
    private String previousPublicKeyPem;

    /** When true, a stable {@code private-key} is mandatory — boot fails without it
     *  (no ephemeral fallback). Default false so non-prod can run ephemeral. */
    @Value("${luke.auth.gateway.require-stable-key:false}")
    private boolean requireStableKey;

    @Value("${luke.auth.gateway.issuer}")
    private String issuer;

    @Value("${luke.auth.gateway.audience}")
    private String audience;

    @Value("${luke.auth.gateway.ttl-seconds}")
    private long ttlSeconds;

    private RSAKey rsaJwk;       // private + public, tagged with a thumbprint kid
    private RSASSASigner signer;
    private String keyId;        // RFC 7638 thumbprint of the public key
    private RSAKey previousPublicJwk; // nullable — published during a rotation overlap

    @PostConstruct
    void init() throws Exception {
        // A hardened deployment must not run on an ephemeral key: it rotates every
        // restart and breaks act-as token verification until the engine refetches JWKS.
        if (requireStableKey && !StringUtils.hasText(privateKeyPem)) {
            throw new IllegalStateException(
                    "luke.auth.gateway.require-stable-key=true but GATEWAY_PRIVATE_KEY is unset. A stable RSA "
                    + "signing key is required (an ephemeral key rotates on every restart). Provide a PKCS#8 PEM.");
        }

        KeyPair keyPair = StringUtils.hasText(privateKeyPem)
                ? loadFromPem(privateKeyPem)
                : generateEphemeral();

        // Derive the kid from the key's own thumbprint. A stable (PEM) key →
        // stable kid; an ephemeral key → new kid each boot, which forces the
        // engine to refetch the JWKS rather than trust a stale cached key.
        RSAKey untagged = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .build();
        this.keyId = untagged.computeThumbprint().toString();
        this.rsaJwk = new RSAKey.Builder(untagged).keyID(keyId).build();
        this.signer = new RSASSASigner(keyPair.getPrivate());

        // Optional previous public key, published in the JWKS during a rotation so
        // tokens still in flight signed by the old kid keep verifying.
        if (StringUtils.hasText(previousPublicKeyPem)) {
            this.previousPublicJwk = loadPublicJwkFromPem(previousPublicKeyPem);
            log.info("GatewayKeys: publishing PREVIOUS public key in JWKS for rotation overlap (kid={})",
                    previousPublicJwk.getKeyID());
        }

        if (StringUtils.hasText(privateKeyPem)) {
            log.info("GatewayKeys: loaded RSA signing key from configuration (kid={})", keyId);
        } else {
            log.warn("GatewayKeys: no GATEWAY_PRIVATE_KEY set — generated an EPHEMERAL key (kid={}). "
                    + "Fine for non-prod (engine refetches JWKS on the new kid after a restart); "
                    + "set GATEWAY_PRIVATE_KEY (and require-stable-key=true) for production.", keyId);
        }
    }

    /**
     * Mint a signed, short-lived token asserting "act as {@code engineUserId}".
     * The engine verifies the signature against {@link #publicJwkSetJson} and
     * trusts the {@code sub} as the user to authenticate.
     */
    /**
     * True once the signing keypair is initialised (so act-as tokens can be minted).
     * Effectively always true post-boot — {@code @PostConstruct} builds an ephemeral or
     * configured key, and {@code require-stable-key} would have failed the boot otherwise
     * — but the readiness indicator (#26) checks it for completeness/defence-in-depth.
     */
    public boolean isReady() {
        return rsaJwk != null && signer != null;
    }

    public String mintActAsToken(String engineUserId) throws JOSEException {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject(engineUserId)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(ttlSeconds)))
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build(),
                claims);
        jwt.sign(signer);
        return jwt.serialize();
    }

    /** Public half of the keypair(s) as a JWK Set JSON document (served at
     *  /.well-known/jwks.json). Includes the previous public key during a rotation
     *  so the engine can verify tokens signed by either kid. */
    public Map<String, Object> publicJwkSetJson() {
        List<JWK> keys = new ArrayList<>();
        keys.add(rsaJwk.toPublicJWK());
        if (previousPublicJwk != null) {
            keys.add(previousPublicJwk); // already public-only
        }
        return new JWKSet(keys).toJSONObject();
    }

    /** Load an X.509 (SubjectPublicKeyInfo) PEM public key into a public-only RSAKey,
     *  tagged with its RFC 7638 thumbprint kid. */
    private RSAKey loadPublicJwkFromPem(String pem) throws Exception {
        String base64 = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKey pub = (RSAPublicKey) factory.generatePublic(
                new java.security.spec.X509EncodedKeySpec(der));
        RSAKey untagged = new RSAKey.Builder(pub).build();
        return new RSAKey.Builder(untagged).keyID(untagged.computeThumbprint().toString()).build();
    }

    private KeyPair generateEphemeral() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    /** Load a PKCS#8 PEM ("-----BEGIN PRIVATE KEY-----"...) into an RSA keypair. */
    private KeyPair loadFromPem(String pem) throws Exception {
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(der));

        // Derive the public key from the private key's modulus + public exponent.
        java.security.interfaces.RSAPrivateCrtKey crt = (java.security.interfaces.RSAPrivateCrtKey) privateKey;
        RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                new java.security.spec.RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
        return new KeyPair(publicKey, privateKey);
    }
}
