package com.luke.auth.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * The typed, validated view of every {@code luke.auth.*} setting (#35) — one auditable
 * place instead of {@code @Value} strings scattered across two dozen classes.
 *
 * <p><b>Constraints are deliberately weak.</b> Only settings that carry a non-empty default
 * in {@code application.yml} are constrained here, so binding can never fail an environment
 * that boots today. Secrets and prod-only invariants (WorkOS credentials, a stable signing
 * key, non-localhost CORS) are NOT constrained at bind time — they are asserted by
 * {@link AuthHardeningGuard}, which only fires under the {@code prod} profile or
 * {@code luke.auth.require-hardened=true}. dev/qa run without either and stay lenient.
 *
 * <p>See {@code docs/CONFIGURATION.md} for the full table and the production checklist.
 */
@ConfigurationProperties(prefix = "luke.auth")
@Validated
public class LukeAuthProperties {

    /** Fail the boot unless the production invariants hold, without the {@code prod} profile. */
    private boolean requireHardened = false;

    /** Auth backdoors (X-Dev-User, /dev/token). Also requires the {@code dev} profile — {@link DevModeGuard}. */
    private boolean devMode = false;

    private @Valid CoreEngine coreEngine = new CoreEngine();
    private @Valid FileProxy fileProxy = new FileProxy();
    private @Valid Workos workos = new Workos();
    private @Valid Gateway gateway = new Gateway();
    private @Valid Session session = new Session();

    public static class CoreEngine {
        /** Upstream engine every {@code /api/**} route proxies to. */
        @NotBlank
        private String baseUrl = "http://localhost:8080";

        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
    }

    public static class FileProxy {
        /** Blank ⇒ {@code /api/documents/**} falls through to core-engine unchanged. */
        private String baseUrl = "";

        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
    }

    public static class Workos {
        /** Secret-bearing; blank is legal locally and fails closed at request time. */
        private String clientId = "";
        private String apiKey = "";
        @NotBlank
        private String apiBaseUrl = "https://api.workos.com";
        private String jwksUrl = "";
        private String issuer = "";
        private String audience = "";
        /** Require issuer+audience binding on every token. Prod must set this true. */
        private boolean strictValidation = false;

        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getApiKey() { return apiKey; }
        public void setApiKey(String apiKey) { this.apiKey = apiKey; }
        public String getApiBaseUrl() { return apiBaseUrl; }
        public void setApiBaseUrl(String apiBaseUrl) { this.apiBaseUrl = apiBaseUrl; }
        public String getJwksUrl() { return jwksUrl; }
        public void setJwksUrl(String jwksUrl) { this.jwksUrl = jwksUrl; }
        public String getIssuer() { return issuer; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
        public String getAudience() { return audience; }
        public void setAudience(String audience) { this.audience = audience; }
        public boolean isStrictValidation() { return strictValidation; }
        public void setStrictValidation(boolean strictValidation) { this.strictValidation = strictValidation; }
    }

    public static class Gateway {
        /** PEM PKCS#8 RSA key. Blank ⇒ ephemeral key regenerated each restart (dev only). */
        private String privateKey = "";
        /** Refuse to boot on an ephemeral key. Prod must set this true. */
        private boolean requireStableKey = false;
        @NotBlank
        private String issuer = "luke-auth-engine";
        @NotBlank
        private String audience = "luke-core-engine";
        @Min(1)
        private int ttlSeconds = 60;

        public String getPrivateKey() { return privateKey; }
        public void setPrivateKey(String privateKey) { this.privateKey = privateKey; }
        public boolean isRequireStableKey() { return requireStableKey; }
        public void setRequireStableKey(boolean requireStableKey) { this.requireStableKey = requireStableKey; }
        public String getIssuer() { return issuer; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
        public String getAudience() { return audience; }
        public void setAudience(String audience) { this.audience = audience; }
        public int getTtlSeconds() { return ttlSeconds; }
        public void setTtlSeconds(int ttlSeconds) { this.ttlSeconds = ttlSeconds; }
    }

    public static class Session {
        @Min(0)
        private int cacheTtlSeconds = 60;

        public int getCacheTtlSeconds() { return cacheTtlSeconds; }
        public void setCacheTtlSeconds(int cacheTtlSeconds) { this.cacheTtlSeconds = cacheTtlSeconds; }
    }

    public boolean isRequireHardened() { return requireHardened; }
    public void setRequireHardened(boolean requireHardened) { this.requireHardened = requireHardened; }
    public boolean isDevMode() { return devMode; }
    public void setDevMode(boolean devMode) { this.devMode = devMode; }
    public CoreEngine getCoreEngine() { return coreEngine; }
    public void setCoreEngine(CoreEngine coreEngine) { this.coreEngine = coreEngine; }
    public FileProxy getFileProxy() { return fileProxy; }
    public void setFileProxy(FileProxy fileProxy) { this.fileProxy = fileProxy; }
    public Workos getWorkos() { return workos; }
    public void setWorkos(Workos workos) { this.workos = workos; }
    public Gateway getGateway() { return gateway; }
    public void setGateway(Gateway gateway) { this.gateway = gateway; }
    public Session getSession() { return session; }
    public void setSession(Session session) { this.session = session; }
}
