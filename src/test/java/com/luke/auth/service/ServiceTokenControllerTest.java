package com.luke.auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.luke.auth.audit.AuditService;
import com.luke.auth.config.GatewayKeys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * #39: service-token issuance is audited + metered; a keyId revoked live via the
 * operator-only endpoint is rejected on the next mint with no restart.
 */
class ServiceTokenControllerTest {

    private Logger auditLogger;
    private ListAppender<ILoggingEvent> appender;

    private static GatewayKeys ephemeralKeys() {
        GatewayKeys k = new GatewayKeys();
        ReflectionTestUtils.setField(k, "privateKeyPem", "");        // ephemeral keypair
        ReflectionTestUtils.setField(k, "previousPublicKeyPem", "");
        ReflectionTestUtils.setField(k, "requireStableKey", false);
        ReflectionTestUtils.setField(k, "issuer", "luke-auth-engine");
        ReflectionTestUtils.setField(k, "audience", "luke-core-engine");
        ReflectionTestUtils.setField(k, "ttlSeconds", 60L);
        ReflectionTestUtils.invokeMethod(k, "init");
        return k;
    }

    private ServiceTokenController controller(ServiceKeyRegistry registry, String operatorToken) {
        return new ServiceTokenController(registry, ephemeralKeys(), new AuditService(), 60L, operatorToken);
    }

    private String lastAudit() {
        return appender.list.get(appender.list.size() - 1).getFormattedMessage();
    }

    @BeforeEach
    void attach() {
        auditLogger = (Logger) LoggerFactory.getLogger("luke.audit");
        appender = new ListAppender<>();
        appender.start();
        auditLogger.addAppender(appender);
    }

    @AfterEach
    void detach() {
        auditLogger.detachAppender(appender);
    }

    @Test
    void issuanceEmitsAuditEventWithKeyIdAndScope() throws Exception {
        ServiceKeyRegistry registry = new ServiceKeyRegistry("s3cret=svc:bot;scope=forms");
        ServiceTokenController c = controller(registry, "");

        ResponseEntity<?> resp = c.token("s3cret", new MockHttpServletRequest());

        assertEquals(HttpStatus.OK, resp.getStatusCode());
        String keyId = registry.resolve("s3cret").keyId();
        String msg = appender.list.stream()
                .map(ILoggingEvent::getFormattedMessage)
                .filter(m -> m.contains("outcome=success"))
                .findFirst().orElseThrow();
        assertTrue(msg.contains("action=service.token"), msg);
        assertTrue(msg.contains("actor=svc:bot"), msg);
        assertTrue(msg.contains("target=" + keyId), "audits the non-secret keyId: " + msg);
        assertTrue(msg.contains("tenant=forms"), "audits the scope: " + msg);
    }

    @Test
    void failedKeyAttemptIsAuditedAsDenied() throws Exception {
        ServiceKeyRegistry registry = new ServiceKeyRegistry("s3cret=svc:bot");
        ServiceTokenController c = controller(registry, "");

        ResponseEntity<?> resp = c.token("wrong", new MockHttpServletRequest());

        assertEquals(HttpStatus.UNAUTHORIZED, resp.getStatusCode());
        assertTrue(lastAudit().contains("action=service.token"), lastAudit());
        assertTrue(lastAudit().contains("outcome=denied"), lastAudit());
    }

    @Test
    void liveRevocationViaOperatorEndpointRejectsNextMintWithoutRestart() throws Exception {
        ServiceKeyRegistry registry = new ServiceKeyRegistry("s3cret=svc:bot");
        ServiceTokenController c = controller(registry, "op-secret");
        String keyId = registry.resolve("s3cret").keyId();

        assertEquals(HttpStatus.OK, c.token("s3cret", new MockHttpServletRequest()).getStatusCode());

        // Operator revokes the keyId live — same controller/registry, no restart.
        ResponseEntity<?> rev = c.revoke(keyId, "op-secret", new MockHttpServletRequest());
        assertEquals(HttpStatus.OK, rev.getStatusCode());

        assertEquals(HttpStatus.UNAUTHORIZED,
                c.token("s3cret", new MockHttpServletRequest()).getStatusCode(),
                "revoked key must be rejected on the very next mint");

        // Operator undoes it → works again.
        assertEquals(HttpStatus.OK, c.unrevoke(keyId, "op-secret", new MockHttpServletRequest()).getStatusCode());
        assertEquals(HttpStatus.OK, c.token("s3cret", new MockHttpServletRequest()).getStatusCode());
    }

    @Test
    void revokeEndpointRequiresOperatorToken() {
        ServiceKeyRegistry registry = new ServiceKeyRegistry("s3cret=svc:bot");
        ServiceTokenController c = controller(registry, "op-secret");
        String keyId = registry.resolve("s3cret").keyId();

        assertEquals(HttpStatus.FORBIDDEN,
                c.revoke(keyId, "wrong-op", new MockHttpServletRequest()).getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN,
                c.revoke(keyId, null, new MockHttpServletRequest()).getStatusCode());
    }

    @Test
    void revokeEndpointDisabledWhenNoOperatorTokenConfigured() {
        ServiceKeyRegistry registry = new ServiceKeyRegistry("s3cret=svc:bot");
        ServiceTokenController c = controller(registry, ""); // no operator token → disabled
        String keyId = registry.resolve("s3cret").keyId();

        assertEquals(HttpStatus.FORBIDDEN,
                c.revoke(keyId, "anything", new MockHttpServletRequest()).getStatusCode(),
                "endpoint is disabled unless an operator token is configured");
    }

    @Test
    void responseCarriesScopeAndIssuanceCount() throws Exception {
        ServiceKeyRegistry registry = new ServiceKeyRegistry("s3cret=svc:bot;scope=emails");
        ServiceTokenController c = controller(registry, "");

        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> body =
                (java.util.Map<String, Object>) c.token("s3cret", new MockHttpServletRequest()).getBody();
        assertNotNull(body);
        assertEquals("emails", body.get("scope"));
        assertTrue(((Number) body.get("issuanceCount")).longValue() >= 1);
    }
}
