package com.luke.auth.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;

/** #24: AuditService emits one structured line per event on the dedicated 'luke.audit' logger. */
class AuditServiceTest {

    private Logger auditLogger;
    private ListAppender<ILoggingEvent> appender;

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
    void emitsStructuredEventWithAllFieldsAndFirstForwardedIp() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("X-Forwarded-For", "203.0.113.7, 10.0.0.1");

        new AuditService().record("auth.login", AuditService.SUCCESS, "user-1", "a@b.com", "tenantA", req);

        assertEquals(1, appender.list.size(), "exactly one audit line per event");
        String msg = appender.list.get(0).getFormattedMessage();
        assertTrue(msg.contains("action=auth.login"), msg);
        assertTrue(msg.contains("outcome=success"), msg);
        assertTrue(msg.contains("actor=user-1"), msg);
        assertTrue(msg.contains("target=a@b.com"), msg);
        assertTrue(msg.contains("tenant=tenantA"), msg);
        assertTrue(msg.contains("ip=203.0.113.7"), "uses the first X-Forwarded-For hop: " + msg);
    }

    @Test
    void missingFieldsRenderAsDashAndNoRequestIsSafe() {
        new AuditService().record("auth.refresh", AuditService.FAILURE, "-", null);
        String msg = appender.list.get(0).getFormattedMessage();
        assertTrue(msg.contains("action=auth.refresh"), msg);
        assertTrue(msg.contains("outcome=failure"), msg);
        assertTrue(msg.contains("target=-"), msg);
        assertTrue(msg.contains("tenant=-"), msg);
        assertTrue(msg.contains("ip=-"), msg);
    }
}
