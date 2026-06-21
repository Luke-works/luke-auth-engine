package com.luke.auth.audit;

import com.luke.auth.config.CorrelationIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

/**
 * Emits a structured audit trail for authentication and privileged actions (#24).
 *
 * <p>auth-engine is the stateless gateway (no DB), so the audit trail is a dedicated
 * SLF4J logger ({@code luke.audit}) rather than a table. Every event is one line of
 * {@code key=value} fields — separable from app logs by the logger name and shipped via
 * stdout to the platform's retained log store, where it can be filtered/queried for
 * incident forensics and SOC2/ISO27001 attestation. Each line already carries the
 * correlation id via the logging pattern; we also embed it as a field so the record is
 * self-contained if parsed in isolation.
 *
 * <p>Retention/redaction: emails are the only PII recorded and only on identity-lifecycle
 * events (register/login/invite/add-member) where they are the audit subject. Retention
 * follows the platform log-store policy — see docs/AUDIT.md.
 */
@Component
public class AuditService {

    /** Dedicated audit logger — filter the log store by this name to isolate the trail. */
    private static final Logger audit = LoggerFactory.getLogger("luke.audit");

    public static final String SUCCESS = "success";
    public static final String FAILURE = "failure";
    public static final String DENIED = "denied";

    /**
     * Record one audit event.
     *
     * @param action  dotted event name, e.g. {@code auth.login}, {@code org.invite}, {@code actas.mint}
     * @param outcome {@link #SUCCESS} / {@link #FAILURE} / {@link #DENIED}
     * @param actor   who performed it (engine userId / service id / "-" if pre-auth)
     * @param target  who/what it acted on (email, member id, subject) or {@code null}
     * @param tenant  tenant scope or {@code null}
     * @param request the inbound request (for source IP) or {@code null} if unavailable
     */
    public void record(String action, String outcome, String actor, String target,
                       String tenant, HttpServletRequest request) {
        String ip = request != null ? clientIp(request) : "-";
        String cid = MDC.get(CorrelationIdFilter.MDC_KEY);
        // SLF4J placeholders keep this allocation-light; values here never contain spaces.
        audit.info("action={} outcome={} actor={} target={} tenant={} ip={} cid={}",
                nz(action), nz(outcome), nz(actor), nz(target), nz(tenant), nz(ip), nz(cid));
    }

    /** Convenience for self-acting events with no distinct target/tenant. */
    public void record(String action, String outcome, String actor, HttpServletRequest request) {
        record(action, outcome, actor, null, null, request);
    }

    /** Source IP: first X-Forwarded-For hop (Render sets it), else the socket address. */
    static String clientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            int comma = xff.indexOf(',');
            return (comma > 0 ? xff.substring(0, comma) : xff).trim();
        }
        return req.getRemoteAddr();
    }

    private static String nz(String s) {
        return (s == null || s.isBlank()) ? "-" : s;
    }
}
