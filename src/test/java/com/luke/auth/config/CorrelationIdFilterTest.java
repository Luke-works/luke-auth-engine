package com.luke.auth.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/** #20: per-request correlation id — accepted/generated, MDC-tagged, echoed, and (via
 *  the proxy) forwarded to core-engine. */
class CorrelationIdFilterTest {

    @Test
    void sanitizeAcceptsSafeIdsAndGeneratesOtherwise() {
        assertEquals("abc-123_.X", CorrelationIdFilter.sanitize("abc-123_.X"));
        assertNotNull(CorrelationIdFilter.sanitize(null));
        assertNotEquals("", CorrelationIdFilter.sanitize(""));
        assertNotEquals("bad id!", CorrelationIdFilter.sanitize("bad id!"));
        assertNotEquals("x".repeat(65), CorrelationIdFilter.sanitize("x".repeat(65)));
    }

    @Test
    void propagatesInboundIdToMdcAndResponseThenClears() throws Exception {
        CorrelationIdFilter filter = new CorrelationIdFilter();
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader(CorrelationIdFilter.HEADER, "trace-42");
        MockHttpServletResponse res = new MockHttpServletResponse();

        String[] seen = new String[1];
        FilterChain chain = (rq, rs) -> seen[0] = MDC.get(CorrelationIdFilter.MDC_KEY);
        filter.doFilter(req, res, chain);

        assertEquals("trace-42", seen[0]);
        assertEquals("trace-42", res.getHeader(CorrelationIdFilter.HEADER));
        assertNull(MDC.get(CorrelationIdFilter.MDC_KEY));
    }

    @Test
    void generatesIdWhenAbsent() throws Exception {
        CorrelationIdFilter filter = new CorrelationIdFilter();
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(new MockHttpServletRequest(), res, (rq, rs) -> {});
        assertNotNull(res.getHeader(CorrelationIdFilter.HEADER));
    }
}
