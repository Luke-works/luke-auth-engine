package com.luke.auth.config;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import org.junit.jupiter.api.Test;

/** /actuator/prometheus is never public: 404 when no scrape token is set, Bearer-gated when it is. */
class MetricsScrapeAuthFilterTest {

    private final FilterChain chain = mock(FilterChain.class);

    private HttpServletRequest req(String method, String authorization) {
        HttpServletRequest r = mock(HttpServletRequest.class);
        when(r.getMethod()).thenReturn(method);
        when(r.getHeader("Authorization")).thenReturn(authorization);
        return r;
    }

    private HttpServletResponse res() {
        HttpServletResponse r = mock(HttpServletResponse.class);
        try {
            when(r.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return r;
    }

    @Test
    void unsetTokenIs404NeverPublic() throws Exception {
        HttpServletResponse res = res();
        new MetricsScrapeAuthFilter.Impl("").doFilter(req("GET", null), res, chain);
        verify(res).setStatus(404);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void configuredValidBearerPassesThrough() throws Exception {
        new MetricsScrapeAuthFilter.Impl("scrape-tok").doFilter(req("GET", "Bearer scrape-tok"), res(), chain);
        verify(chain).doFilter(any(), any());
    }

    @Test
    void configuredMissingTokenIs401() throws Exception {
        HttpServletResponse res = res();
        new MetricsScrapeAuthFilter.Impl("scrape-tok").doFilter(req("GET", null), res, chain);
        verify(res).setStatus(401);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void configuredWrongTokenIs401() throws Exception {
        HttpServletResponse res = res();
        new MetricsScrapeAuthFilter.Impl("scrape-tok").doFilter(req("GET", "Bearer nope"), res, chain);
        verify(res).setStatus(401);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void optionsPreflightPassesThrough() throws Exception {
        new MetricsScrapeAuthFilter.Impl("scrape-tok").doFilter(req("OPTIONS", null), res(), chain);
        verify(chain).doFilter(any(), any());
    }
}
