package com.luke.auth.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Guards {@code /actuator/prometheus} (OBS-2) so the metrics scrape is NEVER public. The gateway's
 * {@code /actuator/} prefix is on the SecurityFilterChain public allowlist (for Render's health probe),
 * so without this the Prometheus endpoint — gateway 5xx-rate, latency, JVM — would be world-readable.
 * Runs at servlet order 0 (ahead of Spring Security), so it is the gate.
 *
 * <p>Keyed on {@code MANAGEMENT_METRICS_TOKEN}: UNSET ⇒ <b>404</b> (safe default; dev/qa boot fine and
 * nothing is exposed); SET ⇒ requires {@code Authorization: Bearer <token>} (constant-time), else 401.
 * The Grafana Alloy collector presents the token. Health/info and the health probe are untouched.
 */
@Configuration
public class MetricsScrapeAuthFilter {

    private static final Logger log = LoggerFactory.getLogger(MetricsScrapeAuthFilter.class);

    @Bean
    public FilterRegistrationBean<Filter> metricsScrapeAuthFilterRegistration(
            @Value("${MANAGEMENT_METRICS_TOKEN:}") String token) {
        FilterRegistrationBean<Filter> reg = new FilterRegistrationBean<>();
        reg.setFilter(new Impl(token));
        reg.addUrlPatterns("/actuator/prometheus");
        reg.setName("metricsScrapeAuthFilter");
        reg.setOrder(0);
        return reg;
    }

    static class Impl implements Filter { // package-private for direct unit testing
        private final String expected; // the scrape token, or null when unconfigured

        Impl(String token) {
            if (token != null && !token.isBlank()) {
                this.expected = token;
                log.info("MetricsScrapeAuthFilter: ENABLED — /actuator/prometheus requires a Bearer scrape token.");
            } else {
                this.expected = null;
                log.info("MetricsScrapeAuthFilter: disabled (MANAGEMENT_METRICS_TOKEN unset) — "
                        + "/actuator/prometheus is 404 (never public). Set the token to enable scraping.");
            }
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            HttpServletRequest req = (HttpServletRequest) request;
            HttpServletResponse res = (HttpServletResponse) response;

            if ("OPTIONS".equalsIgnoreCase(req.getMethod())) {
                chain.doFilter(request, response);
                return;
            }
            if (expected == null) {
                writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found");
                return;
            }
            String presented = req.getHeader("Authorization");
            if (presented == null || !constantTimeEquals(presented, "Bearer " + expected)) {
                writeError(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                return;
            }
            chain.doFilter(request, response);
        }

        private static void writeError(HttpServletResponse res, int status, String message) throws IOException {
            res.setStatus(status);
            res.setContentType("application/json");
            res.setCharacterEncoding("UTF-8");
            res.getWriter().write("{\"error\":\"" + message + "\",\"status\":" + status + "}");
        }

        private static boolean constantTimeEquals(String a, String b) {
            return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
        }
    }
}
