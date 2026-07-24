package com.luke.auth.web.error;

import com.luke.auth.config.CorrelationIdFilter;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;

/**
 * Builds the one error body the gateway returns (#37).
 *
 * <p>The shape is RFC 7807 {@code application/problem+json} ({@code type}, {@code title},
 * {@code status}, {@code detail}) <em>plus</em> two legacy properties, {@code error} and
 * {@code message}. The legacy keys are deliberate and must not be removed: luke-consumer-ui
 * reads {@code data.message || data.error} (see its {@code src/lib/authApi.ts}), so dropping
 * them would blank out every auth error in the UI. Emitting both makes the contract standard
 * without a breaking change on the client.
 *
 * <p>Every body also carries the request's {@code correlationId} so a user-reported failure
 * can be tied to the server-side log line that holds the real (unsanitized) detail.
 */
public final class ApiError {

    /** Client-safe stand-ins. The real cause is logged, never returned (#37). */
    public static final String UPSTREAM_UNAVAILABLE =
            "A required upstream service is unavailable. Please try again.";
    public static final String IDP_UNAVAILABLE =
            "The identity provider is unavailable. Please try again.";
    public static final String INTERNAL =
            "An unexpected error occurred.";

    private ApiError() {}

    public static ProblemDetail problem(HttpStatusCode status, String title, String detail) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, detail);
        pd.setTitle(title);
        decorate(pd, title, detail);
        return pd;
    }

    /**
     * Adds the legacy {@code error}/{@code message} keys and the correlation id to a
     * {@link ProblemDetail} — including ones Spring built for us (see
     * {@code GlobalExceptionHandler#handleExceptionInternal}).
     */
    public static void decorate(ProblemDetail pd, String title, String detail) {
        if (title != null) {
            pd.setProperty("error", title);
        }
        if (detail != null) {
            pd.setProperty("message", detail);
        }
        String cid = MDC.get(CorrelationIdFilter.MDC_KEY);
        if (cid != null && !cid.isBlank()) {
            pd.setProperty("correlationId", cid);
        }
    }

    public static ResponseEntity<ProblemDetail> entity(HttpStatus status, String title, String detail) {
        return ResponseEntity.status(status).body(problem(status, title, detail));
    }

    /** The correlation id for the in-flight request, or {@code "-"} when unset. */
    public static String correlationId() {
        String cid = MDC.get(CorrelationIdFilter.MDC_KEY);
        return (cid == null || cid.isBlank()) ? "-" : cid;
    }
}
