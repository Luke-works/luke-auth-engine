package com.luke.auth.web.error;

import com.luke.auth.session.PermissionsClient;
import com.luke.auth.session.SessionService;
import com.luke.auth.web.CoreAdminClient;
import com.luke.auth.workos.OnboardingClient;
import com.luke.auth.workos.WorkosClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * The gateway's single error boundary (#37).
 *
 * <p>Two rules:
 * <ol>
 *   <li><b>Sanitize outward.</b> Internal detail — upstream URIs and hostnames, connect/TLS
 *       failures, stack messages — is logged with the correlation id and never returned. Only
 *       messages the identity provider deliberately authored for an end user (WorkOS 4xx, e.g.
 *       "Email already in use") pass through, because the UI shows them verbatim.</li>
 *   <li><b>One shape.</b> Everything is an {@link ApiError} body, so {@code /auth/*},
 *       {@code /session} and {@code /service/token} answer identically.</li>
 * </ol>
 *
 * <p>Extending {@link ResponseEntityExceptionHandler} keeps Spring MVC's own exceptions
 * (unreadable body, method not allowed, missing param, …) mapped to their correct statuses
 * instead of being flattened to 500 by the catch-all below; {@link #handleExceptionInternal}
 * re-decorates those Spring-built bodies with our legacy keys + correlation id.
 */
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /** The user asked to act in a tenant they don't belong to — echoes only client-supplied input. */
    @ExceptionHandler(SessionService.TenantForbiddenException.class)
    public ResponseEntity<ProblemDetail> onTenantForbidden(SessionService.TenantForbiddenException e) {
        return ApiError.entity(HttpStatus.FORBIDDEN, "Forbidden", e.getMessage());
    }

    /**
     * WorkOS said no. A 4xx carries a curated, user-facing message from the provider and is
     * safe to surface; anything else (including our own 502 wrapper around a transport
     * failure) is replaced with a generic message.
     */
    @ExceptionHandler(WorkosClient.WorkosException.class)
    public ResponseEntity<ProblemDetail> onWorkos(WorkosClient.WorkosException e) {
        int raw = e.status();
        HttpStatus status = (raw >= 400 && raw < 600) ? HttpStatus.valueOf(raw) : HttpStatus.BAD_GATEWAY;
        boolean clientFacing = status.is4xxClientError();
        if (!clientFacing) {
            log.warn("WorkOS upstream failure [cid={}]: {}", ApiError.correlationId(), e.getMessage());
        }
        ProblemDetail pd = ApiError.problem(status, "Identity provider error",
                clientFacing ? e.getMessage() : ApiError.IDP_UNAVAILABLE);
        String code = e.code();
        if (clientFacing && code != null && !code.isBlank()) {
            pd.setProperty("code", code); // flow-control hint the UI already understands
        }
        return ResponseEntity.status(status).body(pd);
    }

    @ExceptionHandler(PermissionsClient.UpstreamException.class)
    public ResponseEntity<ProblemDetail> onUpstream(PermissionsClient.UpstreamException e) {
        log.warn("Permissions upstream failure [cid={}] status={}: {}",
                ApiError.correlationId(), e.status(), e.getMessage());
        return ApiError.entity(HttpStatus.BAD_GATEWAY, "Bad Gateway", ApiError.UPSTREAM_UNAVAILABLE);
    }

    @ExceptionHandler(CoreAdminClient.CoreException.class)
    public ResponseEntity<ProblemDetail> onCore(CoreAdminClient.CoreException e) {
        log.warn("core-engine call failed [cid={}]: {}", ApiError.correlationId(), e.getMessage());
        return ApiError.entity(HttpStatus.BAD_GATEWAY, "Bad Gateway", ApiError.UPSTREAM_UNAVAILABLE);
    }

    @ExceptionHandler(OnboardingClient.OnboardingException.class)
    public ResponseEntity<ProblemDetail> onOnboarding(OnboardingClient.OnboardingException e) {
        log.warn("Onboarding call failed [cid={}]: {}", ApiError.correlationId(), e.getMessage());
        return ApiError.entity(HttpStatus.BAD_GATEWAY, "Bad Gateway", ApiError.UPSTREAM_UNAVAILABLE);
    }

    /** Token verification failures must never explain *why* (oracle for token forgery). */
    @ExceptionHandler(JwtException.class)
    public ResponseEntity<ProblemDetail> onJwt(JwtException e) {
        log.debug("Token rejected [cid={}]: {}", ApiError.correlationId(), e.getMessage());
        return ApiError.entity(HttpStatus.UNAUTHORIZED, "Unauthorized", "Invalid or expired token");
    }

    /** Last resort: log the whole thing server-side, tell the client nothing. */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> onUnexpected(Exception e) {
        log.error("Unhandled exception [cid={}]", ApiError.correlationId(), e);
        return ApiError.entity(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Error", ApiError.INTERNAL);
    }

    /** Re-decorate the bodies Spring MVC builds for its own exceptions so the shape stays uniform. */
    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception ex, @Nullable Object body,
                                                             HttpHeaders headers, HttpStatusCode status,
                                                             WebRequest request) {
        ResponseEntity<Object> response = super.handleExceptionInternal(ex, body, headers, status, request);
        if (response != null && response.getBody() instanceof ProblemDetail pd) {
            ApiError.decorate(pd, pd.getTitle(), pd.getDetail());
        }
        return response;
    }
}
