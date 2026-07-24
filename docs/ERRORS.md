# Error contract

Every error the gateway returns has one shape, built in one place
(`web/error/ApiError` + `web/error/GlobalExceptionHandler`, issue #37).

## The body

RFC 7807 `application/problem+json`, plus two legacy keys:

```json
{
  "type": "about:blank",
  "title": "Bad Gateway",
  "status": 502,
  "detail": "A required upstream service is unavailable. Please try again.",
  "error": "Bad Gateway",
  "message": "A required upstream service is unavailable. Please try again.",
  "correlationId": "8f1c2e5a-..."
}
```

| Field | Why |
| --- | --- |
| `type` / `title` / `status` / `detail` | RFC 7807. |
| `error` / `message` | **Do not remove.** luke-consumer-ui reads `data.message \|\| data.error` (`src/lib/authApi.ts`); dropping them blanks out every auth error in the UI. |
| `correlationId` | Same id as the `X-Correlation-Id` response header and the `cid=` field on every server log line for the request. |
| `code` | Only on WorkOS 4xx — the provider's error code (e.g. `email_verification_required`), which the UI uses for flow control. |

## What is and isn't returned

**Sanitized** (generic text out, real cause to the log):

- upstream transport failures — URIs, hostnames, ports, DNS/TLS/timeout causes
- `PermissionsClient.UpstreamException`, `CoreAdminClient.CoreException`,
  `OnboardingClient.OnboardingException` → `502` + "A required upstream service is unavailable."
- WorkOS **5xx** and transport failures → `502` + "The identity provider is unavailable."
- any unhandled exception → `500` + "An unexpected error occurred."
- `JwtException` → `401` + "Invalid or expired token" — never *why*, since a specific reason
  is an oracle for token forgery

**Passed through** (deliberately user-facing):

- WorkOS **4xx** messages, e.g. "Email already in use" — the provider authored these for the
  end user and the UI shows them verbatim
- `TenantForbiddenException`, which echoes only the client-supplied tenant id

## Supporting a report

A user reporting an error can quote the `correlationId`. Grep the logs for it:

```bash
grep 'cid=8f1c2e5a' <logs>     # or the [cid:...] prefix on each line
```

The log line holds the unsanitized detail — the upstream URI, status and cause.

## Adding an endpoint

Do nothing. Uncaught exceptions land in `GlobalExceptionHandler` and get the shape above.
If you need an inline error return, use `ApiError.entity(...)` rather than building a map, so
the caught and uncaught paths stay indistinguishable to a client.

> Known gap: responses written by servlet **filters** (e.g. `AuthRateLimitFilter`'s 429) bypass
> `@RestControllerAdvice` and keep their own body shape. They leak nothing, but they are not
> problem+json.
