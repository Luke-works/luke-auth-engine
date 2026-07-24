# Configuration

Every setting the gateway reads, and what a production deploy must set (#35).

## How it binds

`luke.auth.*` and `luke.cors.*` bind to typed, `@Validated` classes —
`config/LukeAuthProperties` and `config/LukeCorsProperties` — discovered by
`@ConfigurationPropertiesScan` on the application class. Bind-time validation
(`@NotBlank`, `@Min`) only guards settings that already carry a non-empty default, so
binding can never fail an environment that boots today.

Secrets and prod-only invariants are **not** enforced at bind time (that would crash
dev/qa, which legitimately run without them). They are asserted by
`config/AuthHardeningGuard`, which runs **only** when the `prod` Spring profile is active
or `luke.auth.require-hardened=true`.

## Production checklist

With `SPRING_PROFILES_ACTIVE=...,prod` (or `LUKE_AUTH_REQUIRE_HARDENED=true`), the app
**refuses to boot** unless all of these hold. Each maps to a concrete failure if skipped:

| Env var | Requirement | Why boot fails without it |
| --- | --- | --- |
| `WORKOS_CLIENT_ID` | non-blank | every login fails closed at runtime — a "healthy" boot that serves nothing |
| `WORKOS_API_KEY` | non-blank | same |
| `WORKOS_STRICT_VALIDATION` | `true` | else tokens verify on signature+expiry only — a token for another WorkOS client under the same key infra would pass |
| `WORKOS_ISSUER` | non-blank | strict validation with no issuer rejects **every** token |
| `WORKOS_AUDIENCE` | non-blank | same |
| `GATEWAY_REQUIRE_STABLE_KEY` | `true` (+ `GATEWAY_PRIVATE_KEY`) | ephemeral key rotates the engine's trust anchor each restart → intermittent auth outages |
| `ALLOWED_ORIGINS` | no `localhost` / open `*` | the gateway is the fleet's CORS terminator and serves credentialed requests |
| `LUKE_AUTH_DEV_MODE` | `false` (default) | dev-mode enables the `X-Dev-User` / `/dev/token` impersonation backdoors |

A bounded pattern like `https://*.lukeflow.com` is a legitimate origin (tenant
subdomains, the public embed surface) and is **not** flagged — only a host of exactly
`*` is.

Dev-mode has a second, independent gate: `DevModeGuard` requires the `dev` profile, so a
single stray `LUKE_AUTH_DEV_MODE=true` can never open the backdoors under any other profile.

## Full setting reference

Defined in `application.yml` with env-var overrides. Grouped by area:

- **`luke.auth.core-engine.base-url`** (`CORE_ENGINE_URL`) — upstream every `/api/**` proxies to.
- **`luke.auth.file-proxy.base-url`** (`FILE_PROXY_URL`) — blank ⇒ `/api/documents/**` falls through to core.
- **`luke.auth.workos.*`** — `client-id`, `api-key`, `api-base-url`, `jwks-url`, `issuer`,
  `audience`, `strict-validation`, `redirect-uri`, `ui-callback-url`, `cookie-secure`,
  `cookie-same-site`, `mark-email-verified-on-register`.
- **`luke.auth.gateway.*`** — `private-key`, `require-stable-key`, `previous-public-key`
  (rotation, see `docs/key-rotation.md`), `issuer`, `audience`, `ttl-seconds`.
- **`luke.auth.session.*`** — `cache-ttl-seconds`, `cache-max-entries`.
- **`luke.auth.ratelimit.*`** — `max-requests`, `window-seconds`, `max-keys`, `trusted-proxy-hops`,
  and **`redis-url`** (`REDIS_URL`). Blank ⇒ the limiter is in-memory and **per-instance** (limits
  reset on restart and don't hold across replicas). Set `REDIS_URL` (e.g. `redis://host:6379`) to
  enforce the credential-endpoint limit **globally** across all gateway replicas (#56). It fails
  safe: if `REDIS_URL` is set but Redis is unreachable — at boot or at request time — the limiter
  degrades to in-memory rather than failing the request or the boot.
- **`luke.auth.service.*`** — `keys`, `operator-token` (service accounts; see `application.yml`).
- **`luke.auth.onboarding.*`** — optional self-service provisioning into core-engine.
- **`luke.auth.upstream.*`** — `max-attempts`, `retry-backoff-ms` (resilience, #23).
- **`luke.auth.proxy.max-request-bytes`** — request-body cap → 413 (#21).
- **`luke.cors.allowed-origins`** (`ALLOWED_ORIGINS`) — credentialed-surface origin allowlist.

> Note: `LukeAuthProperties`/`LukeCorsProperties` are the validated source of truth for the
> security-critical invariants above. Several components still read their own settings via
> constructor `@Value` (each has a unit-test seam that injects the value directly). Those reads
> bind the **same** keys the typed properties validate, so there is no drift — the guard is the
> one place that decides what "correctly configured for prod" means.
