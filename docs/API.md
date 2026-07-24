# API reference

The gateway's HTTP surface. All errors share one body — see `ERRORS.md`. Every
response carries `X-Correlation-Id` (echoing an inbound one or generated).

Authentication is a **WorkOS access token** as `Authorization: Bearer <token>`,
except where noted (the `/auth/*` entry points that establish a session, the
public passthrough, and the service-key / operator surfaces).

## Headers

| Header | Direction | Meaning |
|---|---|---|
| `Authorization: Bearer <workos-token>` | in | the authenticated caller (WorkOS access token) |
| `X-Tenant-Id` | in | the active tenant (org switcher). Validated against the caller's memberships; a tenant the user doesn't belong to → `403`. |
| `X-Service-Key` | in | service-account credential on `POST /service/token` |
| `X-Operator-Token` | in | operator credential on the `/service/keys/*` revocation endpoints |
| `X-Correlation-Id` | in/out | request trace id; forwarded to core-engine so a trace spans the hop |
| `Set-Cookie` (refresh) | out | httpOnly refresh cookie set by login/register/callback/refresh |

Identity/trust headers a client might try to send (`X-User-Id`, …) are **not**
accepted — the gateway asserts identity via the minted act-as token and strips them.

## Auth flows — `/auth/*`

These establish or mutate a session; they do not require an inbound Bearer token
unless they act on an existing user.

| Endpoint | Body / params | Success | Notable errors |
|---|---|---|---|
| `POST /auth/register` | `{email, password, firstName?, lastName?}` | `201` `{userId, workosUserId, user, verifyRequired}` | `4xx` from WorkOS passes through (e.g. "Email already in use"); provisioning failure → `502` |
| `POST /auth/login` | `{email, password, tenant?}` | `200` session `{tenant, roles, capabilities, can[], user, sid}` | bad credentials → the WorkOS `4xx` |
| `GET /auth/social?provider=&tenant=` | query | `302` to WorkOS | — |
| `GET /auth/callback?code=` | query | `302` to the UI callback with the access token | invalid code → `302` with error |
| `POST /auth/refresh` | refresh cookie | `200` new session | missing/expired cookie → `401` |
| `POST /auth/logout` | refresh cookie | `200` `{ok:true}` | — |
| `POST /auth/password` | Bearer + `{currentPassword, newPassword}` | `200` | WorkOS `4xx` |
| `DELETE /auth/account` | Bearer | `200` | engine cleanup failure → `502` |

### Org admin (Bearer must be a tenant-admin of `X-Tenant-Id`)

| Endpoint | Purpose | Non-admin |
|---|---|---|
| `POST /auth/org/invitations` `{email}` | invite to the org | `403` |
| `GET /auth/org/invitations` | list pending invites | `403` |
| `POST /auth/org/invitations/{id}/revoke` | revoke an invite | `403` |
| `POST /auth/org/members` `{email, role?, accessLevel?}` | add an existing platform user | `403` |

> `POST /auth/org/members` returns the **same** `{ok:true}` whether the email was a
> known platform user (added) or not (invited) — deliberately, so it can't be used to
> enumerate who has an account (#31).

## Session — `GET /session`

The per-login / per-tenant-switch view.

- **Auth:** `Authorization: Bearer <workos-token>`; `X-Tenant-Id` selects the active tenant.
- **Query:** `fresh=true` bypasses the `(user,tenant)` cache (the UI sets it right after an access change).
- **200:** `{ tenant, tenantAdmin, roles[], capabilities{}, can[] }`.
- **401** missing/invalid token · **403** not a member of `X-Tenant-Id` · **502** a source of truth (core-engine) was unreachable.

## Service accounts — `/service/*`

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /service/token` | `X-Service-Key` | exchange a service key for a short-lived act-as token for its userId |
| `POST /service/keys/{keyId}/revoke` | `X-Operator-Token` | revoke a non-expired key with no redeploy (enabled only when the operator token is set) |
| `POST /service/keys/{keyId}/unrevoke` | `X-Operator-Token` | reverse a revoke |

`keyId` is the non-secret 8-char label that appears in the audit trail. Keys may be
stored SHA-256-hashed and carry `;exp=<epoch>` / `;scope=<csv>` — see `application.yml`.

A rejected or unknown service key returns a uniform `401`; a disabled revoke endpoint
(no operator token configured) returns `404`. Neither reveals whether the key exists.

## JWKS — `GET /.well-known/jwks.json`

Public. The gateway's RSA public key(s) so core-engine can verify the act-as tokens
it receives. Publishes the current key and, during rotation, the previous public key
(`GATEWAY_PREVIOUS_PUBLIC_KEY`) so both `kid`s verify — see `key-rotation.md`.

## Proxy — `/api/**`

Everything else is reverse-proxied to core-engine.

- **Authenticated by default.** The gateway verifies the Bearer token, mints an act-as
  token for the resolved user, and injects it upstream. No token → `401`.
- **Public passthrough:** `/api/public/**` (and `/embed*`) are forwarded **without** a
  token — they are token/HMAC-gated at core (embed/sign surface). The rule is a
  normalized allowlist, not a raw string prefix.
- **Request-body cap:** requests over `luke.auth.proxy.max-request-bytes` (default 100 MiB)
  → `413` (#21).
- Bodies stream through untouched (the service never parses them), preserving multipart
  uploads verbatim.
