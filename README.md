# luke-auth-engine

Consumer-facing **auth gateway** for the Luke platform. It sits between
`luke-consumer-ui` and `luke-core-engine`:

1. **Authenticates** the caller by verifying their **WorkOS** access token (JWKS),
   or by running the WorkOS login flows itself (`/auth/*`).
2. **Resolves** the WorkOS subject to an engine userId (`workos:<sub>`).
3. **Mints** a short-lived, signed *act-as-user* token (RS256).
4. **Proxies** the request transparently to `luke-core-engine`, which performs
   **authorization** against that user's FluxNova groups/tenants.

The powerful act-as-user token never reaches the browser — the gateway is in
the path for every request, so the only token the browser holds is its own
WorkOS access token. `luke-core-ui` continues to talk to the engine directly
over HTTP Basic and does not go through this service.

```
consumer-ui --WorkOS access token--> luke-auth-engine --act-as-user JWT--> luke-core-engine
                                            |                                     ^
                                    verify WorkOS (JWKS)                 verify gateway (JWKS)
                                    mint signed token                    setAuthentication(user)
```

The gateway is **stateless** — no database. Authorization is read live from
core-engine and cached in-memory per `(user, tenant)` for a short TTL. See
`docs/AUTHZ-DESIGN.md`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/auth/register` | WorkOS user + optional core-engine provisioning |
| `POST` | `/auth/login` | email/password → session |
| `GET`  | `/auth/social` | begin a social/SSO login (redirect to WorkOS) |
| `GET`  | `/auth/callback` | WorkOS redirect target → sets refresh cookie |
| `POST` | `/auth/refresh` | refresh-cookie → new access token |
| `POST` | `/auth/logout` | revoke + clear the session |
| `POST` | `/auth/password` | change password |
| `DELETE` | `/auth/account` | delete the user (cascades engine cleanup) |
| `POST`/`GET` | `/auth/org/invitations` | org-admin: invite / list |
| `POST` | `/auth/org/invitations/{id}/revoke` | org-admin: revoke an invite |
| `POST` | `/auth/org/members` | org-admin: add an existing user |
| `GET`  | `/session` | the merged `{ tenant, roles, capabilities, can[] }` view the UI calls per login / tenant-switch |
| `POST` | `/service/token` | service account: `X-Service-Key` → act-as token |
| `POST` | `/service/keys/{keyId}/revoke` · `/unrevoke` | operator: live key revocation (`X-Operator-Token`) |
| `GET`  | `/.well-known/jwks.json` | the gateway's public keys (core verifies act-as tokens against this) |
| `*`    | `/api/**` | authenticated reverse-proxy to core-engine (mints + injects the act-as token) |

Full request/response shapes, headers and status codes: **`docs/API.md`**.
The uniform error body: **`docs/ERRORS.md`**.
A machine-readable **OpenAPI** document is served at **`/v3/api-docs`** (unauthenticated; describes
endpoint shapes only).

## Configuration

**`docs/CONFIGURATION.md` is the complete reference** — every setting, its default,
and the production checklist. The essentials:

| Env var | Purpose | Prod |
|---|---|---|
| `CORE_ENGINE_URL` | upstream engine base URL the gateway proxies to | required |
| `WORKOS_CLIENT_ID` | WorkOS client id (also derives the default JWKS url) | required |
| `WORKOS_API_KEY` | WorkOS secret API key (login flows are server-to-server) | required |
| `WORKOS_ISSUER` / `WORKOS_AUDIENCE` | expected token claims | required (strict) |
| `WORKOS_STRICT_VALIDATION` | require issuer+audience binding, not expiry-only | `true` |
| `WORKOS_JWKS_URL` | override the JWKS endpoint (defaults to `<api-base>/sso/jwks/<client-id>`) | optional |
| `WORKOS_REDIRECT_URI` / `WORKOS_UI_CALLBACK_URL` | social-login redirect targets | required for SSO |
| `GATEWAY_PRIVATE_KEY` | PEM PKCS#8 RSA key for signing act-as tokens (unset ⇒ ephemeral per boot) | required |
| `GATEWAY_REQUIRE_STABLE_KEY` | refuse to boot on an ephemeral key | `true` |
| `ALLOWED_ORIGINS` | CORS origin(s) of the consumer UI (no localhost/wildcard in prod) | required |
| `ONBOARDING_*` | optional self-service provisioning into core-engine at register | optional |
| `LUKE_AUTH_SERVICE_KEYS` | `key=userId` pairs for service accounts (may be hashed / carry `;exp=` / `;scope=`) | optional |
| `LUKE_AUTH_SERVICE_OPERATOR_TOKEN` | enables the live key-revocation endpoints | optional |
| `LUKE_AUTH_DEV_MODE` | auth backdoors — **local only**, also requires the `dev` profile | must be `false` |

Under `SPRING_PROFILES_ACTIVE=...,prod` the app **refuses to boot** unless the
required-in-prod settings above are all set (see `AuthHardeningGuard`). dev/qa run
without the `prod` profile and stay lenient.

The engine verifies this service's tokens via its published JWKS at
`/.well-known/jwks.json`; set `LUKE_AUTH_GATEWAY_ENABLED=true` and
`LUKE_AUTH_GATEWAY_JWKS_URL` on `luke-core-engine`.

## Build & run

```bash
./mvnw spring-boot:run          # local, port 8083
./mvnw clean package            # jar
./mvnw test                     # unit + functional (H2/no external deps)
docker build -t luke-auth-engine .
```

Spring Boot 3.4 / Java 21. Deployed as a Docker web service on Render (see
`luke-platform/render.yaml`, the `platform-*-auth` services).

## Documentation

This repo is also documented in the **luke-docs** manual
(`Luke-works/luke-docs` → `services/auth-engine.md`). Doc-visible changes must
update that page in the same PR — see `CLAUDE.md`.
