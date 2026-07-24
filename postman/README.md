# Postman — Engine via Auth Gateway

Exercises `luke-core-engine` resources **through** `luke-auth-engine` (the consumer gateway), plus the operator-only admin endpoints that go **directly** to the engine.

## Files
- `luke-engine-via-gateway.postman_collection.json` — the collection
- `local.postman_environment.json` — localhost (auth `:8083`, engine `:8080`)
- `platform-dev.postman_environment.json` — the dev cloud env

## Import
Postman → Import → drop all three files. Pick an environment (top-right).

## Set two values before you start

> Auth is **WorkOS** now. The two env variables are still named `clerkJwt` / `clerkSub`
> for legacy reasons (renaming them would touch the whole collection) — they hold the
> **WorkOS access token** and its `sub`.

1. **`clerkJwt`** — a live WorkOS access token. Sign into the consumer UI, then read it
   from the browser: the token the app holds is sent on every `/api` call, so copy the
   `Authorization: Bearer …` value from a request in the **Network** tab (or from app
   storage). Tokens are short-lived — re-fetch on `401`.
2. **`clerkSub`** — the `sub` claim of that token (the WorkOS user id, e.g. `user_2abc…`).
   Decode the JWT at jwt.io.

## Order of operations
1. **`0 · Setup & Health`** — confirm gateway + engine are up and JWKS is served.
2. **`8 · Engine Admin (DIRECT)` → Onboard User** — provision your WorkOS user once (operator Basic auth). Without this the gateway returns **403 not provisioned**. Set `tenantId` to an existing tenant first (create one with *Create tenant*).
3. **`1 · Identity` → Who am I** — verifies the WorkOS → engine identity mapping; auto-captures your first `tenantId`.
4. **`2–7`** — process definitions, instances, tasks, deployments, decisions, history. Requests chain via captured variables (`processDefinitionId`, `processInstanceId`, `taskId`, `deploymentId`).
5. **`9 · Auth behavior checks`** — proves the gate (no token → 401; Basic to gateway → 401).

## Two auth modes (important)
| Calls | Base URL | Auth |
|---|---|---|
| Runtime/consumer (folders 1–7) | `{{authBaseUrl}}` (gateway) | `Bearer {{clerkJwt}}` (WorkOS access token) |
| Operator/admin (folder 8) | `{{engineBaseUrl}}` (engine) | Basic `{{operatorUser}}/{{operatorPass}}` |

The gateway only accepts WorkOS Bearer tokens, so admin/onboarding (Basic) must bypass it and hit the engine directly. For cloud envs, the engine's admin password is `generateValue` on Render — copy it from the dashboard into `operatorPass`.
