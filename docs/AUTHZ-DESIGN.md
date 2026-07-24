# Authorization Design — auth-engine as a stateless permission translator

> Status: **decided 2026-06-05** (6 decisions below). `luke-auth-engine` gets no
> database. It verifies identity, *asks* the systems that own the truth what a
> user can do, combines the answer for the UI, and vouches for the user to those
> systems — nothing more.
>
> **Update:** the human-authentication provider is now **WorkOS** (the engine
> verifies WorkOS access tokens and namespaces identities as `workos:<sub>`).
> "Clerk" below is historical — the *translator* design is unchanged; only the
> upstream identity provider differs.

## The two things this must do

1. **Derive** what a signed-in user is allowed to do across **Camunda** (org /
   process / task) and **Capabilities** (Forms, more later), and **hand that back
   to the UI** so it shows only the actions the user actually has.
2. **Vouch** for the user **server-to-server** so each system can enforce its own
   rules — *without `auth-engine` storing any of it.*

## Decisions (resolved)

| # | Question | Decision |
|---|---|---|
| 1 | Where does "can edit Forms" live? | **The capability service** — each feature owns its own access list. |
| 2 | View vs edit for Camunda roles? | **Camunda's built-in permissions** — the engine enforces them itself. |
| 3 | Does the middle layer have its own rulebook? | **No — pure translator.** Asks both services, combines. (No Casbin.) |
| 4 | How do robots/service accounts log in? | **Their own key** — Clerk for humans, key door for machines. |
| 5 | Active org when a user has several? | **User picks (switcher), auth-engine verifies** membership. |
| 6 | How fresh must access changes be? | **Within ~1 minute** — cache derived permissions ≈30–60s. |

## Core principle: derive, never store

`auth-engine` is a **stateless translator**. It already verifies Clerk and mints
the act-as-user token; we extend it to *compose* a permission view by reading the
systems that own the truth, and to cache that view in memory for ~60s
(cache ≠ database).

**Why no DB here:** every fact already has an owner. A copy in `auth-engine`
becomes a second source of truth that drifts the moment a membership or grant
changes elsewhere. A translator that *derives* is correct by construction.

## Who owns what (source-of-truth map)

| Concern | System of record | Enforces? |
|---|---|---|
| **Authentication** (who, session) | **Clerk** (humans) / **service keys** (robots) | — |
| **Org / Process / Task** access | **Camunda** (core-engine) via native authorizations | **yes, itself** |
| **Capability** access (Forms, future) | **capability-engine** (per-user/tenant grant) | **yes, itself** |
| Combining it for the UI + vouching | **auth-engine** | no — translates only |

Because Camunda and capability-engine each **enforce their own** rules, the
middle layer holds no policy: it asks, combines, and reports.

## The role model

### Camunda — 3 roles × {READ, READ-WRITE}, enforced by the engine

| Role | Meaning | READ | READ-WRITE |
|---|---|---|---|
| **Tenant User** | belongs to the Org (tenant) | see org resources | manage org-level settings/members |
| **Process User** | start / interact with processes (mostly **service accounts**) | view definitions & instances | start, signal, modify, cancel |
| **Task User** | act on tasks for their **candidate group** — **ABAC** (sales, accounting…) | view tasks in their group | claim / complete / edit those tasks |

View-vs-edit is expressed as **Camunda authorizations** (`READ` vs
`CREATE/UPDATE` on `ProcessInstance` / `Task`), so the engine refuses a
disallowed action at the source — even on a direct call. Task ABAC is native
(candidate groups). `auth-engine` only *reads* these to tell the UI.

### Capabilities — {READ, READ-WRITE} per capability, owned by capability-engine

| Capability | READ | READ-WRITE |
|---|---|---|
| **Forms** | view forms & versions | create / edit / version / publish / retire |
| *(future)* | … | … |

The per-user grant + its level live in **capability-engine**; it enforces its own
forms routes from the verified user + tenant. New capabilities slot in with the
same read/read-write shape.

## How `auth-engine` derives access (per session, cached ~60s)

```
Human:  UI ──Clerk JWT──▶ auth-engine
Robot:  svc ──API key────▶ auth-engine
                     │ 1. authenticate (verify Clerk JWT  |  verify service key)
                     │ 2. active tenant: UI-supplied → VALIDATE against memberships
                     │ 3. mint act-as token for that user + validated tenant
                     │ 4. core-engine     → user's Camunda authorizations + roles  [Camunda enforces]
                     │ 5. capability-engine→ user's capability access (forms: rw)   [capability enforces]
                     │ 6. combine into one permission view   (no rules of its own)
                     ├─ 7a. RETURN to UI: { tenant, roles, permissions }  ← "what can I do"
                     └─ 7b. act-as token carries verified { sub, tenant } ← downstream re-checks itself
```

The act-as token asserts **identity + validated tenant**; it does not need to
carry permissions, because each downstream system looks up and enforces its own
from the verified user. (Roles may ride along as a hint to save a lookup, but
enforcement never depends on the token's word.)

### What the UI receives (illustrative)

```json
{
  "userId": "workos:user_2abc",
  "tenant": "t-acme",
  "tenants": ["t-acme", "t-globex"],
  "camunda":      { "tenantUser": "read-write", "processUser": "none",
                    "taskUser": "read", "candidateGroups": ["sales"] },
  "capabilities": { "forms": "read-write" },
  "can": ["forms:read", "forms:write", "task:read", "org:read", "org:write"]
}
```

## What each service does (concrete implications)

- **auth-engine** — add a **service-key ingress** (robots) beside the Clerk
  ingress; a `/session` (or `/me/permissions`) endpoint that derives + returns
  the view above; **validate** the UI-supplied active tenant against membership;
  a ~60s in-memory cache. No DB, no Casbin.
- **core-engine / Camunda** — configure **authorizations** for the 3 roles
  (READ vs CREATE/UPDATE); expose the caller's effective authorizations +
  tenants for `auth-engine` to read (extends the existing `/api/me`).
- **capability-engine** — add a **per-user/tenant capability grant** (Forms:
  read | read-write) + a read endpoint "what can this user do here," and enforce
  its forms routes from the verified user + tenant.

## Implementation order

Build the **owners** first (they hold + enforce the access), then the
**translator** that reads them, then **downstream hardening**, then **UI**. Steps
1 and 2 are independent and can go in parallel. Each step is testable on its own.

| # | Service | What | Depends on | Done when |
|---|---|---|---|---|
| **1** | capability-engine | Per-user/tenant **capability grant** (Forms: read \| read-write) + `GET /api/my-capabilities` read endpoint; **enforce** forms routes by level from verified user+tenant | forms module (built) | a user with `read` is refused a write route; `my-capabilities` returns their level |
| **2** | core-engine | Configure **Camunda authorizations** for the 3 roles (READ vs CREATE/UPDATE on ProcessInstance/Task); extend `/api/me` to return the caller's **effective permissions + tenants + candidate groups** | — | `/api/me` returns `{ tenantUser, processUser, taskUser, candidateGroups, tenants }` |
| **3** | auth-engine | `GET /session` **translator**: verify Clerk → mint act-as → call #2 + #1 → combine → return the permission view; **validate** UI-supplied active tenant against memberships; **~60s cache** | 1, 2 | `/session` returns the merged `{ tenant, roles, capabilities, can[] }`; bad tenant rejected |
| **4** | capability-engine + core-engine | Verify the **gateway act-as token** (resource-server vs gateway JWKS); derive user+tenant from the **verified token**, drop trust in raw `X-Tenant-Id` | 3 | a forged `X-Tenant-Id` no longer works; identity comes from the signed token |
| **5** | consumer-ui | Call `/session` after login; **gate** buttons/routes by `can[]`; **org switcher** (re-fetch on switch); `getToken()` per-request interceptor + 401-retry | 3 | UI shows only allowed actions; switching org re-derives; tokens never go stale |
| **6** | auth-engine | **Service-key ingress** for robots/service accounts (key → service token), separate from the Clerk path | 3 | a service account authenticates with a key and gets a scoped token |

Why this order: #1 and #2 make the two systems that *own and enforce* access
ready to be queried; #3 is the translator that can't exist until they answer; #4
closes the header-spoofing gap once a signed token flows; #5 consumes it; #6 adds
the machine path last (humans first).

## Why this meets your constraints

- **No DB in `auth-engine`** — it derives + caches in memory; state stays with
  its owner.
- **Forwarder / middle layer** — ingests the credential (Clerk or key), does the
  server-to-server hops, returns roles+permissions to the UI.
- **Relies on Camunda + Capabilities for state** — they remain the systems of
  record *and* the enforcers; `auth-engine` only translates and vouches.
