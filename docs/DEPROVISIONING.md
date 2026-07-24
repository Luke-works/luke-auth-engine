# User deprovisioning (SCIM / directory-sync)

Status: **the `user.deleted` leaver loop is closed (#38).** Directory-Sync (`dsync.*`)
mapping remains, gated on the WorkOS Directory Sync setup.

## The flow

`POST /webhooks/workos` — a signature-verified WorkOS webhook.

- **Signature:** HMAC-SHA256 over `"<t>.<rawBody>"` from the `WorkOS-Signature`
  header (`t=…, v1=…`), checked in constant time with a 5-minute replay window
  (`WorkosWebhookVerifier`).
- **Disabled by default:** with no `WORKOS_WEBHOOK_SECRET` set (dev/qa), the endpoint
  returns 404 — nothing to boot-break, nothing to trust.
- **On `user.deleted`:**
  1. the gateway invalidates its cached authorization view for `workos:<id>` immediately
     (closing the cache-TTL window), then
  2. calls core-engine's operator `POST /api/admin/deprovision-user` (operator Basic auth
     via `ONBOARDING_OPERATOR_USER`/`_PASSWORD`) to remove the user's tenant + group
     memberships, delete the engine user, purge capability grants, and delete any tenant
     they solely owned — the same cleanup as self-service account deletion, shared via
     core-engine's `UserDeprovisioningService`.
  3. audits `user.deprovision`.
  If the engine call fails (core unreachable), the handler returns **500** so WorkOS
  retries — both steps are idempotent, so a retry is safe.
- **Token revocation:** none is needed for `user.deleted` — WorkOS has already invalidated
  the deleted user's sessions and refresh tokens as part of the deletion.
- **On `dsync.*`:** acknowledged and audited as `pending` (see below).

## What still needs the WorkOS Directory Sync setup

**Directory-Sync (`dsync.*`) mapping.** dsync events identify a *directory* user, which
must be mapped to the platform (WorkOS User Management) user before we can act. That
mapping depends on the enterprise's **WorkOS Directory Sync** configuration (a paid WorkOS
capability). Once Directory Sync is enabled for a tenant, deactivation events map to a
platform user and can reuse the exact same path as `user.deleted` above — invalidate cache
→ `deprovision(engineUserId)` → audit. The plumbing is in place; only the event→user
mapping is pending.

## Configuration

| Env var | Purpose |
|---|---|
| `WORKOS_WEBHOOK_SECRET` | WorkOS dashboard → Webhooks signing secret. Blank ⇒ endpoint disabled (404). |
| `ONBOARDING_OPERATOR_USER` / `ONBOARDING_OPERATOR_PASSWORD` | operator credential the deprovision call authenticates with (same as onboarding). Without it, the webhook still invalidates the cache but logs that engine removal was skipped. |
