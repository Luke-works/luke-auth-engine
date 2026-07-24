# User deprovisioning (SCIM / directory-sync)

Status: **partial (#38)** — the webhook and the gateway-local half are built; the
cross-service half needs a decision.

## What's built

`POST /webhooks/workos` — a signature-verified WorkOS webhook.

- **Signature:** HMAC-SHA256 over `"<t>.<rawBody>"` from the `WorkOS-Signature`
  header (`t=…, v1=…`), checked in constant time with a 5-minute replay window
  (`WorkosWebhookVerifier`).
- **Disabled by default:** with no `WORKOS_WEBHOOK_SECRET` set (dev/qa), the endpoint
  returns 404 — nothing to boot-break, nothing to trust.
- **On `user.deleted`:** the gateway immediately invalidates its cached authorization
  view for `workos:<id>` and audits `user.deprovision`. This closes the window where a
  removed user's cached session was honored for the cache TTL.
- **On `dsync.*`:** acknowledged and audited as `pending` (see below).

## What still needs a decision

The full joiner-mover-**leaver** loop isn't closed yet, because the last steps leave
the stateless gateway's authority:

1. **Remove engine membership.** Deprovisioning a user the gateway isn't acting *as*
   requires an **operator-authenticated** call to core-engine to remove that user's
   membership by id. core-engine has no such endpoint today (it has self-service
   `/api/me/account` and operator onboarding, not operator "remove user X"). Decision:
   add an operator deprovision endpoint in core-engine, and give the gateway an operator
   credential (or route the webhook to core directly).

2. **Revoke the WorkOS session / refresh token.** WorkOS is the session system of record;
   revoking a removed user's live session/refresh token is a WorkOS Management API call.
   Decision: which call, and with what credential.

3. **Directory Sync (dsync.*) mapping.** dsync events identify a *directory* user, which
   must be mapped to the platform (WorkOS User Management) user before we can act. This
   depends on the enterprise's **WorkOS Directory Sync** setup — a product/onboarding
   decision (Directory Sync is a paid WorkOS capability), not just code.

## Recommended next step

Enable WorkOS Directory Sync for a pilot enterprise tenant; add the core-engine operator
deprovision endpoint (#38 continues there); then wire steps 1–2 into this handler behind
the same signature gate. The gateway-local cache invalidation already shipped is
forward-compatible — it stays correct once the rest lands.
