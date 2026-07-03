# Audit trail (auth-engine)

auth-engine emits a structured audit trail for authentication and privileged actions
(#24). It is the stateless gateway (no database), so the trail is a dedicated SLF4J
logger — **`luke.audit`** — not a table.

## What is recorded

One `key=value` line per event via `AuditService`:

```
action=<event> outcome=success|failure|denied actor=<id> target=<id> tenant=<id> ip=<src> cid=<correlationId>
```

Events: `auth.register`, `auth.login`, `auth.refresh`, `auth.logout`,
`auth.profile_change`, `auth.password_change`, `auth.account_delete`, `org.invite`,
`org.invite_revoke`, `org.member_add`, `org.member_add_invited`, `service.token`.

Each line also carries the correlation id via the logging pattern (`[cid:…]`) **and** as
a `cid=` field, so it stays self-contained if parsed in isolation, and ties back to the
full request trace across the gateway → core-engine hop.

## Where it goes (separability + retention)

The `luke.audit` logger is INFO and writes to stdout like all logs, but is **isolable by
logger name**: filter the platform log store for `luke.audit` to get only the audit
trail. On Render, stdout is shipped to the retained log store — that store's retention
window is the audit retention. For long-term/tamper-evident retention or SIEM ingest,
ship `luke.audit` lines to a dedicated WORM/retained sink (e.g. an S3-backed log archive
or SIEM) via the log pipeline; no app change is required (filter on the logger name).

## PII & redaction policy

The only PII in the trail is **email addresses**, and only on identity-lifecycle events
(`auth.register`, `auth.login`, `org.invite`, `org.member_add*`) where the email is the
audit subject. No passwords, tokens, or secrets are ever logged. `actor`/`target` are
opaque engine user ids elsewhere.

- **Retention:** follows the log-store policy (set it to satisfy your compliance window,
  e.g. 1 year for SOC2). Document the configured window where the sink is provisioned.
- **Redaction:** if email must not be retained long-term, redact/hash the `target` field
  at the log-pipeline stage for `action=auth.*`/`org.*` past the active-investigation
  window, rather than dropping the event (keep the who/when/outcome).

## Not yet covered (follow-ups)

- Per-request act-as mints in the proxy (`EngineProxyController`) are **not** in this
  trail — that is one mint per API call (access-log volume); it is traceable via the
  correlation id instead. A sampled/separate impersonation-access stream is a follow-up.
