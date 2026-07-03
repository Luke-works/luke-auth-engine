# Test Cases — luke-auth-engine (dev/qa)

These cover the gateway security fixes merged to `develop` (auto-deployed to **dev/qa**).
Run them against your **dev/qa** auth-engine URL.

## Before you start (setup once)
- Your dev/qa auth-engine URL — call it `AUTH` (e.g. `https://luke-auth-engine-dev.onrender.com`).
- A normal consumer login.
- A terminal for `curl`.

---

## ✅ Item 1 — Proxy ignores fake identity headers (PR #44)
**What changed:** a sneaky caller used to be able to add an `X-User-Id` header to *pretend to be someone else*. The gateway now ignores those headers; only the real login token decides who you are.

### Test 1a — pretending to be someone else does nothing
1. Log in normally and grab your access token (in the app: DevTools → Network → any request → `Authorization: Bearer …`). Call it `TOKEN`.
2. Make a normal request but try to impersonate user `victim`:
   ```
   curl -i "$AUTH/api/me/permissions" -H "Authorization: Bearer TOKEN" -H "X-User-Id: victim"
   ```
- ✅ **PASS:** the response is about **you**, not `victim` (the header was ignored).
- ❌ **FAIL:** it returns `victim`'s data → tell the dev.

### Test 1b — path traversal is blocked
1. Try to sneak to a protected page through the public door:
   ```
   curl -i "$AUTH/api/public/../me/permissions"
   ```
- ✅ **PASS:** `400 Bad Request` ("Malformed or traversing request path").
- ❌ **FAIL:** `200` with permissions data → tell the dev.

### Test 1c — real public embed still works
1. Open a real public form embed link (the `/api/public/render/<token>` your app uses).
- ✅ **PASS:** the form loads (no login needed), like before.
- ❌ **FAIL:** it breaks → tell the dev.

---

## ✅ Item 2 — Changing your password needs your current one (PR #45)
**What changed:** you used to be able to change a password without typing the old one. Now the old password is required.

### Test 2a — no current password = refused
1. ```
   curl -i -X POST "$AUTH/auth/password" -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" -d '{"newPassword":"NewPass123!"}'
   ```
- ✅ **PASS:** `400 Bad Request` ("currentPassword is required").
- ❌ **FAIL:** `200`/ok → tell the dev.

### Test 2b — wrong current password = refused
1. ```
   curl -i -X POST "$AUTH/auth/password" -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" -d '{"currentPassword":"WRONG","newPassword":"NewPass123!"}'
   ```
- ✅ **PASS:** `403 Forbidden` ("Current password is incorrect").

### Test 2c — correct current password = works
1. In the app's Change Password screen, enter the **correct** current password + a new one.
- ✅ **PASS:** it changes successfully.

---

## ✅ Item 3 — Social/SSO login is CSRF-protected (PR #45)
**What changed:** the social login round-trip now carries a secret "state" cookie that must match on return.

### Test 3a — normal social login still works  ⚠️ needs HTTPS
> The state cookie is `Secure`, so test on the real **https** dev/qa URL (not http://localhost).
1. Click "Sign in with Google" (or your provider) in the dev/qa app and finish login.
- ✅ **PASS:** you land logged-in like before.
- ❌ **FAIL:** you get bounced with `#error=invalid_state` on a *legit* login → the cookie isn't round-tripping; check the redirect is HTTPS and same site.

### Test 3b — a tampered return is rejected
1. Start a social login, then on the WorkOS screen, manually mess with the `state` value in the URL before it returns (or just confirm a stale/old callback link fails).
- ✅ **PASS:** redirected with `#error=invalid_state`.

---

## ✅ Item 4 — CORS only allows the headers we use (PR #46)
**What changed:** the gateway now allows a small list of request headers instead of "all headers."

### Test 4a — the app still works in the browser
1. Use the dev/qa consumer app normally (log in, open forms). Open DevTools → Console.
- ✅ **PASS:** no **CORS** errors in the console; the app works.
- ❌ **FAIL:** you see a CORS error mentioning a blocked header (e.g. `x-something`) → that header needs adding to the allowlist; tell the dev which header.

---

## Notes
- Deployed via PRs #44, #45, #46 (merged to `develop`).
- The riskiest to watch is **Item 3** (social login) — test it first if your app uses SSO.
