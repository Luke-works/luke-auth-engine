# Social login (WorkOS) — setup runbook

Social sign-in is handled entirely by **WorkOS User Management (AuthKit)**. The luke-auth
gateway only builds the authorize URL and completes the callback — it stores no passwords
and holds no provider secrets.

## How the flow works

1. UI button calls `GET /auth/social?provider=<alias>` (consumer-ui `SignInForm` / `SignUpForm`).
2. `AuthController.social` maps the friendly alias → WorkOS provider and 302-redirects to
   WorkOS `/user_management/authorize` with a CSRF `state` nonce (stored in a short-lived
   HttpOnly cookie).
3. WorkOS runs the provider handshake and redirects back to `luke.auth.workos.redirect-uri`
   (`WORKOS_REDIRECT_URI`) → `GET /auth/callback`, which verifies `state`, exchanges the code,
   and establishes the session via the `wos_refresh` HttpOnly cookie.

### Provider aliases (already wired in `AuthController.PROVIDERS`)

| UI alias    | WorkOS provider   | Status |
|-------------|-------------------|--------|
| `google`    | `GoogleOAuth`     | wired  |
| `microsoft` | `MicrosoftOAuth`  | wired  |
| `github`    | `GitHubOAuth`     | wired  |
| `apple`     | `AppleOAuth`      | wired  |
| `authkit`   | `authkit`         | wired  |

> **Facebook is NOT a WorkOS social-login provider.** WorkOS AuthKit supports only
> Google, Microsoft, GitHub, Apple (+ SSO guides for GitLab/LinkedIn/Slack). The only
> WorkOS-native path for Facebook is a *generic OIDC SSO connection*, which is the
> enterprise-SSO flow (connection-scoped, different code path) — intentionally NOT built.
> Parked. See https://workos.com/docs/user-management/social-login

## Enabling "Sign in with Microsoft"

The **code is already complete** (buttons + provider alias + authorize URL + callback).
Only dashboard configuration remains:

1. **Microsoft Entra ID (Azure portal)** → *App registrations* → *New registration*.
   - Record the **Application (client) ID**.
   - *Certificates & secrets* → create a **client secret** (record its value).
   - *Authentication* → add the **Redirect URI** WorkOS shows in step 2
     (typically `https://api.workos.com/sso/oauth/microsoft/callback`).
2. **WorkOS dashboard** → *Authentication* → enable **Microsoft OAuth** for User Management,
   and paste the Azure **Client ID + Secret**.
   - *(WorkOS ships shared Microsoft creds for dev/staging, so dev/qa may work as soon as
     the toggle is on; production requires your own Azure app as above.)*
3. **WorkOS** → *Redirect URIs* — allow the gateway callbacks (`WORKOS_REDIRECT_URI` per env):
   - dev: `https://authdev.lukeflow.com/auth/callback`
   - qa:  `https://authqa.lukeflow.com/auth/callback`
   - prod: `https://auth.lukeflow.com/auth/callback` (when prod is stood up)
4. **Test** on qa: the "Sign in with Microsoft" button should complete the round-trip and
   land back authenticated.

No env var or code change is required in this repo to turn Microsoft on — it is gated only
by the WorkOS-side configuration above.
