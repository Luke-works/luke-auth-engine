# luke-auth-engine

Consumer-facing **auth gateway** for the Luke platform. It sits between
`luke-consumer-ui` and `luke-core-engine`:

1. **Authenticates** the caller by verifying their **Clerk** JWT.
2. **Resolves** the Clerk subject to an engine userId (`clerk:<sub>`).
3. **Mints** a short-lived, signed *act-as-user* token (RS256).
4. **Proxies** the request transparently to `luke-core-engine`, which performs
   **authorization** against that user's CIBSeven groups/tenants.

The powerful act-as-user token never reaches the browser — the gateway is in
the path for every request, so the only token the browser holds is its own
Clerk session token. `luke-core-ui` continues to talk to the engine directly
over HTTP Basic and does not go through this service.

```
consumer-ui --Clerk JWT--> luke-auth-engine --act-as-user JWT--> luke-core-engine
                                  |                                     ^
                          verify Clerk (JWKS)                  verify gateway (JWKS)
                          mint signed token                    setAuthentication(user)
```

## Configuration

| Env var | Purpose |
|---|---|
| `CORE_ENGINE_URL` | Upstream engine base URL the gateway proxies to |
| `CLERK_JWKS_URL` | Clerk instance JWKS endpoint (verifies consumer tokens) |
| `CLERK_ISSUER` | Expected Clerk issuer |
| `CLERK_AUDIENCE` | Optional — required audience claim |
| `ALLOWED_ORIGINS` | CORS origin(s) of the consumer UI |
| `GATEWAY_PRIVATE_KEY` | PEM PKCS#8 RSA key for signing. If unset, an ephemeral key is generated per boot (the `kid` is derived from its thumbprint, so the engine refetches the JWKS after a restart). |

The engine verifies this service's tokens via its published JWKS at
`/.well-known/jwks.json`; set `LUKE_AUTH_GATEWAY_ENABLED=true` and
`LUKE_AUTH_GATEWAY_JWKS_URL` on `luke-core-engine`.

## Build & run

```bash
./mvnw spring-boot:run          # local, port 8083
./mvnw clean package            # jar
docker build -t luke-auth-engine .
```

Spring Boot 3.4.4 / Java 21. Deployed as a Docker web service on Render (see
`luke-platform/render.yaml`, the `platform-*-auth` services).
