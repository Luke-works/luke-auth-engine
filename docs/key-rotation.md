# Gateway signing-key rotation

The gateway signs short-lived **act-as-user** tokens with an RSA private key
(`GATEWAY_PRIVATE_KEY`, PKCS#8 PEM). `luke-core-engine` verifies them against the
public key published at `/.well-known/jwks.json`, matched by `kid` (the key's RFC
7638 thumbprint). Rotating the key naively causes an outage: the engine briefly
sees tokens signed by an unknown `kid`. The `previous-public-key` overlap window
makes rotation **zero-downtime**.

## Production requirements
- Set `GATEWAY_PRIVATE_KEY` to a stable, secret-managed PKCS#8 PEM (never plaintext
  in source). Set `GATEWAY_REQUIRE_STABLE_KEY=true` so the app **refuses to boot**
  on an ephemeral key.
- `GATEWAY_TTL_SECONDS` (default 60) is the act-as token lifetime — the overlap
  window only needs to exceed this.

## Generate a new keypair
```sh
# New private key (PKCS#8 PEM) — keep secret, store in the secret manager.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out new-private.pem
# Its public key (X.509 SubjectPublicKeyInfo PEM) — used as the overlap public key.
openssl rsa -in new-private.pem -pubout -out new-public.pem
```

## Rotation steps (zero downtime)
1. **Stage the overlap.** Before switching, capture the *current* key's public PEM
   (the one matching today's `GATEWAY_PRIVATE_KEY`). You'll publish it as the
   previous key after the swap so in-flight tokens still verify.
2. **Promote the new key.** Set `GATEWAY_PRIVATE_KEY` = `new-private.pem` and
   `GATEWAY_PREVIOUS_PUBLIC_KEY` = the **old** key's public PEM. Deploy.
   - The gateway now signs with the new `kid` and publishes **both** public keys
     in the JWKS, so the engine verifies tokens signed by either key.
3. **Wait out the TTL.** After `GATEWAY_TTL_SECONDS` (plus a safety margin), no
   tokens signed by the old key remain valid.
4. **Retire the old key.** Unset `GATEWAY_PREVIOUS_PUBLIC_KEY` and redeploy. The
   JWKS now publishes only the new key.

## Notes
- The `kid` is derived automatically from each key's thumbprint — you never set it
  by hand, and a given key always maps to the same `kid`.
- Source key material from the platform secret store; avoid plaintext env where the
  platform supports secret files/refs.
