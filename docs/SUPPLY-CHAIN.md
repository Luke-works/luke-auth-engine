# Supply chain

How the container image is kept reproducible and vulnerability-scanned (#41).

## What's in place

- **Digest-pinned bases.** Both `FROM` lines in the `Dockerfile` pin an
  `image:tag@sha256:<digest>`. The digest is what resolves — the tag is kept only for
  readability — so a rebuild always pulls the exact same layers, and a repository that
  re-tags underneath us cannot silently change the build.
- **Controlled updates.** `.github/dependabot.yml` opens weekly PRs to bump the pinned
  Docker bases, the pinned GitHub Actions, and Maven dependencies. Pins stay current
  instead of rotting; a human reviews each bump.
- **SBOM per build.** CI generates a CycloneDX SBOM (`syft`) for the built image and
  uploads it as a build artifact (`sbom-auth-engine.cyclonedx.json`).
- **Gating CVE scan.** CI builds the image and runs `trivy image` against it, failing on
  a **fixable** HIGH/CRITICAL CVE (`--ignore-unfixed`). "Fixable" means a patched package
  version exists — so a freshly-disclosed CVE with no upstream fix can't permanently block
  delivery; Dependabot bumps the base once a fix lands. Continuous filesystem/dependency
  scanning also runs in `security-scan.yml`.

## How to update a base image

Prefer the Dependabot PR. To do it by hand, resolve the current multi-arch **index**
digest (not a per-arch one) and paste it into the `Dockerfile`:

```bash
repo=library/eclipse-temurin tag=21-jre   # or library/maven : 3.9-eclipse-temurin-21
tok=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -sI -H "Authorization: Bearer $tok" \
  -H "Accept: application/vnd.oci.image.index.v1+json" \
  "https://registry-1.docker.io/v2/${repo}/manifests/${tag}" \
  | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}'
```

## Signing & provenance (half A — shipped)

Every push to `develop`/`main` publishes a **signed, attested** image to GHCR via
`.github/workflows/image-publish.yml`:

- **Registry:** `ghcr.io/luke-works/luke-auth-engine`, tagged by branch + `sha-<commit>`.
- **Signature:** `cosign sign`, **keyless** — the workflow's OIDC identity is bound into a
  short-lived Sigstore certificate (no keys to manage/rotate). Verify with:
  ```bash
  cosign verify ghcr.io/luke-works/luke-auth-engine@sha256:<digest> \
    --certificate-identity-regexp 'https://github.com/Luke-works/luke-auth-engine/.*' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```
- **Provenance:** an SLSA build-provenance attestation (`actions/attest-build-provenance`,
  keyless) pushed to the registry alongside the image.

This is deploy-safe and additive: **Render still builds from source today** — the signed
image is published in parallel, not yet pulled.

## Half B — pull the signed image on Render (runbook, pending)

To close the loop (Render deploys the signed artifact instead of rebuilding):

1. **Registry pull creds on Render.** GHCR package → grant read to a Render-usable token
   (or make the package internal to the org and add a `ghcr.io` registry credential in the
   Render dashboard).
2. **Switch the service to image-backed.** In `luke-platform/render.yaml`, replace the
   auth service's `dockerfilePath: ./Dockerfile` with `image.url:
   ghcr.io/luke-works/luke-auth-engine@sha256:<digest>` (pin the **digest**, not a tag) and
   wire the pull credential. Render then pulls + runs that exact signed image.
3. **Verify before promote.** Render has no cosign admission control, so add a CI/CD gate
   that runs `cosign verify` (command above) on the digest before it's promoted — the
   verification step Render itself can't enforce.

> **Runtime-verification caveat:** because Render isn't Kubernetes, signature *enforcement*
> at pull is not native. The artifacts are signed, attested, digest-pinned and verifiable;
> enforcement lives in the CI gate (step 3), not in an admission controller.

## First scan caught real CVEs

The gate paid for itself on its first run. Trivy flagged fixable CRITICAL/HIGH CVEs in
the app's own dependencies — `jackson-databind` (CVE-2026-54512, arbitrary code
execution), `tomcat-embed-core` (CVE-2026-41293 / -43515, both CRITICAL), and
`spring-boot` 3.4.13 itself (CVE-2026-40973). Spring Boot 3.4.x was already EOL (3.4.13
was its last patch), so the fix was to bump to **3.5.16**, which manages the patched
transitive versions (jackson 2.21.4, tomcat 10.1.55). No `.trivyignore` was needed — the
CVEs were remediated, not suppressed.
