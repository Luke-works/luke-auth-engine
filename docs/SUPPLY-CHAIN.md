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

## Known gap — signing & provenance

The image is **not** cosign-signed and carries no SLSA provenance attestation. This is a
deliberate scope boundary, not an oversight: **Render builds the deployed image from
source on every push** — there is no image published to a registry for us to sign or
attest, and nothing pulls a signed digest. Adding signing/provenance requires first
moving to a **build-and-push-to-a-registry** model (GHCR/ECR) with Render pulling the
signed digest instead of building from source — an infrastructure decision for
`luke-platform`, tracked as the remaining part of #41.

Until then, the reproducibility (digest pins) and vulnerability (SBOM + gating scan)
halves of the supply-chain story are covered; the authenticity half waits on that
registry decision.
