# Scrye — Roadmap

> Forward-looking view of what's next for Scrye. Scrye is feature-complete for its core mission
> — a unified, self-hosted web UI over Trivy and Grype — so this document is about **open work,
> known limitations, and candidate features**, not the original build (that history lives in
> [`ARCHIVE.md`](./ARCHIVE.md), and what Scrye does today is in the [`README.md`](../README.md)).
>
> Nothing here is a commitment or a dated schedule. Items are grouped by rough effort and
> readiness — **near-term** (small, well-scoped, closes a real gap), **medium-term** (a feature
> or a developer-experience investment), and **longer-term / speculative** (architectural, or
> gated on a scale threshold). Scrye's repository is now **public**, so items that were
> previously blocked on that (free CI runners, fork-based contribution safety) are unblocked. A
> final section records **known limitations and accepted trade-offs** that are on the record but
> may never change.

---

## Near-term

Small, self-contained work that closes a concrete gap.

- **Content-addressed SBOM target identity.** Two uploaded SBOMs that share a filename *and*
  target type currently collapse into a single target identity for history grouping, scan-diff,
  and the dashboard's per-target "open" posture — the scan row carries only the filename as
  identity. Key SBOM targets on a content hash (the SHA-256 already computed for the uploaded
  SBOM's artifact) instead of the filename, so distinct SBOMs are always distinct targets.
- **Admin bulk secret re-encryption (key-rotation action, and the legacy-AAD cutover).** The
  master-key file already supports multiple versions (`v<N>:<base64>` lines) and new secrets
  encrypt under the highest version, but there is no admin-facing action to *re-wrap existing
  rows* under a new version. Today an old ciphertext stays wrapped under the version it was
  written with until that record is next updated, so an operator must keep the retired key line
  in place indefinitely. A "re-encrypt all secrets" action (walking the `SECRET_COLUMNS`
  registry) would let a rotation actually retire an old key version.

  The same action also finishes the **row-bound AAD** migration. Row binding itself is already
  implemented — `secret_store.py`'s `row_aad()` composes `<table>.<column>:<row-id>` and
  `encrypt_secret()` binds to the row on every write (L1/SEC-7, #64) — so new and updated
  ciphertext is row-bound today. What is *not* done is the cutover: `decrypt_secret()` falls
  back to the bare column tag so pre-#64 ciphertext still decrypts, and a row that has never
  been updated since then is still column-only. That fallback can only be dropped once every
  row has been re-encrypted, which is exactly what this action would do — one eager pass
  instead of waiting for each record's next write.
- **Move the frontend build from Node 22 to Node 24.** The image's `frontend-builder` stage and
  CI both run Node 22 (`jod`), which entered maintenance on 2025-10-21 and is supported only
  through **2027-04-30**. Node 24 (`krypton`) is the Active LTS and is supported through
  **2028-04-30**, so it is where this should land. Node **26** is deliberately not the target: it
  does not become LTS until **2026-10-28**. The move spans three places that must change together
  — `docker/Dockerfile`'s pinned `node:22-bookworm-slim` digest, `.github/workflows/ci.yml`'s
  `node-version: "22"`, and `CONTRIBUTING.md`'s stated Node floor (plus the matching line in
  `README.md` § Requirements) — which is exactly why it is its own item and not something a
  Dependabot digest bump can carry. Until it happens, the 22 digest still needs refreshing on its
  own schedule; Dependabot offers the 26 major instead of a 22 digest refresh, so declining the
  major leaves the builder stale (see `ARCHIVE.md` §14, 2026-07-26).
- **Frontend tooling majors from Dependabot #86.** After the Mantine/React ignores landed
  (locked decision §2 — `ARCHIVE.md` §14, 2026-07-26), the rest of that grouped PR is still
  wanted and still unapplied: **TypeScript 5.7 → 7.0**, **ESLint 9 → 10**, **`typescript-eslint`
  8.19 → 8.65**, **Vite 6 → 8**, **Vitest 3 → 4**, **jsdom 26 → 29**, and the smaller bumps
  alongside them. None of these is locked. They are grouped here because they share one risk:
  every one of them lands on the **type-aware ESLint gate** turned on 2026-07-24, so the real
  work is the lint-config churn they shake out, not the version numbers. Best done as a single
  deliberate PR rather than folded into an unrelated change.
- **Retire the deprecated Starlette status-code constants.** `status.HTTP_422_UNPROCESSABLE_ENTITY`
  raises a `StarletteDeprecationWarning` on every attribute access — Starlette renamed it to
  `HTTP_422_UNPROCESSABLE_CONTENT` — and it is referenced at **22 call sites** across seven routers
  (`scans.py` ×10, `scan_schedules.py` ×4, `registries.py` ×3, `notifications.py` ×2, and one each
  in `trivy_policy.py`, `git_credentials.py`, `backups.py`). The same rename hit
  `HTTP_413_REQUEST_ENTITY_TOO_LARGE` → `HTTP_413_CONTENT_TOO_LARGE`, at 2 more call sites in
  `uploads.py`. These are the backend suite's standing deprecation warnings, recorded as
  pre-existing at each of the last two interpreter bumps (`ARCHIVE.md` §14, 2026-07-03 and
  2026-07-25) and never actually cleared. The change is mechanical — the constants are equal
  integers, so no status code or behavior moves — and it takes the suite's warning output down to
  the Starlette-TestClient httpx notice, so a genuinely new warning becomes visible instead of
  being lost in known noise.
- **Offline / air-gapped scanner-DB import.** The Scanners settings already drive scheduled
  online DB refreshes (`trivy image --download-db-only`, `grype db update`). Add an import path
  for environments with no outbound access to `mirror.gcr.io` / `grype.anchore.io`, so the Trivy
  and Grype vulnerability databases can be side-loaded from a file.
- **Finish the public-repo governance setup (repository settings).** Going public added the
  in-repo pieces — a `.github/CODEOWNERS` (owner-review requests) and a `SECURITY.md` (private
  vulnerability reporting). The remaining pieces are GitHub **settings**, not files, so they live
  here as a checklist. None of them is doable from a code session, which is exactly why several
  sat invisible in `ARCHIVE.md` §14 prose for weeks before being collected here.

  - **Branch protection** on `main` and `dev` — require a passing CI status, require a pull
    request, require review from Code Owners, and for `main` restrict who can push tags/promote.
  - **Signed-commit enforcement** — a decision to make. Requiring signed commits on the
    protected branches means contributors must sign; worth it for a security tool, so weigh the
    friction.
  - **Private vulnerability reporting** — enable in the repo's Security settings, so
    `SECURITY.md`'s stated channel actually exists.
  - **Confirm Dependabot security alerts are enabled** (Security tab). The config file only
    schedules *version* updates; security alerts are a separate repo setting. (§14 2026-07-20
    context; carried from the remediation tracker.)
  - **Settings → Actions → General → Workflow permissions → read-only.** Every workflow already
    declares its own explicit `permissions:` block, and an explicit block takes precedence over
    the repo default rather than being capped by it, so the restrictive default breaks nothing —
    including GHCR push. Logged in §14 2026-07-06 and never carried anywhere until now.
  - **Confirm the GHCR package `ghcr.io/tyler-rich/scrye` is public.** §14 2026-07-06 asked to
    confirm it was *Private* (it inherited a private repo); the repo went public on 2026-07-09,
    so the check is now the inverse — it should be **public**, per `CLAUDE.md` locked decision §6.
    Still unverified in either direction.
  - **Delete the unused `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` repo secrets.** No workflow has
    referenced them since the GHCR consolidation (§14 2026-07-09); `grep -r DOCKERHUB .github/`
    returns nothing. Dormant registry credentials on a public security-tool repo.
  - **Set the GitHub profile display name to `tyler-rich`.** A squash-merge authors the squashed
    commit with the merging account's *profile display name*, which repo-local `git config
    user.name` cannot override — so while the profile reads "Tyler Richardson", every
    squash-merged promotion silently breaks `CLAUDE.md`'s author-identity rule (R7/D4, §14
    2026-07-13).

## Medium-term

Features and developer-experience investments with a larger surface.

- **Uploaded image-tar (`docker save`) targets.** Both Trivy and Grype can scan a local image
  archive. Add a target type that accepts an uploaded `docker save` tarball, so an image can be
  scanned without a reachable registry.
- **Filesystem-archive upload target.** Grype filesystem scanning today is limited to a
  mounted host path under the admin-configured `SCRYE_FILESYSTEM_SCAN_ROOTS` allowlist. Add an
  archive-upload variant (upload a `.tar`/`.zip`, unpack into scratch, scan, discard) so a
  filesystem scan doesn't require pre-mounting the path into the container.
- **Docker-environment multi-select scan launcher.** The read-only `docker-socket-proxy`
  integration currently *enumerates* the images running in a Docker environment and lets you
  copy a reference to scan as a normal image target. Add a multi-select launcher that queues a
  scan for each chosen image in one action.
- **Cancel a running scan.** Cancellation is currently limited to scans still in the `queued`
  state — the in-process worker has no channel to interrupt a live scanner subprocess. A
  cooperative-cancellation path (signal the subprocess, mark the scan canceled, clean up its
  scratch) would let a long-running scan be stopped.
- **Cross-version backup restore.** A restore requires the bundle's schema version to match the
  running installation. Add forward-migration of an older bundle on restore (run the Alembic
  chain against the imported data) so a backup taken on an earlier release can be restored onto
  a newer one.
- **Generated API client.** The frontend API layer is a thin, hand-written `fetch` wrapper
  (`frontend/src/api/*`). Generating a typed client from the FastAPI OpenAPI schema (e.g.
  openapi-typescript) over that wrapper would keep the client and server contracts in lockstep.
- **Type-checking in CI.** Add a Python type checker (mypy or pyright) to the CI gate. This
  first needs the existing annotation gaps resolved so the gate lands green rather than red.
- **Backend structural cleanup.** The four near-identical secret-CRUD routers (registries, git
  credentials, notification channels, OIDC) could be consolidated behind shared helpers to cut
  duplication. *(The list-response envelope half of this item is done — see `docs/ARCHIVE.md`
  § Deviations, 2026-07-25, and `CONTRIBUTING.md` § API conventions.)*

## Longer-term / speculative

Architectural directions, mostly gated on a scale threshold or an explicit decision.

- **Pluggable scale-out worker (arq / Redis).** The scan worker is a single-container,
  in-process async worker behind a small `ScanWorker` interface, deliberately so it can be
  swapped later. A Redis-backed queue (e.g. arq) would let scans run across multiple worker
  processes or containers for higher throughput — only warranted if a single instance's
  concurrency ceiling becomes the bottleneck.
- **Full-database encryption at rest (SQLCipher).** Secrets are field-encrypted at the
  application layer today (AES-256-GCM), which is the required baseline. SQLCipher would encrypt
  the *entire* database file at rest as defense-in-depth. A clean seam was left for it; adopting
  it is a deliberate future hardening step, not a v1 requirement.
- **Framed streaming backup encryption.** A backup bundle is assembled and encrypted in a single
  in-memory AES-GCM pass, so a very large findings table (hundreds of thousands of rows and up)
  needs container memory headroom proportional to the dump. A framed/streaming encryption format
  would bound backup/restore memory regardless of database size.
- **One-pass SBOM cataloging for Grype.** When an image scan generates a Syft SBOM, that SBOM
  could be fed directly into the same Grype run (one cataloging pass) instead of Grype
  re-cataloging the target. A modest efficiency win for combined SBOM-plus-vuln scans.
- **Native arm64 CI runners.** The multi-arch image build runs its arm64 leg under QEMU
  emulation, which is slow on a cold cache (cross-seeded caches mitigate this — see
  [`ARCHIVE.md` § Build performance](./ARCHIVE.md)). Switching the arm64 leg to native
  `ubuntu-24.04-arm` hosted runners (matrix build + manifest merge) would remove emulation from
  cold builds entirely. Now that the repository is **public**, GitHub-hosted arm64 runners are
  free — the cost concern that previously gated this is gone, making it a straightforward win
  whenever the multi-arch cold-build time becomes annoying.

## Known limitations & accepted trade-offs

On the record and unlikely to change without a specific reason — documented here so a deployer
isn't surprised.

- **OIDC delegates MFA to the identity provider.** The mandatory-MFA policies (`required_all` /
  `required_admin`) are enforced on **local** password login. OIDC logins have no local TOTP
  step in the handshake, and provisioned OIDC accounts carry no usable local password — so an
  OIDC user's second factor must be enforced at the IdP (e.g. Pocket ID). This is an accepted
  limitation, not a planned change; gating it at Scrye's layer would lock out OIDC accounts that
  have no local password. (When group→role mapping is configured it is re-applied on each login,
  but an absent groups claim preserves the current role, and an OIDC sync can never remove the
  last admin.)
- **Cloud registry credential helpers are not bundled.** Static registry credentials and tokens
  work out of the box. The ECR / GCR / ACR credential-helper *configuration* is generated at
  scan time, but the helper binaries themselves are not shipped in the image — those registry
  types work only where the matching helper is present in the runtime environment, as a
  deployment add-on. Bundling them would bloat the image and pull in unvetted dependencies.
- **Bundled scanner binaries track upstream for CVEs.** Trivy, Grype, and Syft are shipped as
  unmodified upstream Go binaries under Apache-2.0. CVEs in *their* embedded Go modules or the Go
  standard library are fixed only when Aqua/Anchore cut a new release built against a patched Go,
  so they're excluded from Scrye's own CI dogfood gate (they remain visible in the informational
  scan report). Keeping the pinned scanner versions current is how those are addressed — Scrye's
  own attack surface (base image, OS packages including `git`, Python/JS deps, app code) stays
  fully gated.
- **The optional `trivy-server` sidecar runs as root.** The upstream `aquasec/trivy` image ships
  no non-root `USER` and hard-codes its cache under `/root/.cache`, so running it as an arbitrary
  uid breaks the DB cache on a root-owned named volume. The sidecar is optional (profile-gated),
  reachable only on the internal network, and otherwise hardened (read-only root FS,
  `no-new-privileges`, `cap_drop: ALL`, resource-limited). Rebuilding it on a non-root base with
  a writable cache path is a possible future hardening.
- **Very large backups need memory headroom.** See the framed-streaming item above — until that
  lands, sizing container memory to the dump is the operational answer, and Scrye logs a warning
  past the threshold.
