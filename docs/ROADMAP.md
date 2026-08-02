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
  registry) would let a rotation actually retire an old key version. The same gap now also shows up
  when a deployment that auto-generated its key later adopts a Docker secret: the documented move is
  to carry the generated key forward as its own version (Scrye refuses to start if it isn't, rather
  than orphan whatever was written under it), and only this action would let that version be dropped
  afterwards.

  The same action also finishes the **row-bound AAD** migration. Row binding itself is already
  implemented — `secret_store.py`'s `row_aad()` composes `<table>.<column>:<row-id>` and
  `encrypt_secret()` binds to the row on every write (L1/SEC-7, #64) — so new and updated
  ciphertext is row-bound today. What is *not* done is the cutover: `decrypt_secret()` falls
  back to the bare column tag so pre-#64 ciphertext still decrypts, and a row that has never
  been updated since then is still column-only. That fallback can only be dropped once every
  row has been re-encrypted, which is exactly what this action would do — one eager pass
  instead of waiting for each record's next write.
- ~~**Move the frontend build from Node 22 to Node 24.**~~ **Done 2026-08-02** — the image's
  `frontend-builder` stage, CI's `setup-node`, and the stated requirement in `CONTRIBUTING.md` /
  `README.md` all moved to Node 24 (`krypton`, Active LTS, supported through **2028-04-30**) in
  one PR, with `.github/dependabot.yml`'s major-ignore re-pointed at the 24 line. See
  [`ARCHIVE.md` §14, 2026-08-02](./ARCHIVE.md).

  **What remains is the Node 26 decision, and it is not due yet.** 26 became current on
  2026-05-05 but does not enter LTS until **2026-10-28** (EOL 2029-04-30). Revisit it
  deliberately after that date — the 24 line does not go to maintenance until 2026-10-20 and is
  supported for eighteen months past it, so there is no pressure. The same three-file lockstep
  applies to any future major: the Dockerfile stage, `ci.yml`'s `node-version`, and the
  CONTRIBUTING/README requirement move together, or a version-specific failure surfaces in a
  published image instead of in a check. Node majors stay ignored for the `docker` ecosystem in
  `.github/dependabot.yml` — scoped to `version-update:semver-major`, so digest refreshes of the
  pinned 24 tag still arrive — which is why odd-numbered lines like the **#126** Node 25 proposal
  (never LTS, EOL 2026-06-01) do not show up here.
- **Frontend tooling majors from Dependabot #86.** After the Mantine/React ignores landed
  (locked decision §2 — `ARCHIVE.md` §14, 2026-07-26), the rest of that grouped PR is still
  wanted and still unapplied: **TypeScript 5.7 → 7.0**, **ESLint 9 → 10**, **`typescript-eslint`
  8.19 → 8.65**, **Vite 6 → 8**, **Vitest 3 → 4**, **jsdom 26 → 29**, and the smaller bumps
  alongside them. None of these is locked. They are grouped here because they share one risk:
  every one of them lands on the **type-aware ESLint gate** turned on 2026-07-24, so the real
  work is the lint-config churn they shake out, not the version numbers. Best done as a single
  deliberate PR rather than folded into an unrelated change.
- **`react-router` 7 → 8.** Belongs with the tooling majors above, and is now a **pure currency
  item with no security component**. It was previously coupled to GHSA-qwww-vcr4-c8h2 (#123),
  whose only recorded fix was the 8.3.0 major; that advisory was closed on 2026-08-02 by the
  **7.18.2 backport** instead, so nothing about the 8 line is required (see
  [`ARCHIVE.md` §14, 2026-08-02](./ARCHIVE.md)). Do not re-argue it as a security fix — as of
  7.18.2 there is nothing left for it to fix. The migration's actual cost is that v8 folds
  `react-router-dom` back into `react-router`, so **every import site in `frontend/src/` moves**
  (twelve files today), plus whatever the type-aware ESLint gate makes of the new type surface —
  which is the same risk the bumps above share, and the reason to do them together.
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
- **De-flake `test_cancel_queued_scan` (make slot acquisition observable).**
  `backend/tests/test_scans_api.py::test_cancel_queued_scan` is timing-dependent **by
  construction**: it monkeypatches a scanner whose `scan_image` does `await asyncio.sleep(0.2)`,
  forces the worker semaphore to a single slot, queues two scans, and cancels the second — which
  only works while that second scan is still `queued`. On a loaded CI runner the 0.2 s window
  closes before the cancel POST is processed, the scan has left `queued`, and the endpoint
  correctly returns **409**. So the failure is the *test* being wrong, not the code: queued-only
  cancellation is a deliberate design decision (`docs/ARCHIVE.md` §14, 2026-07-03 — the in-process
  worker has no channel to interrupt a live scanner subprocess; lifting that limit is the separate
  "Cancel a running scan" item under Medium-term).

  **Fix by making the worker's slot acquisition observable to the test** — e.g. an event/future the
  test can await to know the first scan actually holds the only slot, so the cancel is issued at a
  known state instead of inside a sleep window. **Do not just widen the sleep**: a longer sleep only
  lengthens the odds, leaves the race in place, and slows the suite on every run.

  **Why it matters more than one red check:** a test that reddens CI intermittently trains everyone
  to re-run without reading the failure. That habit is exactly how a real regression gets waved
  through — and it costs the most on a security tool, where the dogfood gate's output is the thing
  nobody should learn to skim. Observed 2026-07-31 on a docs-and-workflow-only PR (#118), where it
  failed once and passed on re-run of the identical commit.
- **Finish the public-repo governance setup (repository settings).** Going public added the
  in-repo pieces — a `.github/CODEOWNERS` (owner-review requests) and a `SECURITY.md` (private
  vulnerability reporting). The remaining pieces are GitHub **settings**, not files, so they live
  here as a checklist. None of them is doable from a code session, which is exactly why several
  sat invisible in `ARCHIVE.md` §14 prose for weeks before being collected here.

  **Six of the original eight items are now closed.** Five were verified in GitHub Settings on
  2026-08-02 — the GitHub profile display name, the dormant Docker Hub secrets, GHCR package
  visibility, Dependabot security alerts, and the Actions workflow permissions; what that
  verification actually found (including the two that turned out to be correct already rather than
  newly changed) is in [`ARCHIVE.md` §14, 2026-08-02](./ARCHIVE.md). **Private vulnerability
  reporting is the sixth** — see below. Check that entry, not this list, before re-doing any of
  them: a settings change leaves no artifact in the repository, so §14 is the only durable record it
  happened.

  **What remains is one decision and two tracked settings gaps.** The branch-protection item turned
  out to be mostly done; the parts of it that are genuinely open are now issues rather than prose,
  for exactly the reason this checklist exists.

  - **Branch protection** on `main` and `dev` — **mostly done; do not re-scope from the original
    wording.** A ruleset readout on 2026-08-02 (`ARCHIVE.md` §14) found `protect-dev` and
    `protect-main` both `active`, each already carrying `pull_request` (1 approval,
    dismiss-stale-on-push, thread resolution, squash-only), `required_status_checks`, `deletion`,
    and `non_fast_forward`. So *"require a passing CI status"* and *"require a pull request"* are
    **already in place on both branches**.

    Three things are genuinely still open, two of them now tracked:

    - **[#136](https://github.com/tyler-rich/Scrye/issues/136) — the dogfood self-scan is not a
      required check.** `required_status_checks` is an allowlist naming only `Backend — lint +
      tests` and `Frontend — lint + build`, so a PR can merge with the image scan red. Includes the
      `paths:`-filter hazard: a required context whose workflow never triggers blocks a PR forever
      (a job skipped by `if:` is fine — it reports `skipped`).
    - **[#137](https://github.com/tyler-rich/Scrye/issues/137) — nothing restricts tag pushes.**
      Both rulesets are `target: "branch"`; there is no tag-targeted ruleset, and a `v*.*.*` tag push
      is what triggers `publish.yml` (GHCR push, `:latest` move, provenance + SBOM attestation).
      Theoretical with a sole maintainer; the trigger is **before any collaborator is added**.
    - **Code-owner review is not required.** `require_code_owner_review` is `false` on both rulesets,
      so `.github/CODEOWNERS` requests review but does not compel it. Untracked — it is a decision
      rather than a gap, and on a single-maintainer repo it is close to a no-op today.

    Note when working any of these: *Restrict deletions* is enabled on `protect-dev` and did **not**
    prevent `dev` from being deleted during the v0.2.0 promotion, because the ruleset's bypass list
    grants Repository admin *Always allow* (`ARCHIVE.md` §14, 2026-08-02). Assume any rule configured
    here is advisory for the repository owner until the bypass list says otherwise. (The bypass list
    is not readable at the API permission level available to a code session — the ruleset endpoint
    returns `bypass_actors: null` — so confirm it in Settings rather than from an API dump.)
  - **Signed-commit enforcement** — a decision to make, and **verified still open**: neither ruleset
    carries a `required_signatures` rule (2026-08-02 readout). Requiring signed commits on the
    protected branches means contributors must sign; worth it for a security tool, so weigh the
    friction.
  - ~~**Private vulnerability reporting**~~ — **Done; verified 2026-08-02.**
    `GET /repos/tyler-rich/Scrye/private-vulnerability-reporting` returns `{"enabled": true}`, so
    `SECURITY.md`'s stated channel exists. It is not recorded when this was turned on — it may have
    been enabled at any point since the repo went public and simply never struck from this list,
    which is the same drift this checklist was created to stop.

- ~~**Enable GitHub code scanning (CodeQL) for Python and TypeScript.**~~ **Done 2026-08-02** —
  enabled via **default setup** on the **`security-extended`** query suite (a dropdown in the same
  settings pane; "default setup" names the setup mode, not the suite). Language auto-detection added
  a third language, **`actions`**, alongside Python and JavaScript/TypeScript. The first run covered
  every source file — 174/174 Python, 78/78 TypeScript, 2/2 JavaScript, 5/5 workflows — and produced
  **six alerts, all Python, all assessed as false positives**: two `py/path-injection` on the
  filesystem-scan containment gate (`backend/app/scanners/targets.py:138` and `:144`), three
  `py/incomplete-url-substring-sanitization` on test assertions, and one `py/log-injection` on an
  `int`-typed path parameter (`backend/app/api/scans.py:574`). Advanced setup was **not** taken:
  there is no vendored or generated tree to path-exclude and no need for custom query packs, and
  default setup keeps the action and query-pack versions managed rather than adding a fourth
  SHA-pinned workflow with its own bump stream. Full reasoning per alert, the reproduction method
  behind the numbers, and the recommended disposition for each are in
  [`ARCHIVE.md` §14, 2026-08-02](./ARCHIVE.md).

  **What remains is disposition, and two dependencies.** No alert has been dismissed — that is a
  deliberate hold, since a dismissal with no written reason is indistinguishable from an unread
  finding. The §14 entry supplies the written reason for each; applying them (and deciding whether
  the two `targets.py` alerts warrant a code change to make the containment legible to the analyzer,
  rather than merely a dismissal) is the open work.

  **CodeQL does not currently run on `dev` PRs — confirmed on #134, which got four check runs and no
  CodeQL among them.** Default setup's PR trigger targets the **default branch**, so it covers PRs
  into `main`; `dev`, which is where day-to-day work is actually PR'd, gets nothing. CodeQL therefore
  analyses `main` on push — *after* a promotion has landed — and on its weekly schedule.

  **The advanced-setup migration was assessed on 2026-08-02; the recommendation is to do it, with no
  sequencing dependency.** Full reasoning, the measured CI cost (≈0 added wall-clock — CodeQL's
  longest job is 62 s against the pipeline's 121 s critical path), the maintenance cost (≈0 marginal,
  because `dependabot.yml` already groups all action bumps into one weekly PR), what migrating does
  and does not lose (query packs stay GitHub-managed; automatic language detection does not), and the
  case *against* migrating are in [`ARCHIVE.md` §14, 2026-08-02](./ARCHIVE.md). Two corrections that
  entry makes to the framing above: `:latest` is published by a **tag push**, not by the promotion
  merge, so CodeQL's run on `main` normally lands *before* `:latest` exists — the real
  published-artifact gap is **`:dev`**, which the nightly builds from a branch CodeQL never sees.

  **Do not assume a CodeQL check would be blocked on the branch-protection item above.** The
  `protect-dev` ruleset is already `active` and already has `required_status_checks` — but that rule
  is an **explicit allowlist of contexts**, currently naming only `Backend — lint + tests` and
  `Frontend — lint + build` (neither image job is on it either). A migrated CodeQL workflow would run
  and be visible but would not block a merge until its contexts are added to that list, which is a
  settings edit made *alongside* the migration, not a prerequisite for it. One caveat if they are
  added: a required context that never reports blocks a PR forever, so the CodeQL workflow must not
  carry `paths:` filters.

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
- **Single-source the version string, and stamp it into the image.** Two halves of one problem:
  the version is declared in several places and derived from none of them.

  *Single-sourcing.* The app version is declared independently in `backend/app/__init__.py`,
  `backend/pyproject.toml` and `frontend/package.json` (+ the lockfile's root fields), and
  nothing derives one from another or from the git tag — so a release has to touch several files
  in lockstep. `backend/tests/test_version.py` now fails on drift, which makes the duplication
  safe but not gone. Collapse it to `app.__version__` as the single source: `pyproject.toml` can
  pick it up via setuptools' dynamic version (`dynamic = ["version"]` +
  `[tool.setuptools.dynamic] version = {attr = "app.__version__"}`), and
  `frontend/package.json`'s copy — which is never bundled and never published (`private: true`),
  since the SPA reads the version from the About/health API at runtime — can be dropped to a
  fixed placeholder.

  *Image stamping.* `publish.yml` computes the image tag from the pushed ref
  (`${GITHUB_REF_NAME#v}`) but never stamps a version **into** the image: there is no `LABEL` in
  `docker/Dockerfile` and no `labels:`/`build-args:` in any of the three build workflows
  (`publish.yml`, `dev-nightly.yml`, `ci.yml` — none of them uses `docker/metadata-action`, which
  is what normally generates the OCI label set). So `docker inspect` on a published image reveals
  nothing about what is inside it, and an image whose tag was retagged or lost carries no
  self-description at all. This is **metadata hygiene, not a defect**: the running app reports its
  version correctly because `app/__init__.py` is baked in, and `/healthz` and the About tab both
  serve it. The fix is the standard OCI label set on the runtime stage — at minimum
  `org.opencontainers.image.version`, alongside `.title`, `.source`, `.revision` and `.created` —
  fed by a build arg the publish workflow already has in `steps.version.outputs.version`. Note the
  image is not wholly opaque today: `publish.yml` attaches BuildKit SLSA provenance
  (`provenance: mode=max`) and an SPDX SBOM (`sbom: true`) plus a GitHub-signed attestation, so
  the build is describable — just not through the one-command channel operators actually reach
  for.

  Both halves want their own PR and CI run rather than riding on a release bump; the label work
  also touches the runtime stage, so read `docs/ARCHIVE.md` § Build performance first. See
  `docs/ARCHIVE.md` § Deviations, 2026-07-29.
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
