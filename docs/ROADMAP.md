# Scrye — Roadmap

> Forward-looking view of what's next for Scrye — a self-hosted web UI that unifies
> multiple open-source scanning engines behind one interface, API, and normalized
> findings model. Scrye is feature-complete for its original core mission (a unified UI
> over Trivy and Grype), so this document covers **open engineering work, known
> limitations, and the feature direction** — the original build history lives in
> [`ARCHIVE.md`](./ARCHIVE.md), and what Scrye does today is in the
> [`README.md`](../README.md).
>
> Nothing here is a commitment or a dated schedule. **Track A** is engineering and
> hardening work grouped by rough effort and readiness; **Track B** is the feature
> direction grouped into phases. Done items are kept, struck through, with pointers to
> [`ARCHIVE.md` §14](./ARCHIVE.md) — check the referenced entry before re-doing or
> re-arguing anything marked done or declined.

---

## Where Scrye is heading

Scanners answer *"what is vulnerable right now?"* Scrye's direction is everything that
comes after that answer:

1. **Decide** — triage findings with a real workflow: VEX authoring, documented
   acceptances with review dates, a full audit trail.
2. **Watch** — Scrye keeps history and runs on a schedule, so it can tell you what the
   stateless scanners can't: when a fix lands, when your fleet drifts, when an
   acceptance expires.
3. **Corroborate** — multiple independent engines, where agreement and disagreement are
   both signal.
4. **Interoperate** — SARIF, OpenVEX, MCP, CI gates: decisions made in Scrye are
   portable and enforceable everywhere else in your pipeline.

---

# Track A — Engineering & hardening

Items marked † are prerequisites for features in Track B.

## Near-term

Small, self-contained work that closes a concrete gap.

- **Content-addressed SBOM target identity.** † *(prerequisite for Phase 2 fix-watch —
  a watched SBOM must have stable identity)* Two uploaded SBOMs that share a filename
  *and* target type currently collapse into a single target identity for history
  grouping, scan-diff, and the dashboard's per-target "open" posture — the scan row
  carries only the filename as identity. Key SBOM targets on a content hash (the
  SHA-256 already computed for the uploaded SBOM's artifact) instead of the filename, so
  distinct SBOMs are always distinct targets.
- **Admin bulk secret re-encryption (key-rotation action, and the legacy-AAD cutover).**
  The master-key file already supports multiple versions (`v<N>:<base64>` lines) and new
  secrets encrypt under the highest version, but there is no admin-facing action to
  *re-wrap existing rows* under a new version. Today an old ciphertext stays wrapped
  under the version it was written with until that record is next updated, so an
  operator must keep the retired key line in place indefinitely. A "re-encrypt all
  secrets" action (walking the `SECRET_COLUMNS` registry) would let a rotation actually
  retire an old key version. The same gap now also shows up when a deployment that
  auto-generated its key later adopts a Docker secret: the documented move is to carry
  the generated key forward as its own version (Scrye refuses to start if it isn't,
  rather than orphan whatever was written under it), and only this action would let that
  version be dropped afterwards.

  The same action also finishes the **row-bound AAD** migration. Row binding itself is
  already implemented — `secret_store.py`'s `row_aad()` composes
  `<table>.<column>:<row-id>` and `encrypt_secret()` binds to the row on every write
  (L1/SEC-7, #64) — so new and updated ciphertext is row-bound today. What is *not* done
  is the cutover: `decrypt_secret()` falls back to the bare column tag so pre-#64
  ciphertext still decrypts, and a row that has never been updated since then is still
  column-only. That fallback can only be dropped once every row has been re-encrypted,
  which is exactly what this action would do — one eager pass instead of waiting for
  each record's next write.
- ~~**Move the frontend build from Node 22 to Node 24.**~~ **Done 2026-08-02** — the
  image's `frontend-builder` stage, CI's `setup-node`, and the stated requirement in
  `CONTRIBUTING.md` / `README.md` all moved to Node 24 (`krypton`, Active LTS, supported
  through **2028-04-30**) in one PR, with `.github/dependabot.yml`'s major-ignore
  re-pointed at the 24 line. See [`ARCHIVE.md` §14, 2026-08-02](./ARCHIVE.md).

  **What remains is the Node 26 decision, and it is not due yet.** 26 became current on
  2026-05-05 but does not enter LTS until **2026-10-28** (EOL 2029-04-30). Revisit it
  deliberately after that date — the 24 line does not go to maintenance until 2026-10-20
  and is supported for eighteen months past it, so there is no pressure. The same
  three-file lockstep applies to any future major: the Dockerfile stage, `ci.yml`'s
  `node-version`, and the CONTRIBUTING/README requirement move together, or a
  version-specific failure surfaces in a published image instead of in a check. Node
  majors stay ignored for the `docker` ecosystem in `.github/dependabot.yml` — scoped to
  `version-update:semver-major`, so digest refreshes of the pinned 24 tag still arrive —
  which is why odd-numbered lines like the **#126** Node 25 proposal (never LTS, EOL
  2026-06-01) do not show up here.
- ~~**Frontend tooling majors from Dependabot #86.**~~ **Done 2026-08-09** — landed as an
  ordered eight-step sequence, one PR per step, each verified green before the next began:
  **[#171](https://github.com/tyler-rich/Scrye/pull/171)** `typescript-eslint` 8.19.0 →
  8.66.0 · **[#174](https://github.com/tyler-rich/Scrye/pull/174)** the ESLint 10 family
  (`eslint` 9.39.4 → 10.8.1, `@eslint/js` → 10.0.1, `eslint-plugin-react-hooks` 5.1.0 →
  7.1.1, `eslint-plugin-react-refresh` 0.4.16 → 0.5.3) ·
  **[#177](https://github.com/tyler-rich/Scrye/pull/177)** the React Compiler rule set
  adopted, with `react-hooks/set-state-in-effect` held off over twelve reports that have no
  honest fix (tracked in [#176](https://github.com/tyler-rich/Scrye/issues/176)) ·
  **[#179](https://github.com/tyler-rich/Scrye/pull/179)** TypeScript 5.7.2 → 6.0.3 ·
  **[#180](https://github.com/tyler-rich/Scrye/pull/180)** Vitest 3.2.7 → 4.1.10 ·
  **[#183](https://github.com/tyler-rich/Scrye/pull/183)** jsdom 26.1.0 → 30.0.1 ·
  **[#185](https://github.com/tyler-rich/Scrye/pull/185)** Vite 6.4.3 → 8.2.1 with
  `@vitejs/plugin-react` 4.3.4 → 6.0.5 ·
  **[#187](https://github.com/tyler-rich/Scrye/pull/187)** `globals` 17.9.0,
  `@testing-library/user-event` 14.6.3, `postcss` 8.5.26.

  **Two packages from the original group were deliberately excluded rather than
  overlooked.** **TypeScript 7** — the Go-native compiler — is out because no published
  `typescript-eslint` accepts it: its peer range is `>=4.8.4 <6.1.0` at both `latest` and
  canary, and support is expected to arrive as a new `typescript-eslint` major built
  against TS 7's API rather than as a range widen, so the sweep's ceiling is **6.0.3**.
  **`@types/node` 26** is out because nothing in the toolchain needs it: the only
  constraints in play are optional peers that the pinned 24.x already satisfies. Both will
  keep appearing in Dependabot's grouped frontend PR until they are either taken or ignored
  on the default branch — Dependabot reads `.github/dependabot.yml`, including its `ignore`
  list, from the default branch rather than from `target-branch`. Per-step records,
  including what each step's predictions got right and wrong, are in
  [`ARCHIVE.md` §14, 2026-08-09](./ARCHIVE.md).
- ~~**Ask GitHub to re-cut GHSA-qwww-vcr4-c8h2's affected range for the 7.18.2
  backport.**~~ **Done 2026-08-09** — no request was needed: the advisory has already been
  re-cut upstream, in exactly the shape this item asked for. The GitHub Advisory Database
  record now carries **two** affected ranges for `react-router` — **`>= 7.12.0, < 7.18.2`**
  and **`>= 8.0.0, < 8.3.0`** — in place of the single `>= 7.12.0, < 8.3.0` that spanned
  the backport, with the 8.x range left as it was. Verified live on 2026-08-09 against the
  advisory record itself in the `github/advisory-database` repository (`published` and
  `github_reviewed_at` 2026-07-24, `modified` 2026-08-07, so the record was amended after
  review), and independently against the npm registry's advisory endpoint, which returns
  those same two ranges and returns **nothing** for 7.18.2. The pinned `react-router`
  7.18.2 therefore no longer matches the advisory, and the standing false HIGH in
  `npm audit` and Dependabot — which is what made this worth raising upstream, since a
  known-bogus finding in a vulnerability scanner's own pipeline teaches everyone to dismiss
  that package's alerts on sight — is gone for every consumer on 7.18.2, not just for
  Scrye. The evidence that the backport genuinely carries the fix is unchanged and does not
  need re-deriving: `throwIfPotentialCSRFAttack()` is byte-identical across 7.18.1, 7.18.2
  and 8.3.0, and the fix is entirely at the call site in `index-react-server.js`'s
  `generateMiddlewareResponse`, matching upstream's single 7.18.2 patch note *"Harden RSC
  CSRF codepaths"*
  ([remix-run/react-router#15353](https://github.com/remix-run/react-router/pull/15353)).
  Scrye's own exposure was nil either way — the SPA is declarative-only, so the vulnerable
  RSC entry point never enters the bundle. Background in
  [#123](https://github.com/tyler-rich/Scrye/issues/123) (closed) and
  [`ARCHIVE.md` §14, 2026-08-02](./ARCHIVE.md) / [2026-08-03](./ARCHIVE.md).
- ~~**Retire the deprecated Starlette status-code constants.**~~ **Done 2026-08-03** —
  `HTTP_422_UNPROCESSABLE_ENTITY` → `HTTP_422_UNPROCESSABLE_CONTENT` and
  `HTTP_413_REQUEST_ENTITY_TOO_LARGE` → `HTTP_413_CONTENT_TOO_LARGE` across all 24 call
  sites in the 8 files that used them. Both constants verified equal to their
  predecessor before the rename (422 and 413 respectively, checked against the pinned
  `starlette==1.3.1`), so no status code or response behavior moved. See
  [`ARCHIVE.md` §14, 2026-08-03](./ARCHIVE.md).
- **Offline / air-gapped scanner-DB import.** The Scanners settings already drive
  scheduled online DB refreshes (`trivy image --download-db-only`, `grype db update`).
  Add an import path for environments with no outbound access to `mirror.gcr.io` /
  `grype.anchore.io`, so the Trivy and Grype vulnerability databases can be side-loaded
  from a file.
- ~~**De-flake `test_cancel_queued_scan` (make slot acquisition observable).**~~
  **Done 2026-08-03** — the fixed `await asyncio.sleep(0.2)` the fake scanner used to
  hold the worker's only slot is replaced with a `threading.Event` pair: the first
  scan's `scan_image` blocks until the test releases it, and a second event fires the
  instant `scan_image` actually starts (which only happens once the worker's semaphore
  is acquired), so the test knows the second scan is deterministically still `queued`
  before it cancels it — no wall-clock window to race under a loaded CI runner.
  Test-only change; queued-only cancellation itself is unchanged (still gated on the
  separate "Cancel a running scan" item under Medium-term). See
  [`ARCHIVE.md` §14, 2026-08-03](./ARCHIVE.md).
- **Retire `GET /api/scans` (deprecation-window decision, not yet scheduled).** The
  bare-array `GET /api/scans` was frozen and marked `deprecated=True` rather than
  reshaped when the list envelope landed (`backend/app/api/scans.py:276`,
  `docs/ARCHIVE.md` §14, 2026-07-25) — its replacement, `GET /api/scans/history`,
  already ships the `{total, items}` envelope. Removing the deprecated endpoint is a
  **breaking change for any external consumer using an API token**, so it needs an
  announced deprecation window (a `CHANGELOG.md` entry plus a stated removal release),
  not a silent drop in a routine cleanup PR. This item exists so that window is a
  deliberate decision someone makes, rather than something that never gets tracked
  because the endpoint itself was already marked deprecated and looked "handled." No
  removal date is set yet.
- **Finish the public-repo governance setup (repository settings).** Going public added
  the in-repo pieces — a `.github/CODEOWNERS` (owner-review requests) and a
  `SECURITY.md` (private vulnerability reporting). The remaining pieces are GitHub
  **settings**, not files, so they live here as a checklist. None of them is doable from
  a code session, which is exactly why several sat invisible in `ARCHIVE.md` §14 prose
  for weeks before being collected here.

  **Six of the original eight items are now closed.** Four were verified in GitHub
  Settings on 2026-08-02 — the dormant Docker Hub secrets, GHCR package visibility,
  Dependabot security alerts, and the Actions workflow permissions; what that
  verification actually found (including the two that turned out to be correct already
  rather than newly changed) is in [`ARCHIVE.md` §14, 2026-08-02](./ARCHIVE.md).
  **Private vulnerability reporting is the fifth** — see below.

  **The GitHub profile display name is the sixth, closed as a decision rather than a
  change — declined 2026-08-09, not deferred.** The display name stays the maintainer's
  real name. Merges performed through the GitHub web UI or API author the resulting
  commit as that display name — repo-local `git config` cannot override it — so those
  commits, including the v0.3.0 promotion merge commit, carry it and **are correct as
  they stand**; they are not drift and not something to fix. The authorship invariant
  this project actually enforces is that no AI-tooling identity appears in commits or
  PRs, and the maintainer's real name satisfies it. The accepted cost is two author
  strings for the same person in history (`tyler-rich` on branch commits via repo-local
  git config, which continues unchanged; the display name on web-UI/API merge commits),
  which is cosmetic. No review date, no resolution trigger — do not re-raise. See
  [`ARCHIVE.md` §14, 2026-08-09](./ARCHIVE.md).

  A 2026-08-09 re-verification of this list against the live API confirmed GHCR package
  visibility (an anonymous manifest pull of `ghcr.io/tyler-rich/scrye:latest` succeeds)
  and private vulnerability reporting (`{"enabled": true}`), and re-read all three
  rulesets (`protect-dev`, `protect-main`, `protect-tags` — all `active`, contents in
  [`ARCHIVE.md` §14, 2026-08-09](./ARCHIVE.md)). The Actions secrets, Dependabot alert
  toggles, and workflow-permissions settings sit behind API paths this session can't
  reach, so those were checked the only other way available: the maintainer read them
  directly in the GitHub UI, also on 2026-08-09 — Actions secrets empty, Dependabot
  alerts/malware-alerts/grouped-security-updates/security-updates all on, workflow
  permissions read-only with PR-creation off, code scanning 0 open / 6 closed on both
  `main` and `dev`, and "Require actions to be pinned to a full-length commit SHA" still
  off (safe to turn on — every `uses:` line in the repo is already a resolved commit
  SHA). See [`ARCHIVE.md` §14, 2026-08-09](./ARCHIVE.md) for the full readout. Check the
  §14 entries, not this list, before re-doing any of them: a settings change leaves no
  artifact in the repository, so §14 is the only durable record it happened.

  **What remains is one untracked decision.** The branch-protection item turned out to
  be mostly done; the two genuinely open pieces of it were tracked as issues, and both
  are now closed.

  - **Branch protection** on `main` and `dev` — **mostly done; do not re-scope from the
    original wording.** A ruleset readout on 2026-08-02 (`ARCHIVE.md` §14) found
    `protect-dev` and `protect-main` both `active`, each already carrying `pull_request`
    (1 approval, dismiss-stale-on-push, thread resolution, squash-only),
    `required_status_checks`, `deletion`, and `non_fast_forward`. So *"require a passing
    CI status"* and *"require a pull request"* are **already in place on both
    branches**.

    Three things were flagged as genuinely open, two of them tracked as issues:

    - ~~**[#136](https://github.com/tyler-rich/Scrye/issues/136) — the dogfood self-scan
      is not a required check.**~~ **Done 2026-08-03** — verified live: `protect-dev`'s
      `required_status_checks` now lists `Backend — lint + tests`, `Frontend — lint +
      build`, and `Image — build + dogfood self-scan`, with "Require branches to be up
      to date before merging" also enabled. See
      [`ARCHIVE.md` §14, 2026-08-03](./ARCHIVE.md).
    - ~~**[#137](https://github.com/tyler-rich/Scrye/issues/137) — nothing restricts tag
      pushes.**~~ **Done 2026-08-03** — a `protect-tags` ruleset now targets `v*` (any
      tag beginning with `v`, not only the dotted semver form), restricting
      creation/update/deletion and blocking force pushes, with Repository admin on the
      bypass list (same bypass shape as `protect-dev`/`protect-main`). See
      [`ARCHIVE.md` §14, 2026-08-03](./ARCHIVE.md).
    - **Code-owner review is not required.** `require_code_owner_review` is `false` on
      both rulesets, so `.github/CODEOWNERS` requests review but does not compel it.
      Untracked — it is a decision rather than a gap, and on a single-maintainer repo it
      is close to a no-op today.

    Note when working any of these: *Restrict deletions* is enabled on `protect-dev` and
    did **not** prevent `dev` from being deleted during the v0.2.0 promotion, because
    the ruleset's bypass list grants Repository admin *Always allow* (`ARCHIVE.md` §14,
    2026-08-02). Assume any rule configured here is advisory for the repository owner
    until the bypass list says otherwise. (The bypass list is not readable at the API
    permission level available to a code session — the ruleset endpoint returns
    `bypass_actors: null` — so confirm it in Settings rather than from an API dump.)
  - ~~**Signed-commit enforcement**~~ **Declined 2026-08-03** — every commit in this
    repo is authored by a Claude Code session pushing over local `git`, with no signing
    key present in that environment; requiring signed commits would reject every session
    push outright, and both workarounds (provisioning a signing key into a sandboxed
    session, or moving to API-authored commits) cost more than the friction they'd
    remove on a solo-maintainer repo. Revisit if a collaborator with write access is
    added, or if the commit workflow stops going through local git. See
    [`ARCHIVE.md` §14, 2026-08-03](./ARCHIVE.md).
  - ~~**Private vulnerability reporting**~~ — **Done; verified 2026-08-02.**
    `GET /repos/tyler-rich/Scrye/private-vulnerability-reporting` returns
    `{"enabled": true}`, so `SECURITY.md`'s stated channel exists. It is not recorded
    when this was turned on — it may have been enabled at any point since the repo went
    public and simply never struck from this list, which is the same drift this
    checklist was created to stop.

- ~~**Enable GitHub code scanning (CodeQL) for Python and TypeScript.**~~
  **Done 2026-08-02** — enabled via **default setup** on the **`security-extended`**
  query suite (a dropdown in the same settings pane; "default setup" names the setup
  mode, not the suite). Language auto-detection added a third language, **`actions`**,
  alongside Python and JavaScript/TypeScript. The first run covered every source file —
  174/174 Python, 78/78 TypeScript, 2/2 JavaScript, 5/5 workflows — and produced **six
  alerts, all Python, all assessed as false positives**: two `py/path-injection` on the
  filesystem-scan containment gate (`backend/app/scanners/targets.py:138` and `:144`),
  three `py/incomplete-url-substring-sanitization` on test assertions, and one
  `py/log-injection` on an `int`-typed path parameter (`backend/app/api/scans.py:574`).
  Full reasoning per alert, the reproduction method behind the numbers, and the
  recommended disposition for each are in [`ARCHIVE.md` §14, 2026-08-02](./ARCHIVE.md).

  ~~**Advanced setup was not taken.**~~ **Reversed 2026-08-02 — the migration is
  done.** Default setup's pull-request trigger targets the **default branch**, so PRs
  into `dev` — where day-to-day work is actually PR'd — got no CodeQL check at all
  (confirmed on #134, which got four check runs and no CodeQL among them). CodeQL
  therefore analysed `main` on push, *after* a promotion had landed, where a finding's
  remedy is a revert rather than a review comment, and where with several PRs in flight
  it is attributable to a batch rather than to the PR that introduced it.
  `.github/workflows/codeql.yml` now runs on `pull_request` and `push` for both `dev`
  and `main`, on the same `security-extended` suite, the same three languages and the
  same SHA-pinned `codeql-action` v4.37.4 default setup was running — so nothing about
  the analysis changed, only when it runs. Pinning the action does not pin the query
  packs (`init`'s `tools:` defaults to the recommended bundle), and Dependabot's
  existing grouped weekly `github-actions` PR carries the SHAs forward. **Default
  setup's weekly scan is carried over too** — `schedule: - cron: "0 4 * * 1"` — so a
  newly published query fires on its own rather than waiting for someone to touch a
  file in that language. One scope note, because it is not obvious: `on: schedule`
  **always runs against the default branch**, so that cron analyses `main`, not `dev`,
  and does not fire until `codeql.yml` reaches `main` via a promotion. `dev` is covered
  continuously by the push/PR triggers instead. See
  [`ARCHIVE.md` §14, 2026-08-02](./ARCHIVE.md).

  **The two settings edits that used to be listed here are done, verified live on
  2026-08-09.** A ruleset read shows all three contexts — `CodeQL — python`,
  `CodeQL — javascript-typescript`, `CodeQL — actions` — present in
  `required_status_checks` on **both** `protect-dev` and `protect-main`, and the
  committed workflow's checks run and pass on PRs into `dev`, which is only possible
  with default setup disabled (while it is enabled, the API rejects the workflow's SARIF
  outright). The same read shows `protect-dev` requiring `Backend — lint + tests`,
  `Frontend — lint + build`, and `Image — build + dogfood self-scan` alongside the three
  CodeQL contexts, with strict "require branches to be up to date" enforcement;
  `protect-main` requires Backend, Frontend, and the three CodeQL contexts. See
  [`ARCHIVE.md` §14, 2026-08-09](./ARCHIVE.md).

  ~~**Alert disposition.**~~ **Closed 2026-08-09** — the Security tab shows **0 open /
  6 closed** on both `branch:main` and `branch:dev`, verified directly in GitHub
  Settings/Security by the maintainer (not readable at the API permission level
  available to a code session). All six alerts from the first-run triage — recorded
  with their per-alert reasoning in [`ARCHIVE.md` §14, 2026-08-02](./ARCHIVE.md) — are
  accounted for. Nothing further to do here.

## Medium-term

Features and developer-experience investments with a larger surface.

- **Admin-issued OIDC link invitations.** Self-service linking shipped (a user binds
  their *own* account to an OIDC identity through the authorization-code flow). An admin
  binding an identity on someone *else's* behalf is deliberately absent and cannot be
  added as a text field: obtaining another person's `sub` requires **them** to
  authenticate at the IdP, and a type-in-a-subject fallback would reintroduce both the
  manual-determination problem and an arbitrary-binding surface. The correct shape, if
  demand appears, is an **invite link**: the admin generates a one-time token, the
  target user opens it and completes the OIDC handshake under it, and the binding lands
  on their account with the subject still coming only from the verified token. Worth
  doing for a bulk onboarding; not worth it for a handful of users, who can each link
  themselves in two clicks. (Email-based auto-linking stays rejected outright — it is a
  well-known account-takeover vector, not a missing feature.)
- **Uploaded image-tar (`docker save`) targets.** Both Trivy and Grype can scan a local
  image archive. Add a target type that accepts an uploaded `docker save` tarball, so an
  image can be scanned without a reachable registry.
- **Filesystem-archive upload target.** Grype filesystem scanning today is limited to a
  mounted host path under the admin-configured `SCRYE_FILESYSTEM_SCAN_ROOTS` allowlist.
  Add an archive-upload variant (upload a `.tar`/`.zip`, unpack into scratch, scan,
  discard) so a filesystem scan doesn't require pre-mounting the path into the
  container.
- **Docker-environment multi-select scan launcher.** The read-only `docker-socket-proxy`
  integration currently *enumerates* the images running in a Docker environment and lets
  you copy a reference to scan as a normal image target. Add a multi-select launcher
  that queues a scan for each chosen image in one action.
- **Cancel a running scan.** † *(prerequisite for heavier engines and any future
  endpoint-scanning target class)* Cancellation is currently limited to scans still in
  the `queued` state — the in-process worker has no channel to interrupt a live scanner
  subprocess. A cooperative-cancellation path (signal the subprocess, mark the scan
  canceled, clean up its scratch) would let a long-running scan be stopped.
- **Cross-version backup restore.** A restore requires the bundle's schema version to
  match the running installation. Add forward-migration of an older bundle on restore
  (run the Alembic chain against the imported data) so a backup taken on an earlier
  release can be restored onto a newer one.
- **Generated API client.** † *(one typed contract for the frontend and the Phase 4 MCP
  server — do this before the MCP server)* The frontend API layer is a thin,
  hand-written `fetch` wrapper (`frontend/src/api/*`). Generating a typed client from
  the FastAPI OpenAPI schema (e.g. openapi-typescript) over that wrapper would keep the
  client and server contracts in lockstep.
- **Single-source the version string, and stamp it into the image.** Two halves of one
  problem: the version is declared in several places and derived from none of them.

  *Single-sourcing.* The app version is declared independently in
  `backend/app/__init__.py`, `backend/pyproject.toml` and `frontend/package.json` (+ the
  lockfile's root fields), and nothing derives one from another or from the git tag — so
  a release has to touch several files in lockstep. `backend/tests/test_version.py` now
  fails on drift, which makes the duplication safe but not gone. Collapse it to
  `app.__version__` as the single source: `pyproject.toml` can pick it up via
  setuptools' dynamic version (`dynamic = ["version"]` + `[tool.setuptools.dynamic]
  version = {attr = "app.__version__"}`), and `frontend/package.json`'s copy — which is
  never bundled and never published (`private: true`), since the SPA reads the version
  from the About/health API at runtime — can be dropped to a fixed placeholder.

  *Image stamping.* `publish.yml` computes the image tag from the pushed ref
  (`${GITHUB_REF_NAME#v}`) but never stamps a version **into** the image: there is no
  `LABEL` in `docker/Dockerfile` and no `labels:`/`build-args:` in any of the three
  build workflows (`publish.yml`, `dev-nightly.yml`, `ci.yml` — none of them uses
  `docker/metadata-action`, which is what normally generates the OCI label set). So
  `docker inspect` on a published image reveals nothing about what is inside it, and an
  image whose tag was retagged or lost carries no self-description at all. This is
  **metadata hygiene, not a defect**: the running app reports its version correctly
  because `app/__init__.py` is baked in, and `/healthz` and the About tab both serve it.
  The fix is the standard OCI label set on the runtime stage — at minimum
  `org.opencontainers.image.version`, alongside `.title`, `.source`, `.revision` and
  `.created` — fed by a build arg the publish workflow already has in
  `steps.version.outputs.version`. Note the image is not wholly opaque today:
  `publish.yml` attaches BuildKit SLSA provenance (`provenance: mode=max`) and an SPDX
  SBOM (`sbom: true`) plus a GitHub-signed attestation, so the build is describable —
  just not through the one-command channel operators actually reach for.

  Both halves want their own PR and CI run rather than riding on a release bump; the
  label work also touches the runtime stage, so read `docs/ARCHIVE.md` § Build
  performance first. See `docs/ARCHIVE.md` § Deviations, 2026-07-29.
- **Type-checking in CI.** Add a Python type checker (mypy or pyright) to the CI gate.
  This first needs the existing annotation gaps resolved so the gate lands green rather
  than red.
- **Backend structural cleanup.** The four near-identical secret-CRUD routers
  (registries, git credentials, notification channels, OIDC) could be consolidated
  behind shared helpers to cut duplication. *(The list-response envelope half of this
  item is done — see `docs/ARCHIVE.md` § Deviations, 2026-07-25, and `CONTRIBUTING.md`
  § API conventions.)*

## Longer-term / speculative

Architectural directions, mostly gated on a scale threshold or an explicit decision.

- **Pluggable scale-out worker (arq / Redis).** The scan worker is a single-container,
  in-process async worker behind a small `ScanWorker` interface, deliberately so it can
  be swapped later. A Redis-backed queue (e.g. arq) would let scans run across multiple
  worker processes or containers for higher throughput — only warranted if a single
  instance's concurrency ceiling becomes the bottleneck.
- **Full-database encryption at rest (SQLCipher).** Secrets are field-encrypted at the
  application layer today (AES-256-GCM), which is the required baseline. SQLCipher would
  encrypt the *entire* database file at rest as defense-in-depth. A clean seam was left
  for it; adopting it is a deliberate future hardening step, not a v1 requirement.
- **Framed streaming backup encryption.** A backup bundle is assembled and encrypted in
  a single in-memory AES-GCM pass, so a very large findings table (hundreds of thousands
  of rows and up) needs container memory headroom proportional to the dump. A
  framed/streaming encryption format would bound backup/restore memory regardless of
  database size.
- **One-pass SBOM cataloging for Grype.** When an image scan generates a Syft SBOM, that
  SBOM could be fed directly into the same Grype run (one cataloging pass) instead of
  Grype re-cataloging the target. A modest efficiency win for combined SBOM-plus-vuln
  scans.
- **Native arm64 CI runners.** The multi-arch image build runs its arm64 leg under QEMU
  emulation, which is slow on a cold cache (cross-seeded caches mitigate this — see
  [`ARCHIVE.md` § Build performance](./ARCHIVE.md)). Switching the arm64 leg to native
  `ubuntu-24.04-arm` hosted runners (matrix build + manifest merge) would remove
  emulation from cold builds entirely. Now that the repository is **public**,
  GitHub-hosted arm64 runners are free — the cost concern that previously gated this is
  gone, making it a straightforward win whenever the multi-arch cold-build time becomes
  annoying.
- **`react-router` 7 → 8 — blocked on a React 19 decision, not on a tooling bump.**
  `react-router@8.3.0` (the current `latest`) declares `react: ">=19.2.7"` and
  `react-dom: ">=19.2.7"` as peer dependencies — verified at the published package on
  2026-08-09. Scrye pins **React and React DOM at 18.3.1**, so adopting the 8 line means
  first deciding to move the frontend to React 19: a deliberate choice about the app's
  foundation, reaching Mantine and every component in the tree, rather than a routine
  dependency bump. It is listed here for that reason and not alongside the toolchain
  currency work, which shares none of that constraint.

  Nothing forces the move. This is a **pure currency item with no security component**: it
  was once coupled to GHSA-qwww-vcr4-c8h2, but that advisory was closed by the **7.18.2**
  backport on 2026-08-02 and has since been re-cut upstream to exclude 7.18.2 entirely (see
  the struck item under Near-term), so there is nothing left for the 8 major to fix — do
  not re-argue it as a security fix. If and when React 19 is taken, the migration's own
  cost is that v8 folds `react-router-dom` back into `react-router`, so **every import site
  in `frontend/src/` moves** (twelve files today), plus whatever the type-aware ESLint gate
  makes of the new type surface.

---

# Track B — Features

New capabilities, grouped into phases by dependency and theme — not a schedule.

## Phase 1 — Prioritization & enrichment

No new binaries; everything later builds on these.

- **SARIF export.** SARIF 2.1.0, one `run` per engine; rules, results, locations,
  severities, and fix data populated from the normalized model; round-trips into GitHub
  code scanning and aggregators without parser errors; available via UI download and
  API. Every engine on this roadmap emits SARIF, so this compounds.
- **EPSS + CISA KEV enrichment.** Public feeds, scheduled sync, local cache,
  offline-graceful. EPSS score/percentile and a KEV flag on every finding, sortable and
  filterable, included in exports and SARIF; a configurable "fix-first" view combining
  severity + EPSS + KEV; **KEV remediation due dates surfaced as a countdown** where
  CISA has set one. Feed attribution handled per source at implementation.
- **End-of-life enrichment.** Flag base images, OS releases, and runtimes that are past
  or approaching end-of-life, using the public endoflife.date dataset. An EOL base gets
  no new fixes regardless of CVE count — a signal scanners don't surface clearly.
- **Noise controls.** Fixed-only filter, per-view persistence, reflected in exports.

## Phase 2 — Triage & decisions

The workflow layer: findings become decisions, and decisions have accountability.

- **VEX authoring.** Triage a finding in the UI → status + justification → a persisted
  OpenVEX document, auto-applied on rescan and **exportable so Trivy and Grype in CI
  honor the same decisions**. Layered over the VEX support that already exists (Trivy
  VEX + `.trivyignore` + Grype ignore).
- **Expiring acceptances & review dates.** Every acceptance carries evidence, a
  resolution trigger, and a review date; expired acceptances resurface as findings.
  Backed by the existing auth and audit log — suppression with accountability.
- **Fix-watch.** Track findings with no available fix across scheduled DB refreshes;
  when an advisory gains a fixed version, notify through the configured channels.
  *(Depends on content-addressed SBOM identity — Track A.)*
- **Scanner-disagreement queue.** Findings reported by one engine but not another,
  surfaced as a reviewable queue with per-item disposition — cross-validation turned
  into a workflow instead of a curiosity.
- **Base-image advisor.** Scan candidate base images and show the delta: "moving to
  `<candidate>` removes N of M findings." Curated candidate list plus operator-defined
  candidates.

## Phase 3 — Reporting & visibility

Scrye's history, made legible.

- **Trend analytics.** Severity-over-time per target and fleet-wide, new-vs-fixed
  rates, time-to-remediate, acceptance aging — a risk-burndown view over data Scrye
  already stores.
- **Scheduled digest reports.** A recurring "state of the fleet" summary delivered
  through existing notification channels: new findings, newly-fixable findings, expiring
  acceptances, drift since the last digest. Export as HTML/Markdown for sharing.
- **Audit evidence export.** A signed, self-contained bundle of a scan plus its
  decisions (acceptances, VEX statements, justifications, timestamps) suitable as
  compliance evidence.
- **Status badge endpoint.** A tokened, cache-friendly badge (shields.io-compatible) a
  project can embed in its README: current finding counts for a chosen target.
- **Kiosk / wall-dashboard mode.** A read-only, scoped token rendering a
  display-friendly posture dashboard for a TV or monitoring wall.
- **Saved views.** Persist and share filter/sort combinations across the findings UI.
- **ntfy and Gotify notification channels.** First-class support for the two most
  common self-hosted notification services, alongside the existing webhook, Discord,
  SMTP, and Matrix channels.

## Phase 4 — AI assist & MCP

- **AI-assisted triage (bring-your-own endpoint).** An optional, off-by-default module
  speaking to **any OpenAI-compatible endpoint the operator configures** — local on the
  same host, a machine elsewhere on the network, or a hosted provider; Scrye bundles no
  model, favors no provider, and ships no default endpoint. Configuration via
  environment / secret store (`AI_TRIAGE_ENABLED` default `false`,
  `AI_TRIAGE_BASE_URL`, `AI_TRIAGE_MODEL`, `AI_TRIAGE_API_KEY` as a secret reference,
  `AI_TRIAGE_TLS_VERIFY` / custom CA path, timeout / token / rate-limit guardrails, and
  `AI_TRIAGE_REDACT`). Capabilities, all advisory and human-confirmed: scan summaries,
  plain-language CVE explanations in the finding drawer, drafted VEX justifications for
  Phase 2, cross-engine clustering suggestions, and drafted report text from a scan
  diff. Data-egress disclosure at enable-time and per use; the redaction toggle strips
  paths, hostnames, and secret snippets before sending; failures never block a scan;
  fully inert when disabled — no outbound calls.
- **Built-in MCP server.** Expose Scrye to MCP clients so operators can query posture,
  diff scans, and review acceptances from their tools of choice. Security posture:
  authentication required before any response including `tools/list`, reusing existing
  API tokens and RBAC — an MCP session has exactly the permissions of the token that
  opened it; streamable HTTP behind the documented reverse-proxy guidance;
  **read-only tool set at launch** (query scans, findings, diffs, acceptances,
  targets), with mutating tools added later behind individually scoped tokens; tool
  descriptions are static, never built from scanned content; input validation on every
  parameter; rate limiting; every call in the audit log; disabled by default. *(Builds
  on the generated API client in Track A — do that first.)*

## Phase 5 — Continuous scanning & supply chain

- **Registry-watch / auto-scan.** Webhook-triggered scans on push (Harbor, GHCR, Docker
  Hub, Quay) plus scheduled re-scans of stored SBOMs as vulnerability databases update.
  Per-registry configuration, rate limiting, and a clear audit trail; registry
  credentials via the existing secret handling.
- **Running-fleet drift.** Via the existing read-only Docker socket proxy: compare what
  is *running* against what is *current* — "this image's tag moved; the new digest
  closes 6 criticals."
- **Kubernetes cluster targets.** Enumerate images running in a cluster through a
  read-only, operator-supplied kubeconfig — the cluster analogue of the Docker
  socket-proxy integration — and scan them individually or in bulk.
- **SBOM diffing.** Package and CVE delta between any two selected artifacts.
- **Cosign / Sigstore.** Optional signature verification before scanning; sign
  generated SBOMs; keyless (OIDC) and key-based flows documented.
- **Outbound event webhooks.** Stable, schema'd events (`scan.completed`,
  `finding.new`, `acceptance.expired`, …) as the automation primitive for pipelines not
  using the MCP server.
- **OSV-based third engine (spike-gated).** A native PURL matcher (Syft SBOM → matcher
  → local OSV mirror in SQLite), evaluated **as an additional engine alongside Trivy and
  Grype** on a pinned image corpus, with OSV data licensing resolved per-record before
  any build. Proceeds past the spike only if distro-backport accuracy holds up against
  the incumbents. Never CPE-based.
- **Push to Dependency-Track / DefectDojo.** Operator-configured, off by default, for
  deployments that already run an aggregation hub; push on scan completion; failures
  surfaced, not silent.

## Phase 6 — Ecosystem & team workflow

- **CI/CD action + policy gate.** A GitHub Action and GitLab template calling Scrye's
  API, with a policy gate (OPA/Conftest) failing builds on configurable thresholds
  combining severity + EPSS + KEV — and honoring the VEX documents authored in Phase 2,
  so CI enforces the decisions made in the UI.
- **Ticketing.** Auto-open findings as issues in GitHub, GitLab, Jira, or
  Gitea/Forgejo; configurable per provider; deduplicated against existing issues;
  templated issue body with finding detail and remediation; off by default.
- **Finding ownership & assignment.** Assign findings or targets to users; assignments
  feed the digest reports and the ticketing integration.
- **OpenGrep SAST.** A net-new scan class on the existing repository-scan checkout.
  LGPL-2.1 engine invoked subprocess-only (never statically linked), shipping with
  openly licensed rules — not Semgrep's maintained rules, whose license restricts use in
  hostable tools; operator can supply custom rules. Language coverage documented;
  performance bounded.

---

## Deferred

Welcome contributions, not currently scheduled:

- **Gitleaks** (MIT) — secrets second opinion with git-history depth
- **Checkov / KICS** (Apache-2.0) — IaC second opinions with deeper policy libraries
- **Hadolint** (GPL-3.0) — Dockerfile build-hygiene lint; sidecar only, per the
  licensing policy
- **Nuclei** (MIT) — template-driven checks against running endpoints; a new
  *running-service* target class needing its own authorization and blast-radius
  guardrail design; gated on scan cancellation (Track A) landing first
- **cve-lite-cli** (MIT, OWASP Lab) — JS/TS remediation-first guidance
  (parent-aware transitive fix commands, fix-version validation) as an opt-in Node
  sidecar; core image unchanged when disabled
- **OSV-Scanner binary** (Apache-2.0) — held pending the native-matcher spike, which
  would make it redundant

## Out of scope (policy)

- AGPL-licensed engines in the core image — permissive equivalents are preferred; see
  the licensing policy
- Semgrep-maintained rulesets — their license restricts use in hostable tools;
  OpenGrep's open rules are used instead
- Bundling any specific LLM or model — the AI module is bring-your-own-endpoint

## Licensing & bundling policy

Scrye is MIT-licensed and invokes scanners as separate CLI binaries over a process
boundary (subprocess), not as linked libraries, so the copyleft "derivative work"
trigger is generally avoided (mere aggregation). Placement rules:

| Tool license | Where it may ship | Rationale |
|---|---|---|
| **Permissive** (MIT, Apache-2.0, BSD) | Core image | No obligations that conflict with MIT; safe to bundle and redistribute. |
| **LGPL** (e.g., OpenGrep) | Core image, **subprocess only** | Fine when invoked as a separate program; do **not** statically link into Scrye's own binaries. |
| **GPL-2.0 / GPL-3.0** (e.g., Hadolint) | **Opt-in sidecar** | Mere aggregation keeps Scrye's MIT code MIT, but shipping the GPL program still carries source-offer/notice obligations. Isolating it keeps the core clean and the obligation self-contained. |
| **AGPL-3.0** | **Not bundled** | AGPL's network clause is the sharp edge for a network-served app. Prefer a permissive alternative; if truly needed, operator-supplied external sidecar only. |
| **Proprietary / source-available with SaaS restrictions** | Not bundled | Terms often bar use in a competing hostable tool. Use the permissive fork/feed instead. |

Two rules for every engine PR: **re-verify the license at integration time** (projects
relicense — with a link in the PR), and **prefer the permissive equivalent** when one
exists. Data feeds (EPSS, KEV, OSV, endoflife.date) additionally carry attribution
obligations resolved per source — for OSV, per record — at implementation time.

## Guiding principles

1. **Normalize, don't fragment.** Every engine's output maps into the shared findings
   model; a new engine isn't done until its results dedupe and render alongside
   existing ones.
2. **Cross-validation is a feature.** Second-opinion engines add coverage and are
   labeled as such.
3. **Security-first, minimal core image.** Small, non-root, read-only,
   least-privilege, dogfooded by CI. Anything that materially grows the attack surface
   belongs in an opt-in sidecar.
4. **Opt-in by default for anything external.** Integrations that send data off-box are
   inert until configured and transparent about what leaves the instance.
5. **Advisory, not autonomous.** Automated remediation, suppression, and AI output are
   suggestions surfaced to a human; nothing mutates state without explicit
   confirmation.

## Known limitations & accepted trade-offs

On the record and unlikely to change without a specific reason — documented here so a
deployer isn't surprised.

- **OIDC delegates MFA to the identity provider.** The mandatory-MFA policies
  (`required_all` / `required_admin`) are enforced on **local** password login. OIDC
  logins have no local TOTP step in the handshake, and provisioned OIDC accounts carry
  no usable local password — so an OIDC user's second factor must be enforced at the IdP
  (e.g. Pocket ID). This is an accepted limitation, not a planned change; gating it at
  Scrye's layer would lock out OIDC accounts that have no local password. (When
  group→role mapping is configured it is re-applied on each login, but an absent groups
  claim preserves the current role, and an OIDC sync can never remove the last admin.)
  **Account linking widened this** from provisioned accounts to any linked account,
  including MFA-enrolled admins — a linked admin's local TOTP challenge never runs on
  the OIDC path. The bound cost is that link and unlink both require fresh full
  re-authentication (password + current TOTP when enrolled), so a stolen session cannot
  create the bypass path; the UI warns before linking and both events are audited. See
  the README security model.
- **Cloud registry credential helpers are not bundled.** Static registry credentials
  and tokens work out of the box. The ECR / GCR / ACR credential-helper *configuration*
  is generated at scan time, but the helper binaries themselves are not shipped in the
  image — those registry types work only where the matching helper is present in the
  runtime environment, as a deployment add-on. Bundling them would bloat the image and
  pull in unvetted dependencies.
- **Bundled scanner binaries track upstream for CVEs.** Trivy, Grype, and Syft are
  shipped as unmodified upstream Go binaries under Apache-2.0. CVEs in *their* embedded
  Go modules or the Go standard library are fixed only when Aqua/Anchore cut a new
  release built against a patched Go, so they're excluded from Scrye's own CI dogfood
  gate (they remain visible in the informational scan report). Keeping the pinned
  scanner versions current is how those are addressed — Scrye's own attack surface (base
  image, OS packages including `git`, Python/JS deps, app code) stays fully gated.
- **The optional `trivy-server` sidecar runs as root.** The upstream `aquasec/trivy`
  image ships no non-root `USER` and hard-codes its cache under `/root/.cache`, so
  running it as an arbitrary uid breaks the DB cache on a root-owned named volume. The
  sidecar is optional (profile-gated), reachable only on the internal network, and
  otherwise hardened (read-only root FS, `no-new-privileges`, `cap_drop: ALL`,
  resource-limited). Rebuilding it on a non-root base with a writable cache path is a
  possible future hardening.
- **Very large backups need memory headroom.** See the framed-streaming item above —
  until that lands, sizing container memory to the dump is the operational answer, and
  Scrye logs a warning past the threshold.
