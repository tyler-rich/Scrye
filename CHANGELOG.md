# Changelog

All notable changes to Scrye are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **`postcss` bumped 8.5.16 → 8.5.25, closing GHSA-r28c-9q8g-f849** (HIGH) — path
  traversal in PostCSS's previous-source-map auto-loading, where a crafted
  `sourceMappingURL` comment could make PostCSS read an arbitrary `.map` file from
  disk and inline it into the generated source map. Unlike the `brace-expansion`
  bump in 0.2.0, this one **does** clear its advisory: the containment check in
  `lib/previous-map.js` was verified present in the published 8.5.18 source (the
  real fix floor) and still present in the pinned 8.5.25.

  `postcss` is a `devDependency` that runs during `vite build`; the runtime image
  copies only the built `dist/` output, so no deployed Scrye was ever exposed and
  nothing about the shipped image changes. Tracked in #124.

### Changed

- **The SPA is now built on Node 24 (`krypton`), the Active LTS.** The image's
  `frontend-builder` stage and CI's frontend job moved together from Node 22,
  which is in maintenance and supported only through 2027-04-30; 24 is supported
  through 2028-04-30. Node is a build-time toolchain that never reaches the
  runtime image, so nothing about a deployed Scrye changes — no dependency,
  bundle or behaviour moves, and the lint/test/build gate was verified green on
  Node 24.18.1 before the bump. The documented requirement for native
  development is now **Node 22+** (it named the end-of-life 20 line before).
- `docker/login-action` pinned to v4.6.0 in the GHCR publish, nightly and re-scan
  workflows. No behaviour change for Scrye — the release hardens buildx-scoped
  config-path handling, which is gated on a `scope` input none of the call sites
  passes.
- `fastapi` bumped 0.140.0 → 0.140.13 (dependency currency; the intervening fixes
  are all on streaming, `jsonable_encoder` and OpenAPI-flattening paths Scrye does
  not use), with `backend/requirements.lock` regenerated.

## [0.2.0] - 2026-07-31

### Added

- **A plain-HTTP deployment now explains itself instead of looking broken.**
  Scrye marks its session cookie `Secure`, and browsers refuse to store a `Secure`
  cookie on an `http://` page — so deploying over plain HTTP produced repeated
  401s with correct credentials, with nothing in the logs or the UI to say why.
  Nothing about the cookie posture changes; the failure is now legible:

  - **Startup** logs whether HTTPS enforcement is on and, when it is, that logins
    over plain HTTP will fail unless the operator opts out — naming
    `SCRYE_SESSION_COOKIE_SECURE=false` explicitly. With it off, a warning states
    that session cookies now travel in cleartext.
  - **Sign-in** (password login, first-admin setup, MFA verification and the OIDC
    handshake) is **refused** with `503` and a transport-specific message rather
    than returning a session the browser will discard. The log says plainly
    whether the submitted credentials were valid — a valid-credential rejection
    for this reason never reads as a bad-password 401 — and a distinct
    `auth.login_blocked_insecure_transport` audit entry is recorded. The
    client-visible refusal is byte-identical for valid, invalid, and unknown
    accounts, so it discloses nothing. First-admin setup is refused **before** the
    account is created, so bootstrap stays re-runnable.
  - **The login and setup screens** show a banner explaining that this is an HTTPS
    configuration issue and not wrong credentials, with the three fixes. It is
    driven by `/auth/status` and appears before anything is typed, so it never
    reflects credential state.

- **`X-Forwarded-Proto` is honored from configured reverse proxies.** A
  TLS-terminating proxy can now tell Scrye the client is on HTTPS even though
  Scrye's own listener sees plain HTTP, so shape-2 deployments satisfy the
  sign-in check. Trust is limited to the peers already named in
  `SCRYE_FORWARDED_ALLOW_IPS` (never blanket), and the header can only *upgrade*
  the scheme `http` → `https`, never downgrade it. Scrye still **never** drops
  `Secure` from an auto-detected scheme: that would silently downgrade every
  deployment behind a TLS-terminating proxy. See README
  § "If you're not using HTTPS".

- **Settings → About now shows which master key the instance is using.** Admins
  see the source and the path — "auto-generated at `/data/app_secret_key` — back
  this up; a Docker secret gives stronger at-rest separation", or "supplied as a
  secret file at `<path>`" for a Docker secret. The row carries **no key material**
  (and no key version), is **admin-only** — the About tab itself is readable by any
  role, and an admin's role-capped API token doesn't see it either — and is omitted
  entirely when no key resolves. This is the durable place to find the "back it up"
  fact months after deploying, which a one-time startup log line is not.

- **The master key is generated automatically on first launch, so a new
  deployment starts with no pre-seeded secret.** Previously the container would
  not start until you had run `openssl rand -base64 48` into
  `secrets/app_secret_key` — and because Compose requires a `secrets:` file to
  exist before it will even read the stack, that was a hard first-run blocker
  rather than a startup error you could read. With no key supplied, Scrye now
  mints one from the OS CSPRNG (48 random bytes base64-encoded — the exact
  `openssl rand -base64 48` equivalent, clearing the existing entropy floor),
  writes it to `/data/app_secret_key` with mode `0600`, verifies those
  permissions off disk, and logs one INFO line saying where it went and that it
  **must be backed up**. Concurrent starts cannot both generate: the file is
  created with `O_CREAT|O_EXCL` and the loser reads the winner's key.

  **Precedence is unchanged where it already existed.** A Docker secret at
  `SCRYE_APP_SECRET_KEY_FILE` still wins over everything; generation is the last
  resort, and only when no key file exists. Two new settings control it:
  `SCRYE_APP_SECRET_KEY_AUTOGENERATE` (default `true`) and
  `SCRYE_APP_SECRET_KEY_AUTOGEN_FILE` (default `/data/app_secret_key`).

  **An existing key file is never replaced.** A key file that exists but cannot be
  loaded — unreadable, empty, not base64, too short, malformed — now fails startup
  instead of ever being regenerated, because a second key would leave every stored
  secret undecryptable while the app looked healthy. For the same reason: a *set*
  `SCRYE_APP_SECRET_KEY_FILE` pointing at a missing file is a startup error, not a
  cue to generate one; and a supplied secret alongside a previously auto-generated
  key that it does not cover stops startup until the two are reconciled.

  **Existing deployments are unaffected** — their key file is found exactly as
  before, and no stored ciphertext changed (no KDF or token-format change). **New
  deployments must back up `/data/app_secret_key`**: lose it and every stored
  secret is unrecoverable. See [The master key](README.md#the-master-key), which
  now documents the precedence order, the loss consequences, and the trade-off of
  the generated key living on the same volume as the database it protects.

  `docker/docker-compose.yml` and the README paste-in stack no longer require the
  secret; the Docker-secret blocks are kept, commented out, for deployments that
  want the key and the data on separate mounts.

- **Scan history is deep-linkable.** Filters, date range, sort and page are read
  from the URL on mount and mirrored back into the query string, so Back,
  bookmarking and sharing a filtered view all work. Defaults are omitted from the
  URL, so an unfiltered history page still has a clean address.

- **A filtered-history export says when it was truncated.** Exports are capped at
  5 000 rows; hitting the cap is now reported in the JSON metadata, as a note in
  the Markdown and CSV output, and in `X-Scrye-Truncated` / `X-Scrye-Total`
  response headers, rather than silently returning a short file.

- **Accessibility.** The history table is keyboard-navigable with sortable column
  headers exposing `aria-sort` and rows as real links; loading spinners announce
  themselves through a polite live region instead of being silent; the dashboard's
  chart bars are exposed as images with their existing labels; the New scan,
  scan-detail and MFA controls gained accessible names; and a Burger + Drawer
  navigation fallback appears below the `sm` breakpoint.

### Fixed

- **An unwritable data directory now reports what is wrong and how to fix it,
  instead of a SQLite stack trace.** The container entrypoint checks that the
  database directory exists and is writable **before** running migrations. The
  previous symptom was `sqlite3.OperationalError: unable to open database file`
  from Alembic, which named neither the path nor the cause; the preflight now names
  the directory, the container `uid:gid`, and the concrete fix. This is the most
  common first-run failure on NAS platforms (Synology, QNAP), where a **bind mount
  keeps the host directory's ownership** while a named volume inherits the correct
  ownership from the image — so `chown -R 1000:1000 /path/on/host`, a matching
  `user:`, or a named volume all resolve it.

  The master-key errors in the same class were made equally actionable: an
  unwritable key directory now names the directory, the uid:gid and the `chown`,
  and a filesystem that *synthesizes* ownership (a CIFS/SMB mount with `uid=`, NFS
  squashing) says so explicitly — `chown` cannot help there, so it points at
  matching the container `user:` or supplying a Docker secret instead. README
  § Troubleshooting first-run issues covers both.

- **Scans no longer get stuck `queued` or `running` until a restart.** Three
  failures compounded into one symptom. The worker's database commits now retry
  with backoff on SQLite lock contention instead of giving up under a large
  findings flush; a successful scan's artifacts are unlinked only after the final
  commit attempt fails, not the first; and a watchdog on every maintenance tick
  re-submits `queued` scans that have no live task and fails task-less `running`
  ones, so both families self-heal within a tick rather than needing a restart.

- **A cancelled or timed-out scan no longer leaves orphaned processes behind.**
  Scanner and git subprocesses are spawned as their own process group and the
  whole group is killed on every abort path — output-cap overflow, timeout, and
  shutdown. Previously only the direct child was signalled, so `git clone`'s
  `git-remote-https` and any Trivy/Grype helpers survived the kill.

- **A large scan result no longer stalls the whole app while it is parsed.**
  Scanner JSON parsing and normalization run in a worker thread. On a result
  large enough to matter, the event loop stayed blocked for the duration, so
  every other request — including `/healthz` — waited behind it.

- **A minutes-long scan no longer holds a database connection for its duration.**
  The worker resolves its inputs up front, returns its pooled connection, runs the
  scanner holding none, and re-acquires only to persist. The pool is also sized
  from `max_concurrent_scans`, which is now bounded to 1–32.

- **Shutdown is bounded and can no longer be skipped.** Lifespan teardown is
  shielded and each component shuts down under its own error handling, so one
  failure or a second cancellation cannot abandon live scanner subprocesses; each
  scheduler's shutdown is time-bounded so a wedged task is abandoned rather than
  running past `SIGKILL`; and the Compose stack allows a 30s stop grace period.

- **A backup taken while a scan was running could tear.** `build_bundle` now reads
  every table inside a single read snapshot, and a scheduled backup defers (and
  retries next tick) while any scan is queued or running — mirroring the guard
  manual restore already had.

- **A failed credential or filter list no longer looks like "none configured".**
  Both were swallowed by empty `catch` blocks, so a fetch failure was
  indistinguishable from an empty list — an operator could launch a private-image
  or private-repository scan **anonymously**, believing no credential was saved,
  and only find out minutes later from an opaque auth error. New Scan now shows a
  warning with a Retry action above the credential picker, and Scan history shows
  an inline warning that its lists may be incomplete.

- **Sign-in and sign-out races.** A status refresh already in flight could
  overwrite a completed login, MFA verification or first-admin setup and drop the
  shell back to the login screen; running the other way, a refresh answered before
  a session was revoked could restore the signed-out session and flash the
  authenticated shell. Both directions are now sequenced, so a completed
  authentication is never undone by an in-flight refresh and a logged-out session
  is never restored by a late one. ([#83](https://github.com/tyler-rich/Scrye/issues/83))

- **Frontend lifecycle correctness.** Settings forms no longer render editable
  before their initial load resolves, so a slow response cannot be saved over with
  defaults; the scan-detail poller backs off exponentially and halts after a
  failure ceiling instead of hammering a failing endpoint behind a stale "running"
  badge; history and findings fetches use a latest-wins guard so out-of-order
  responses cannot render results for a filter no longer selected; a status poll no
  longer wipes an in-progress tag edit; per-scan state resets on navigation so two
  scans cannot mix; the compare selection is reconciled against the visible rows so
  it cannot diff a deleted scan; and mutation triggers are guarded in-flight —
  most importantly stopping a double-click from minting an invisible second API
  token.

- **API-layer fixes.** A schema-validation `422` now renders its reason in the UI
  instead of an empty error; a Trivy ignore rule's timezone offset is no longer
  silently dropped; scan comparison includes `location` in the diff identity for
  non-vulnerability findings and checks `target_type` before offering a compare;
  and update paths for secret-bearing resources re-establish their create-time
  invariants — a mandatory notification secret cannot be cleared, and a registry
  update cannot blank a username.

### Changed

- **The Compose stack no longer uses `deploy:` keys, so it deploys on NAS
  container platforms.** Synology Container Manager and QNAP Container Station
  reject or mishandle the Swarm-oriented `deploy:` block, which
  `docker/docker-compose.yml` used to carry on all three services — the stack
  simply would not deploy there, even though Compose v2 honours `deploy:`
  standalone.

  **Memory limits are unchanged in effect and still on by default**, now written
  with the portable `mem_limit` / `mem_reservation` keys: `scrye` 2g (256m
  reserved), `trivy-server` 1g, `docker-socket-proxy` 64m. Compose treats these
  and `deploy.resources.limits.memory` as the same field.

  **CPU limits moved to a new opt-in overlay,
  `docker/docker-compose.cpu-limits.yml`**, rather than being deleted — the caps
  (`scrye` 2.0, `trivy-server` 1.0, `docker-socket-proxy` 0.5) are a hardening
  measure and the 0.5 cap on the socket proxy in particular is deliberate. Apply
  it with a second `-f`:

  ```bash
  docker compose -f docker/docker-compose.yml \
                 -f docker/docker-compose.cpu-limits.yml up -d
  ```

  **Action required only if you want CPU caps back:** add that second `-f` (on
  every command for the stack, not just `up`), or set `COMPOSE_FILE` once. A
  plain `docker compose up` now starts without CPU limits; memory limits apply
  either way. If you deploy with your own Compose file, the paste-in stack in the
  README changed the same way. See
  [Resource limits](README.md#resource-limits-and-nas-platforms).

- **The backend runtime moved from Python 3.13 to Python 3.14.** The image is
  built on `python:3.14-slim-bookworm`, digest-pinned to **3.14.6**. The floor is
  3.14.6 and not lower: 3.14.0–3.14.4 shipped an incremental garbage collector
  that let resident memory grow several-fold in long-running servers, reverted in
  3.14.5. Native (non-container) development now needs Python 3.14.

  **No interpreter CVE is cleared by this move.** It was scoped on the premise
  that 3.14.6 carried the **CVE-2025-15366** / **CVE-2025-15367** (imaplib/poplib
  command injection) fixes. It does not: released 3.14.6 has neither guard, so the
  upgrade cleared nothing at the version the image pins. **CVE-2026-15308** and
  **CVE-2026-12003** were already known to be unaffected by the move. All four stay
  waived in the dogfood scan.

  What *has* changed is the outlook, and only for one of them. Three of the four —
  CVE-2026-15308, CVE-2026-12003 and **CVE-2025-15366** — now have their fixes
  merged on the CPython `3.14` maintenance branch and unreleased, so they close on
  the next point release, **3.14.7**; they are tracked in **issue #98** with a
  2026-10-25 review. Only **CVE-2025-15367** (poplib) is genuinely unfixable below
  3.15 — its fix exists on `main` alone with no backport to any maintenance branch —
  and it is a standing accepted risk with an annual re-confirmation, tracked in
  **issue #52**. An earlier version of this entry said all four were unfixable until
  3.15 and pointed at #52 for all of them; both statements were wrong, and the
  imaplib backport had in fact merged before this entry was first written. (Three
  further interpreter CVEs — the `tarfile` set — were waived later in this cycle
  and are not part of these four; see **Security** below for the full waived set.)

  Dependencies bumped for 3.14: `pydantic` 2.10.4 → 2.13.4, `uvicorn[standard]`
  0.34.0 → 0.51.0, `sqlalchemy` 2.0.36 → 2.0.51, and a new explicit
  `greenlet` 3.5.4 pin for SQLAlchemy's async support. The pydantic bump is
  behaviour-neutral for API consumers: the only OpenAPI-schema change is that
  fields typed as a bare object now state `"additionalProperties": true`
  explicitly, which was already implied.

  **No action required for deployments** — pull the new image. Only contributors
  running the backend natively need to recreate their virtualenv on 3.14.

- **List endpoints returning persisted resources now use the shared
  `{total, items}` envelope.** Thirteen endpoints that previously returned a
  bare JSON array now return `{"total": <int>, "items": [...]}`, matching the
  shape `/api/scans/history`, `/api/scans/{id}/findings`, and `/api/audit`
  already used:

  `GET /api/registries` · `GET /api/git-credentials` · `GET /api/users` ·
  `GET /api/notifications` · `GET /api/scan-schedules` · `GET /api/api-tokens` ·
  `GET /api/backups` · `GET /api/filter-presets` ·
  `GET /api/docker-environments` · `GET /api/trivy/vex-documents` ·
  `GET /api/trivy/ignore-rules` · `GET /api/auth/sessions` ·
  `GET /api/scans/{id}/artifacts`

  These endpoints remain unpaginated, so `total` always equals `items.length`
  today. Enveloping them now means pagination can be added later as a purely
  additive `limit`/`offset` parameter rather than as a second breaking change.

  The convention that decides a new endpoint's shape: **persisted resource
  collections** get the envelope; **fixed enumerations and live, non-persisted
  data** stay bare arrays. Four endpoints are therefore deliberately unchanged —
  `GET /api/registries/options`, `GET /api/git-credentials/options`,
  `GET /api/notifications/events`, and
  `GET /api/docker-environments/{id}/images`. See `CONTRIBUTING.md`
  § API conventions.

  **Action required for API-token consumers only.** Scripts calling any of the
  thirteen endpoints above must read the rows from `.items`
  (`resp.json()["items"]` instead of `resp.json()`). The Scrye web UI is
  unaffected — it unwraps the envelope in its API client, and no page behavior
  changed. (L13 / APIR-8 — see [`docs/ARCHIVE.md` §15](docs/ARCHIVE.md#15-finding-id-index-decoder-for-14s-citations))

- **`GET /api/scans` is deprecated** in favour of `GET /api/scans/history`. It
  returns a bare array with no total, so a client paging through it cannot tell
  when the results are exhausted. Its response shape is a frozen contract and is
  **unchanged**; only the OpenAPI `deprecated` marker and a description naming
  the replacement were added. `/api/scans/history` supersedes it with the full
  filter set and the standard `{total, items}` envelope.

- **Docker socket proxy migrated to `wollomatic/socket-proxy`.** The optional
  `docker-env` sidecar — the only container in the stack that mounts
  `/var/run/docker.sock` — now runs `wollomatic/socket-proxy` (a from-scratch Go
  binary running as uid 65534, digest-pinned) instead of
  `tecnativa/docker-socket-proxy` (HAProxy on Alpine, running as root). Its
  request allowlist is pinned to the **single** endpoint Scrye calls,
  `GET /images/json`; every other path is refused with 403 and every other method
  with 405 before reaching the socket, and only the `scrye` container may connect.
  The previous configuration allowed the whole `/images` and `/containers` GET
  surface — including `/containers/{id}/json` (container environment variables),
  `/containers/{id}/archive`, and `/containers/{id}/export` — to any client on the
  Compose network. The sidecar also no longer needs a writable `/run` tmpfs.
  ([#63](https://github.com/tyler-rich/Scrye/issues/63))

  **Action required if you use the `docker-env` profile:** the proxy now runs
  unprivileged and must be given the host's docker group id to read the socket —
  set `DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"` before
  `docker compose --profile docker-env up`. Derive it rather than trusting the
  Compose fallback of `999` — that is a convention, not a guarantee, and the
  Debian host this was verified on used `989`. A wrong value crash-loops the
  sidecar (STATUS `Restarting`) and leaves image enumeration returning 502; it
  does not affect the rest of Scrye. No Scrye configuration changes;
  `SCRYE_DOCKER_PROXY_URL` and port 2375 are unchanged.

- **Three smaller API response changes**, all narrower than the envelope change
  above but worth knowing if you parse responses yourself:

  - **Timestamps serialize with an explicit `Z`.** Every response timestamp is now
    `2026-07-31T05:00:00Z` rather than bare ISO-8601. Storage is unchanged. This is
    additive for any consumer that parses ISO-8601 correctly, but a consumer that
    string-matches or assumes a fixed length will see the difference.
  - **`GET /api/audit` renamed its envelope key `entries` → `items`**, matching the
    `{total, items}` shape everything else uses. Admin-only, and the web UI was
    updated with it.
  - **Scan rows in list, history and dashboard responses no longer carry `options`
    or `error`.** They carry a boolean `has_error` instead; the full fields remain
    on the single-scan detail response. Fetch the scan by id if you need them.

### Security

- **A repository scan can no longer be pointed at the container's own
  filesystem.** A `repository` target was validated only for length and a leading
  `-` before being handed to `trivy repo`, which also accepts a **local path** — so
  a target of `/data` or `/run/secrets` walked the container filesystem and
  persisted the result as a downloadable artifact. That is the arbitrary-file read
  the `SCRYE_FILESYSTEM_SCAN_ROOTS` allowlist exists to prevent, reached through a
  path the allowlist never covered, and it exposed the SQLite database and the
  master key. A `repository` target must now be a **remote clone URL** (`http`,
  `https`, `ssh` or `git`); anything else is refused at request time with a 422.
  Scheduled scans are covered by the same validator.

  **Action required only if you scanned a local path this way.** There was no UI
  or configuration for it and the field has always been documented as a clone URL,
  so most deployments are unaffected. Local directories are still scannable via a
  **filesystem** scan, which remains gated by `SCRYE_FILESYSTEM_SCAN_ROOTS`.

- **Server-side fetchers no longer reach private addresses by default.** A new
  egress guard screens the notification (webhook/SMTP/Matrix) and registry-probe
  fetchers: loopback and cloud-metadata addresses are **always** refused, and
  RFC-1918/private ranges are refused unless `SCRYE_ALLOW_INTERNAL_EGRESS` is
  enabled. The Docker-proxy fetcher is exempted from the private-range rule — it is
  internal by design — but still refuses loopback and metadata.

  **Action required if any notification target or registry lives on your LAN**,
  which for a self-hosted deployment is likely: set
  `SCRYE_ALLOW_INTERNAL_EGRESS=true`.

- **The master key must now carry real entropy.** The key file must be valid
  base64 decoding to at least 32 bytes. **The KDF and the on-disk token format are
  unchanged, so all existing ciphertext still decrypts** — this is input validation
  only.

  **Action required if your key file holds a raw passphrase**, which v0.1.0
  accepted: the container will not start. Do **not** simply generate a new key —
  that leaves every stored secret undecryptable. Set the temporary escape hatch
  `SCRYE_ALLOW_WEAK_MASTER_KEY=true` to boot (every load under it warns), take a
  backup, then restore under a strong key and remove the opt-out.

- **A scanner-supplied URL can no longer be rendered as a live link, and every
  response carries a security-header baseline.** A finding's scanner-derived
  `primary_url` is rendered as a link only if it is a well-formed `http`/`https`
  URL — `javascript:`, `data:` and malformed values render as inert text — with
  `rel="noopener noreferrer"`. Alongside it, every response now carries
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`, and a Content-Security-Policy
  with `script-src 'self'`, `object-src 'none'` and `frame-ancestors 'none'`. The
  interactive API docs at `/docs` and `/redoc` are exempt from the CSP only, since
  they need inline scripts. The CSRF double-submit design is unchanged.

- **Stored secrets bind to their row, not just their column.** Field-encryption
  AAD is now `<table>.<column>:<row-id>`, so a ciphertext lifted from one row
  cannot be replayed into another. **Migration-free:** decryption tries the
  row-bound tag and falls back to the column tag, so existing ciphertext still
  decrypts and each secret upgrades on its next write.

- **Restore and backup hardening.** A restore takes the write lock up front and
  re-checks its "no scans in flight" guard **inside** the transaction (returning
  409 rather than racing the check), and pauses the worker for its duration.
  Passphrase-KDF parameters supplied by a restored bundle are clamped rather than
  trusted, and the memory budget is a fixed constant instead of being derived from
  the bundle's own numbers — an untrusted bundle can no longer drive the host out
  of memory.

- **Log redaction covers more shapes**, so a secret carrying spaces or commas in an
  unquoted `key=value` pair is redacted whole rather than to its first token. This
  over-redacts trailing free text after such a pair, which is the accepted
  trade-off.

- **Rate-limiter and MFA-challenge memory are bounded.** The rate limiter evicts
  expired keys once its map grows past a threshold, and concurrent pending MFA
  challenges are capped per user.

- **Supply chain.** Backend dependencies install from a fully-resolved,
  hash-verified `backend/requirements.lock` with `pip --require-hashes`, and CI
  fails on lock drift. Every GitHub Action is pinned to a commit SHA and the
  publish workflows' checkouts are hardened. Published images carry a BuildKit
  **SLSA provenance** attestation (`mode=max`), an **SPDX SBOM**, and a
  GitHub-signed build-provenance attestation you can check with
  `gh attestation verify oci://ghcr.io/tyler-rich/scrye:0.2.0 --owner tyler-rich`.
  The Dockerfile **cosign-verifies** each scanner's checksum file — keyless, with
  the certificate identity pinned to that project's release workflow — before
  verifying and extracting the binary. A weekly workflow re-scans the *published*
  images and opens a tracking issue when a newly disclosed fixable HIGH/CRITICAL
  appears, rather than waiting for the next release to notice. The backend test
  suite and dev scripts no longer ship inside the image.

- **Audit visibility for two documented MFA limitations.** An OIDC login under a
  mandatory MFA policy records `mfa_delegated_to_idp` (Scrye delegates MFA to the
  identity provider), and a policy-forced first enrollment records
  `forced_by_policy`. No authentication behavior changed; both windows are
  described in the README security model.

- **A current image.** `ghcr.io/tyler-rich/scrye:latest` has been the v0.1.0
  build from 2026-07-09 for this whole cycle, and the weekly re-scan has been
  reporting **fixable HIGH/CRITICAL** CVEs against it since 2026-07-20
  ([#75](https://github.com/tyler-rich/Scrye/issues/75)). None of those are
  defects in Scrye's own code — they are advisories disclosed against the base
  image and the dependency tree *after* that image was built, so the fix is a
  rebuild on current bases and dependencies rather than a code change. This
  release is that rebuild. Since v0.1.0:

  - **Base images.** Both Python stages moved from `python:3.13-slim-bookworm`
    to `python:3.14-slim-bookworm` (3.14.6). The `debian:bookworm-slim`
    scanners stage ([#104](https://github.com/tyler-rich/Scrye/pull/104)) and
    the `node:22-bookworm-slim` frontend-builder stage
    ([#107](https://github.com/tyler-rich/Scrye/pull/107)) had their pinned
    digests refreshed. The runtime stage's `curl`/`libcurl` are explicitly
    version-pinned for CVE-2026-5773. Every base is still digest-pinned.
  - **Backend dependencies.** `fastapi` 0.139.0 → 0.140.0, `uvicorn[standard]`
    0.34.0 → 0.51.0, `pydantic` 2.10.4 → 2.13.4, `pydantic-settings` 2.7.1 →
    2.14.2, `sqlalchemy` 2.0.36 → 2.0.51, `alembic` 1.14.0 → 1.18.5, plus a new
    explicit `greenlet` 3.5.4 pin
    ([#105](https://github.com/tyler-rich/Scrye/pull/105) and the 3.14 move).
    The `setuptools` build backend is now pinned exactly and hash-locked in
    `backend/requirements.lock` instead of floating at `>=75`, so no build-time
    dependency resolves unpinned.
  - **Frontend.** `brace-expansion` 1.1.16 → 1.1.18, and the nested
    `@typescript-eslint/typescript-estree` copy 2.1.3 → 2.1.4. Both are
    build-time-only dependencies — neither ships in the image or in the browser
    bundle.

  CI's dogfood gate (Trivy + Grype, failing on **fixable** HIGH/CRITICAL) passes
  on this build.

  **What this deliberately does not clear.** Seven CPython interpreter CVEs are
  *waived* in the dogfood gate rather than fixed, each with a dated
  source-verification and a review date in `ci/grype.yaml`. Six close on the
  next CPython point release, 3.14.7 — `html.parser`, `getpath` and `imaplib`
  ([#98](https://github.com/tyler-rich/Scrye/issues/98)) and three `tarfile`
  CVEs ([#116](https://github.com/tyler-rich/Scrye/issues/116)). The seventh,
  CVE-2025-15367 (`poplib`), has no fix on any branch below 3.15 and is a
  standing accepted risk ([#52](https://github.com/tyler-rich/Scrye/issues/52)).
  Unfixable Debian base-image CVEs are unchanged in kind from v0.1.0 and remain
  noted in the README.

## [0.1.0] - 2026-07-09

First release. A self-hosted, browser-based web UI that unifies the
[Trivy](https://github.com/aquasecurity/trivy) and
[Grype](https://github.com/anchore/grype) scanners (with
[Syft](https://github.com/anchore/syft) for SBOMs) behind one normalized findings
model, in a single hardened container.

### Added

- **Trivy scanning** — container image and git repository (public/private)
  targets; selectable vulnerability, misconfiguration/IaC, secret, and license
  scanners; per-scan severity filter, `--ignore-unfixed`, and branch/commit/tag;
  optional Syft SBOM generation alongside an image scan; global VEX and
  `.trivyignore` policy.
- **Grype scanning** — container image, filesystem/directory (admin allowlist,
  off by default), and uploaded SBOM (CycloneDX / SPDX / Syft JSON) targets;
  global Grype ignore config.
- **Syft** — on-request SBOM generation, stored as a downloadable artifact and
  reusable as a Grype target.
- **Private registries** — field-encrypted credentials materialized into a
  transient in-memory Docker `config.json` at scan time; static credentials
  built in, ECR/GCR/ACR helper config generated (helper binaries not bundled).
- **Docker environments** — image enumeration via a read-only
  `docker-socket-proxy` sidecar; the app never mounts the Docker socket.
- **Normalized findings** — raw scanner JSON persisted verbatim as the source of
  truth, normalized into a shared 6-level severity model.
- **Exports** — CSV, Markdown, and JSON, per scan or across a filtered history
  set (with CSV formula-injection guards).
- **Scan history** — filterable, sortable, paginated, with saved filter presets
  and per-scan tags.
- **Scan diff** — new vs. fixed findings and per-severity deltas between two
  scans of the same target.
- **Dashboard** — total scans, 30-day trend, top vulnerable targets, open
  critical/high, scanner-DB freshness, recent scans, and failed-scan alerts.
- **Scheduled scans** — recurring scans on a 5-field cron cadence from saved
  templates, with a run-now action.
- **Notifications** — event-driven dispatch (scan completed / scan failed /
  critical-or-high findings) to webhook, Discord, SMTP, and Matrix channels, each
  with a test-send.
- **Result retention** — optional pruning of old raw artifacts while keeping scan
  rows and normalized findings.
- **Monitoring** — an authenticated Prometheus `/metrics` endpoint.
- **Authentication & RBAC** — local accounts (argon2id) with revocable
  server-side sessions, optional TOTP MFA with an enforceable policy, personal
  API tokens, and generic OIDC (Authlib, PKCE + nonce, ID-token validation)
  alongside local auth; viewer / operator / admin roles.
- **Secrets at rest** — AES-256-GCM field encryption with the master key from a
  Docker secret file; write-only secret API fields; log redaction; decryption
  only in memory at scan time into tmpfs.
- **Backup & restore** — portable, passphrase-protected bundles that re-wrap
  secrets on backup and re-encrypt them under the new host's master key on
  restore; optional scheduled backups with retention.
- **Distribution** — multi-arch (linux/amd64 + linux/arm64) image published to
  GHCR as `ghcr.io/tyler-rich/scrye:0.1.0` and `:latest` from a semver tag on
  `main`; bundled Trivy 0.72.0, Grype 0.115.0, and Syft 1.46.0 (Apache-2.0,
  license/notice files carried in the image).
- **Hardening** — CIS-aligned container posture (digest-pinned base images,
  non-root user, `cap_drop: ALL`, `no-new-privileges`, read-only root filesystem
  + tmpfs, resource limits, healthcheck, loopback-only port binding); CSRF
  protection, rate-limited auth, and an audit log.

[Unreleased]: https://github.com/tyler-rich/Scrye/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/tyler-rich/Scrye/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tyler-rich/Scrye/releases/tag/v0.1.0
