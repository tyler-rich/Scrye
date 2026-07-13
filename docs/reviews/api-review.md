# Scrye — API Layer & Data-Model Review (2026-07-11)

> **Report-only review. No code was changed.** Scope: the FastAPI layer
> (`backend/app/api/`), the Pydantic request/response schemas, the SQLAlchemy models
> (`backend/app/db/models/`), and the Alembic migration chain (`0001`–`0008`), with
> spot-checks into their immediate collaborators (`core/dashboard.py`,
> `reports/exporters.py`, `reports/diff.py`, `workers/schedules.py`) and the SPA's
> hand-written API client where it defines the consumer side of a contract.
>
> Review axes, as requested: request/response model correctness · status codes ·
> error-envelope consistency · pagination · N+1 query patterns against SQLite ·
> migration integrity vs. the models · nullable/optional mismatches between API and
> schema · endpoints returning more data than the frontend needs · API-contract
> stability for consumers of the scan (and SARIF — see §1) endpoints.
>
> **Confidence markers** follow `full-audit-2026-07-05.md`: **CONFIRMED** = verified
> against the actual source with the triggering line cited; **PLAUSIBLE** = the
> mechanism is present but the trigger is runtime/volume dependent.
>
> **Finding IDs** use the prefix `APIR-` (API review) to avoid colliding with the
> stable `API-*` IDs from the 2026-07-05 full audit. Where a prior `API-*` finding
> was re-checked, it is cited by its original ID.

---

## 0. Executive summary

The API layer is in good shape. The remediations from the 2026-07-05 audit are
present and effective where this review touched them: list endpoints eager-load
tags (API-1), uploads are size-capped while streaming (API-4), the dashboard
aggregates are TTL-cached and run off the event loop (API-7), and the API-token
mint check caps against the *effective* role (QUA-1). Secret masking is uniform
across every secret-bearing resource (registries, git credentials, notification
channels — including the SEC-1 URL-as-credential handling — OIDC config, backup
schedule): one `MaskedSecret` shape, one `masked_secret()` helper, write-only
`SecretStr` inputs everywhere. Status codes are largely consistent (201 on create,
204 on delete, 409 for name conflicts and state conflicts, 422 for semantic
validation), and CSRF + role dependencies + audit records are applied with almost
mechanical regularity across routers.

The issues that remain are contract-level, not crashes:

- **The one real data bug:** a timezone-aware `expires_at` on a Trivy ignore rule
  is stored with its UTC offset silently dropped, so the rule expires at the wrong
  moment — a vulnerability can stay suppressed hours longer than the admin
  intended (APIR-1).
- **Two different 422 body shapes** cross the wire, and the SPA's error handler
  only understands one of them, so every Pydantic-validation failure surfaces as a
  blank "Request failed (422)" (APIR-2).
- **The scan-diff contract has a consumer-side gap and a payload gap:** the SPA
  enables Compare without checking `target_type` (guaranteed 422 from the API),
  and the diff response omits the `location` that is part of the diff *identity*
  for non-vulnerability findings, making distinct rows indistinguishable (APIR-3).
- **The filtered-history export silently truncates at 5 000 scans** with no marker
  (APIR-4).

On the specific request to check **SARIF endpoints**: Scrye has no SARIF endpoint
or SARIF export path (the only SARIF mention in the repo is an unrelated note in
`docs/reviews/phase3-finding2-resolution.md`). Exports are CSV/Markdown/JSON only
(`app/reports/exporters.py`), matching the plan (§4.3). Contract-stability notes
for the scan/export/diff endpoints are covered in APIR-3/4/5 and §2 below.

---

## 1. Findings

### APIR-1 · CONFIRMED · High — Timezone-aware `expires_at` is stored with its offset silently dropped

- **Where:** `backend/app/api/trivy_policy.py:212` (`IgnoreRuleIn.expires_at:
  datetime | None`), stored via `backend/app/db/models/trivy_policy.py:438` into a
  naive-UTC `DateTime` column; consumed by
  `backend/app/scanners/trivy_policy.py:87` (`r.expires_at > now`, naive `utcnow`).
- **What:** The whole persistence layer runs on the documented naive-UTC
  convention (`core/timeutil.py`), and the history filters carefully normalize
  client datetimes (`scan_filters.py:29` `_to_naive_utc`). `IgnoreRuleIn` does
  not. Pydantic v2 happily parses `"2026-08-01T00:00:00+09:00"` into an *aware*
  datetime, and SQLAlchemy's SQLite `DATETIME` bind renders only the wall-clock
  fields — the `+09:00` is discarded without conversion.
- **Failure scenario:** An admin in Tokyo posts an ignore rule expiring
  `2026-08-01T00:00:00+09:00` (= `2026-07-31T15:00Z`). The stored value is
  `2026-08-01 00:00:00` naive-UTC. The rule — which suppresses a CVE from every
  Trivy scan — keeps suppressing it for 9 extra hours. The same field is also
  echoed back shifted in `IgnoreRuleOut`.
- **Fix direction:** Add the same aware→naive-UTC normalization the history
  filters use, as a `field_validator` on `IgnoreRuleIn.expires_at` (this is the
  only client-supplied datetime that reaches a column unnormalized; the history
  `created_from`/`created_to` already convert).

### APIR-2 · CONFIRMED · High — Two 422 envelope shapes; the SPA surfaces only one of them

- **Where:** Backend-wide (e.g. `backend/app/api/scans.py:120,171,616` raise
  `HTTPException(422, detail="<string>")` while any Pydantic schema failure —
  `ScanCreateIn`, `ScanTagsIn`, `ScanScheduleIn.cron`, `NewUserIn.password` —
  produces FastAPI's `RequestValidationError` body where `detail` is a **list** of
  error objects). Consumer: `frontend/src/api/client.ts:62-63`
  (`if (typeof data.detail === 'string')`).
- **What:** The same status code, 422, carries two incompatible body shapes, and
  the API client keeps the generic fallback for the list shape. Every
  server-side-validated form error (tag too long, invalid cron, target starting
  with `-`, password too short at the schema layer) renders as
  `"Request failed (422)"` with no reason, while hand-raised 422s render nicely.
- **Failure scenario:** A user pastes a 70-character tag into the tag editor →
  `ScanTagsIn` rejects it with a precise message → the UI shows only
  "Request failed (422)". Same for a malformed cron on the schedule form.
- **Fix direction:** Either normalize at the source (a `RequestValidationError`
  exception handler in `main.py` that flattens the first error into a `detail`
  string — keeps one envelope for all errors), or teach `client.ts` to render the
  list shape. The backend handler is the deeper fix: it makes the envelope
  uniform for *every* consumer, not just the SPA.

### APIR-3 · CONFIRMED · Medium — Scan-diff contract: consumer gate misses `target_type`, and the payload omits the identity's `location`

- **Where:** `backend/app/api/scans.py:623-631` (diff 422s unless scanner **and
  target_type** and target match) vs. `frontend/src/pages/ScansPage.tsx:202-204`
  (`canCompare` checks `scanner` and `target` only);
  `backend/app/api/history_schemas.py:64-75` (`DiffFindingOut` has no `location`)
  vs. `backend/app/reports/diff.py:30-36` (identity keeps `location` for every
  non-vulnerability class, precisely so per-file occurrences stay distinct).
- **What:** Two halves of the same contract drift:
  1. The SPA enables its Compare button for two scans of the same scanner+target
     string across *different* target types (an image named `foo` and an uploaded
     SBOM named `foo`), and the backend then rejects the navigated-to diff with
     422 — a dead-end the UI invited.
  2. The diff engine distinguishes two occurrences of the same misconfiguration
     rule in different files (identity = class+id+location), but
     `DiffFindingOut` drops `location`, so the response contains multiple
     byte-identical rows. A consumer cannot tell which file's finding was added
     or removed — the information that made them distinct findings is withheld.
- **Failure scenario:** Diff two repo scans where `DS002` fires in `a/Dockerfile`
  (fixed) and appears in `b/Dockerfile` (new): the response's `removed` and
  `added` arrays each contain a row that is field-for-field identical.
- **Fix direction:** Add `location` to `DiffFindingOut` (additive, non-breaking),
  and add the `target_type` equality to `canCompare` (the backend message already
  names it). Consider echoing `target_type` in `ScanDiffOut` alongside
  `target`/`scanner` for the same reason it is part of the identity.

### APIR-4 · CONFIRMED · Medium — Filtered-history export truncates at 5 000 scans with no truncation signal

- **Where:** `backend/app/api/scans.py:90,365` (`_MAX_HISTORY_EXPORT_SCANS = 5000`,
  `.limit(...)`), rendered by `app/reports/exporters.py:376-391` (`export_history`
  — no count vs. total comparison, no marker in JSON metadata, CSV, or Markdown).
- **What:** The cap itself is sensible (bounded downloads), but nothing in the
  response says the cap fired. The JSON export even echoes the active `filters`,
  implying "this is everything matching these filters".
- **Failure scenario:** An instance with 8 000 scans exports its full history for
  a compliance snapshot; the file contains the newest 5 000 with no indication
  that 3 000 are missing. The consumer reports on incomplete data believing it
  complete.
- **Fix direction:** The history page already computes `total` — do the same
  count in `export_history_view` and either (a) embed
  `{"truncated": true, "total": N, "exported": 5000}` in the JSON metadata and a
  note line in CSV/Markdown, or (b) refuse with a 422 asking for narrower filters.
  Option (a) preserves the current contract additively.

### APIR-5 · CONFIRMED · Medium — Naive-UTC timestamps are serialized with no timezone designator, and one consumer already parses them wrong

- **Where:** Every datetime in every response model (e.g. `ScanOut.created_at`,
  `backend/app/api/scan_schemas.py:147`) serializes as `2026-07-11T04:00:00`
  (no `Z`), per the naive-UTC storage convention (`core/timeutil.py:1-16`).
  Consumer workaround: `frontend/src/lib/dates.ts:14` appends `Z` before parsing.
  Bypass already shipped: `frontend/src/pages/ScansPage.tsx:208` calls
  `new Date(x.created_at)` directly — browser-local parsing.
- **What:** The wire format is ambiguous ISO-8601: correct interpretation depends
  on out-of-band knowledge ("all Scrye timestamps are UTC"). The repo's own SPA
  needed a dedicated helper to cope, and the one call site that skipped the
  helper demonstrates exactly how consumers get it wrong. For third-party
  consumers of the scan endpoints (the stated contract-stability concern) this is
  the most likely silent-corruption point: every timestamp shifts by the client's
  UTC offset.
- **Failure scenario (shipped code):** `runCompare` orders the two selected scans
  by locally-parsed `created_at` to pick diff base vs. compare. Two scans 30
  minutes apart straddling a DST transition can mis-order, silently inverting the
  diff (`added` ↔ `removed`).
- **Fix direction:** Serialize with an explicit UTC designator at the API
  boundary — a shared base model / `field_serializer` that emits
  `...isoformat() + "Z"` — leaving storage naive (the DB convention is fine).
  This is additive for correct consumers (`parseUtc` already accepts `Z`) and
  fixes incorrect ones. Also route `ScansPage.tsx:208` through `parseUtc`.

### APIR-6 · CONFIRMED · Medium — Update paths accept states their create paths forbid on secret-bearing resources

- **Where:**
  - `backend/app/api/notifications.py:269-277`: `PATCH` with `secret: ""` clears
    `secret_ciphertext` entirely, while create (`:195-199`) 422s because **every**
    channel type requires a secret (`SECRET_OPTIONAL_TYPES` is empty,
    `db/models/notification.py:261-264`).
  - `backend/app/api/target_schemas.py:72-83`: `RegistryUpdateIn` carries none of
    `RegistryCreateIn`'s `_check_auth` rules — `username` can be blanked on a
    `username_password` registry (create requires it, `:63-64`), and `name` /
    `registry_host` are not stripped on update (create strips, `:48-55`).
- **What:** The write-model invariants live in the create schema (or create
  handler) and are not re-established on update, so a resource can be PATCHed
  into a shape that could never have been created.
- **Failure scenario:** An admin "clears" a webhook channel's secret → the channel
  remains `enabled` with no credential; the next `scan_completed` dispatch fails
  at send time with only a log line. Or: a registry renamed to `" ghcr "` (spaces
  preserved) sits alongside `"ghcr"` — two visually identical names the 409
  duplicate check treats as distinct.
- **Fix direction:** Reject secret-clearing on mandatory-secret channels (422,
  mirroring create), and give the update schemas the same strip/consistency
  validators as their create counterparts (a shared mixin keeps them from
  drifting again).

### APIR-7 · CONFIRMED · Low — "Run now" leaves schedule bookkeeping contradicting itself

- **Where:** `backend/app/api/scan_schedules.py:279` (`run_schedule_now` sets
  `last_scan_id` only) vs. `backend/app/workers/schedules.py:64-66` (the cron path
  sets `last_run_at`, `last_scan_id`, **and** `last_status` together).
- **What:** The three `last_*` fields form one record of "the most recent firing",
  but the manual-fire path updates a third of it.
- **Failure scenario:** A schedule last cron-fired Monday (`last_status:
  "error: ..."`). An operator hits Run Now on Wednesday; the scan succeeds. The
  schedules list still shows Monday's timestamp and the stale error next to a
  `last_scan_id` pointing at Wednesday's healthy scan.
- **Fix direction:** Set `last_run_at = utcnow()` and `last_status = "ok"` (or a
  distinct `"manual"`) in `run_schedule_now`, or extract the worker's
  fire-bookkeeping into a helper both paths call.

### APIR-8 · CONFIRMED · Low — Pagination envelopes are inconsistent across list endpoints

- **Where:** `GET /api/scans` → bare `list[ScanOut]` with `limit`/`offset` but no
  total (`backend/app/api/scans.py:269-290`); `GET /api/scans/history` →
  `{total, items}` (`:293`); `GET /api/scans/{id}/findings` → `{total, items}`
  (`scan_schemas.py:170-174`); `GET /api/audit` → `{total, entries}` — a third
  key name (`audit.py:36-41`); registries / git credentials / schedules / users /
  notifications / presets → unbounded bare arrays with no `limit` at all.
- **What:** Three envelope conventions coexist. `GET /api/scans` is documented in
  `docs/ARCHIVE.md` (Phase P4 entry) as a deliberately-frozen legacy contract, and
  it now has **zero SPA consumers** (`frontend/src/api/scans.ts` defines
  `listScans` but no page calls it); the unbounded admin lists are fine at
  self-hosted scale but make the generated client inconsistent.
- **Failure scenario:** A third-party consumer paging `GET /api/scans` cannot know
  when to stop except by observing a short page; the same consumer must special-
  case `entries` vs `items` for audit vs everything else.
- **Fix direction:** Standardize on `{total, items}` for anything paginated;
  rename `AuditPageOut.entries` → `items` at the next deliberate contract rev (it
  is admin-UI-only today). Consider deprecating `GET /api/scans` in the OpenAPI
  description since history supersedes it and nothing in the SPA uses it.

### APIR-9 · CONFIRMED · Low — Every scan list/history row ships `options` and unbounded `error` text the views never render

- **Where:** `backend/app/api/scan_schemas.py:129-149` — `ScanOut` ("summary and
  detail share this shape") includes `options: dict` and `error: str | None`
  (backed by unbounded `Text`, `db/models/scan.py:126`); returned per-row by
  `GET /api/scans`, `/scans/history` (up to 200 rows/page), and the dashboard's
  `recent_scans`.
- **What:** The history table and dashboard widgets render target/status/severity/
  tags/counts; `options` (which also exposes internal `registry_id` /
  `git_credential_id` to viewer-role callers — ids only, no metadata) and the full
  scanner `error` text ride along on every row. A history page of failed repo
  scans, each carrying a multi-KB git/scanner stderr in `error`, multiplies the
  payload for nothing; the failed-alerts widget (`api/dashboard.py:110-119`)
  legitimately needs `error`, but it builds its own `FailedAlertOut` anyway.
- **Failure scenario:** 200-row history page over failed scans with verbose
  errors → hundreds of KB of JSON the table drops on the floor; slower page
  loads on the deployment's uplink for zero rendered pixels.
- **Fix direction:** Split a `ScanSummaryOut` (no `options`, `error` capped or
  replaced by `has_error: bool`) for list/history/recents from the full `ScanOut`
  for `GET /scans/{id}`. Additive if the detail model keeps its shape; the SPA
  already reads `error` only on the detail page.

### APIR-10 · CONFIRMED · Low — `_ALLOWED_SCANNERS` matrix is defined twice and has already drifted in shape

- **Where:** `backend/app/api/scans.py:77-83` (4 entries, incl. `SBOM`) vs.
  `backend/app/api/scan_schedules.py:41-46` (3 entries; relies on a separate
  explicit SBOM 422 plus a defensive `.get(..., set())` at `:104-110`).
- **What:** The scanner↔target compatibility matrix is scanner-domain knowledge
  duplicated across two routers with different shapes. Adding a combination
  (e.g. Trivy filesystem scans, or a third engine) requires remembering both
  copies; missing one produces schedule-vs-scan behavioral divergence, the exact
  class of drift the shared `scan_filters.py` module was created to prevent for
  filters.
- **Failure scenario:** Trivy gains `filesystem` support in `scans.py` only —
  users can run one-off Trivy filesystem scans but scheduling the identical scan
  422s with "trivy does not support filesystem targets".
- **Fix direction:** Move the matrix (and `_reject_unsupported_combo`) next to the
  domain — `app/scanners/` or `app/api/scan_schemas.py` — and import it in both
  routers; the schedules router keeps only its extra "SBOM cannot be scheduled"
  rule.

---

## 2. Checked and clean

Areas the review examined that need no action, recorded so the next reviewer
doesn't re-plough them:

- **Migration integrity (0001–0008 vs. models).** Reconstructed the schema from
  the full chain and compared column-by-column: all columns, nullability, FK
  `ondelete` behaviors, unique constraints, and **every model-declared index**
  (users, sessions, audit_log, scans ×3, scan_tags ×2, findings ×2, artifacts,
  registries, git_credentials, docker_environments, filter_presets,
  oidc_identities, oidc_login_flows, notification_channels, api_tokens ×3,
  backups, scan_schedules, vex_documents, trivy_ignore_rules) are present and
  match. The plan's key indices exist: `findings(scan_id, severity, vuln_id)` and
  the scans composite (implemented as `(scanner, status, created_at)` — a
  reasonable recorded substitution for the plan's `started_at`, which is
  nullable). Late columns arrive correctly with `batch_alter_table` +
  `server_default` (`users.mfa_enabled` in 0006, `notification_channels.events`
  in 0007), and downgrades reverse their upgrades in FK-safe order.
  `PRAGMA foreign_keys=ON` is applied per-connection (`db/session.py:36`), so the
  `ON DELETE` rules are actually enforced on SQLite. Two cosmetic notes only:
  the non-native enum CHECK-constraint *names* drift between 0003
  (`target_type`, `scan_status`) and 0007/metadata (`targettype`) — no runtime
  effect on SQLite; and the drift test (`tests/test_migrations.py`, QUA-23)
  compares table/column **names** only, so type/nullability/index drift would
  not be caught by CI — worth extending when convenient.
- **Nullable/optional alignment.** Every `X | None` response field traced maps to
  a genuinely nullable column, and every non-optional field to a `NOT NULL`
  column (ScanOut, FindingOut, ArtifactOut, UserOut, SessionOut, ApiTokenOut,
  RegistryOut, GitCredentialOut, NotificationChannelOut, ScanScheduleOut,
  VexDocumentOut, IgnoreRuleOut, AuditEntryOut, FilterPresetOut, OidcConfigOut).
  No read-time validation traps found. (The one datetime *semantics* issue is
  APIR-1/APIR-5, not a nullability issue.)
- **N+1 against SQLite.** The known hot paths are fixed and stayed fixed:
  `list_scans`/`list_history`/`export_history_view` eager-load `tag_rows`
  (API-1), the dashboard's `recent_scans` eager-loads tags and the aggregate runs
  once per 15 s TTL in a threadpool (API-7), export/diff select only the columns
  the reports read via `load_only` and deliberately skip `description`
  (`scans.py:548-563`). Single-row endpoints take one extra lazy tags SELECT on a
  sync session — constant, not N+1. History tag filtering uses indexed
  `EXISTS` per tag; the severity sort is an unindexed CASE ranking, acceptable at
  self-hosted volumes.
- **Secret masking / write-only contract.** Uniform across all six secret-bearing
  resources; one `MaskedSecret` schema and helper; `SecretStr` on every write
  model; audit `details` record `"updated"`, never values; the notification
  URL-credential (SEC-1) masks in `config` on read and tolerates the masked
  round-trip on write. No plaintext or ciphertext egress path found in any read
  model.
- **Status codes.** 201 on every create, 204 on every delete, 409 for duplicate
  names and state conflicts (cancel/delete/disabled-environment), 413 on capped
  uploads, 429 with `Retry-After` on auth rate limiting, 502 for docker-proxy
  upstream failures. Minor unflagged nit: `users.py` uses 400 where siblings use
  409 for self-change conflicts — cosmetic.
- **SARIF.** No SARIF endpoints exist to protect (see §0). If SARIF export is ever
  added, the diff/export identity semantics in APIR-3 are the contract to build
  on.

---

## 3. Suggested priority

| # | Finding | Sev | Effort |
|---|---------|-----|--------|
| APIR-1 | `expires_at` timezone drop | High | Small (one validator) |
| APIR-2 | Dual 422 envelope, SPA drops one | High | Small (one exception handler) |
| APIR-3 | Diff: `target_type` gate + missing `location` | Medium | Small |
| APIR-4 | Silent 5 000-row export truncation | Medium | Small |
| APIR-5 | Naive timestamps on the wire | Medium | Medium (contract rev; additive) |
| APIR-6 | Update/create validation asymmetry | Medium | Small |
| APIR-7 | Run-now bookkeeping | Low | Trivial |
| APIR-8 | Pagination envelope drift | Low | Medium (contract rev) |
| APIR-9 | `options`/`error` over-fetch in lists | Low | Medium (schema split) |
| APIR-10 | Duplicated `_ALLOWED_SCANNERS` | Low | Trivial |

APIR-1, -2, -3, -4, -6, -7, -10 are all additive or internal and safe to fix
without a contract version bump. APIR-5, -8, -9 change response shapes third
parties may rely on; batch them into one deliberate, changelogged contract
revision.
