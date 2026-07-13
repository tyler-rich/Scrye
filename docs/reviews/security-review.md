# Scrye — Security Review

**Date:** 2026-07-11
**Reviewed commit:** `81d35fe` (branch `claude/scrye-security-review-q7973e`, identical to `dev`)
**Scope:** Full backend codebase — every FastAPI endpoint's input validation and
authz/authn; the AES-256-GCM field-encryption layer (key handling, nonce/IV, key
rotation); secret handling and log/error leakage; SQL/command/argv-injection
surfaces; SSRF in outbound fetchers (registry probe, Docker proxy, notifications,
OIDC); path traversal in file/artifact/backup handling; the Docker-daemon
connection; and the Dockerfile/container runtime posture.

## Method

Reviewed against the project's own threat model (CLAUDE.md § Hard security rules,
ARCHIVE.md §5/§6/§9). This codebase has already been through multiple documented
audit rounds (Phase-3 security reviews, the 2026-07-04/05 full-repo audits), and
that shows: the core auth, session, CSRF, crypto-primitive, and argv-injection
surfaces are in good shape. The findings below are the residual gaps a careful
reviewer still finds — one genuine access-control bypass, several
defense-in-depth weaknesses, and a set of documented-but-worth-restating
limitations.

## What was verified as sound (no action)

These were examined and found correct, so the report doesn't belabor them:

- **GCM nonces** are fresh `os.urandom(12)` per `encrypt`, under both the
  master-derived key and each per-backup passphrase key (fresh salt per backup).
  No nonce-reuse path exists.
- **Key rotation** is correct: tokens are self-describing (`scrye$v<n>$…`), old
  key versions remain available for decrypt, `rotate()` round-trips through
  decrypt+re-encrypt preserving AAD.
- **Master-key loading** fails closed — a missing/empty/malformed secret file
  raises `MasterKeyError`; no weak/empty/default fallback; key bytes never appear
  in errors (only lengths/paths).
- **Argv/option injection** is well-defended: `target` and `branch`/`commit`/`tag`
  reject a leading `-` (`scan_schemas.py:77-100`), and every scanner argv builder
  inserts a `--` end-of-options terminator before the positional
  (`trivy.py:100,126`, and the Grype/Syft builders). Subprocesses use
  `create_subprocess_exec` with a list argv (no shell).
- **Git credential handling** keeps the token off argv (native `GITHUB_TOKEN`/
  `GITLAB_TOKEN` env for hosted providers; a tmpfs `GIT_ASKPASS` helper for
  generic hosts) and shreds transient credential files in `finally`
  (`credentials.py`).
- **CSRF + RBAC** are applied consistently: a per-router sweep confirms every
  state-changing `POST/PUT/PATCH/DELETE` carries `require_csrf` **and** a
  `require_role(...)` dependency; bearer-token requests are correctly CSRF-exempt;
  API-token privilege is capped at `min(token_role, owner_role)` via
  `effective_role`.
- **Timing-safe comparisons** where they matter: CSRF and OIDC browser-binding use
  `hmac.compare_digest`; session/API tokens are looked up by SHA-256 hash, not
  plaintext compare; unknown-user login equalizes timing.
- **Path traversal** in artifact handling is guarded: `store_artifact` rejects
  path separators in filenames and `artifact_path` re-resolves and confirms the
  result stays under the artifacts root (`core/artifacts.py`). The artifact
  download endpoint scopes the artifact to its `scan_id`.
- **Upload size** is bounded up front by `read_upload_capped` (reported-size
  check + chunked read), and scanner stdout is byte-capped (`SCN-1`).

---

## Findings

### 1. Repository scans bypass the filesystem-scan allowlist (arbitrary local-path read) — HIGH

**Files:** `backend/app/workers/inprocess.py:329-330`,
`backend/app/api/scan_schemas.py:77-89`, `backend/app/scanners/trivy.py:103-127`

**Explanation.** Filesystem (`grype dir:`) scanning is deliberately gated behind
an admin allowlist — `resolve_filesystem_path` rejects any target not under
`SCRYE_FILESYSTEM_SCAN_ROOTS`, and the Phase-P3 deviation note states the reason
verbatim: *"Allowing arbitrary absolute paths would let an operator read
sensitive host files (the SQLite DB, the master-key file) as scan output."*

That control is bypassable through a different target type. A **`repository`**
scan is validated only by `ScanCreateIn._strip_target` (non-empty, no leading
`-`, ≤512 chars) — there is **no scheme/URL validation**. In the worker, a public
repository scan (no git credential) passes the raw target straight through:

```python
# inprocess.py:328-330
auth = resolve_git_auth(session, options)
if auth is None:
    return await scanner.scan_repo(scan.target, options, env=base_env or None)
```

`scan_repo` builds `trivy repo … -- <target>` (`trivy.py:126`). Trivy's `repo`
command accepts a **local path**, not just a remote URL, and runs the selected
scanners (vuln/misconfig/secret/license) over it. An **operator** (not admin) can
therefore submit `target_type=repository`, `target=/` (or `/data`, `/run/secrets`,
`/app`) and have Trivy walk the container/host filesystem. The raw Trivy JSON is
persisted as the scan's source-of-truth artifact and is downloadable by any
viewer, so file contents and paths that Trivy surfaces (misconfig excerpts,
secret-finding context/locations, license file paths) leak — squarely the
DB/master-key exposure the filesystem allowlist exists to prevent, reached via an
ungated code path.

**Fix.** Validate repository targets to be remote clone URLs before they reach the
scanner, mirroring the intent of the filesystem gate. In `ScanCreateIn` (or the
worker's `_scan_repo`), require the target to parse as an `https://`/`http://`/
`ssh://`/`git://` URL (reuse `is_http_url` plus an ssh/git allowance) and reject
anything that resolves to a local filesystem path. Alternatively, if local git
repos are a wanted feature, route them through `resolve_filesystem_path` so the
same `SCRYE_FILESYSTEM_SCAN_ROOTS` allowlist applies. Add a regression test that a
`repository` scan with `target="/data"` is rejected.

---

### 2. Backup restore trusts bundle-supplied scrypt parameters → pre-auth memory-exhaustion DoS — MEDIUM

**Files:** `backend/app/backup/bundle.py:262-269`,
`backend/app/core/passphrase.py:73-83`

**Explanation.** On restore, the scrypt cost parameters are read from the
**attacker-controlled bundle envelope** and passed to `derive_key`:

```python
# bundle.py:262-269
pass_cipher = passphrase_cipher(
    passphrase, salt,
    n=int(kdf.get("n", SCRYPT_N)),   # from the uploaded file
    r=int(kdf.get("r", SCRYPT_R)),
    p=int(kdf.get("p", SCRYPT_P)),
)
```

`derive_key` only checks `n >= 2`, `n` is a power of two, `r >= 1`, `p >= 1`
(`passphrase.py:73`) — there is no upper bound — and it sets
`maxmem = 128 * n * r * 2` (`passphrase.py:82`), so scrypt's own memory guard is
widened to whatever the bundle demands and won't self-limit. A bundle declaring
`n = 2**30, r = 8` makes `hashlib.scrypt` attempt to allocate ~1 TiB
(`128·N·r`), OOM-killing the container. Crucially this happens **before** the
passphrase is validated (`bundle.py:274`), so no knowledge of the real passphrase
is needed to trigger it; a large `p` similarly drives unbounded CPU.

Restore is admin+CSRF-gated, which bounds the severity — an admin can already wipe
the DB via a legitimate restore — but this turns a crafted upload into a
container-availability kill without even needing the passphrase, and it's a
robustness gap in a security-sensitive path.

**Fix.** Clamp the restore-supplied parameters to a sane ceiling (e.g.
`n <= 2**20`, `r <= 16`, `p <= 4`) and raise `BackupError` otherwise, and cap
`maxmem` at a fixed budget (e.g. a few hundred MiB) rather than deriving it from
the untrusted `n`. Legitimate bundles only ever record the module defaults
(`N=2**17, r=8, p=1`), so a tight cap breaks nothing.

---

### 3. No entropy floor and no key stretching on the master key weakens stolen-DB resistance — MEDIUM

**Files:** `backend/app/core/crypto.py:79`, `backend/app/core/crypto.py:167`

**Explanation.** The only strength gate on the master key is length: `if
len(decoded) < _MIN_KEY_BYTES` (32 bytes) at `crypto.py:79`, and
`_decode_key_material` falls back to raw UTF-8 bytes when the material isn't
base64. A memorable **40-character passphrase** is therefore accepted as a master
key. Field keys are then derived with a single HKDF-SHA256 expand —
`HKDF(algorithm=SHA256, length=32, salt=None, info=_HKDF_INFO)` at
`crypto.py:167` — which is a fast KDF, not a password-stretcher, and uses no salt.

The §6 threat model is *"DB read access must not reveal secrets."* If an attacker
obtains `scrye.db` (exactly that threat) and the operator chose a low-entropy but
≥32-byte key against the `openssl rand` guidance, the key can be brute-forced
offline at HKDF speed (billions/sec) and every stored registry credential, git
token, OIDC secret, and TOTP seed decrypted. Nothing enforces entropy or adds
stretching to compensate for a weak-but-long key.

**Fix.** Detect and require high-entropy key material: if the secret file isn't
valid base64 of ≥32 bytes (i.e. it looks like a passphrase), either reject it with
a clear "generate with `openssl rand -base64 48`" error, or run it through a
memory-hard KDF (scrypt/argon2 with a fixed application salt) before HKDF, so a
low-entropy key is stretched rather than expanded at HKDF speed. Document the
requirement in the README security model.

---

### 4. Log-redaction filter only prefix-masks unquoted secrets containing spaces/commas — MEDIUM

**File:** `backend/app/core/logging.py:59-62`

**Explanation.** The key/value redaction pattern's unquoted-value branch is
`((?!(?:bearer|basic)\b)[^\s"',;&]+)` (`logging.py:61`), which stops at the first
whitespace, comma, semicolon, ampersand, or quote. A secret logged **unquoted**
that contains any of those characters is only partially masked — e.g.
`password=p@ss w0rd here` becomes `password=[REDACTED] w0rd here`, leaking
`w0rd here`, and `api_key=abc,def` leaks `,def`. SMTP passwords, backup
passphrases, and multi-word tokens are exactly the shapes that contain spaces.

The quoted-value branches (`"…"` / `'…'`) correctly capture spaced values, so the
common dict/JSON-repr case is covered and the exposure is limited to bare
`key=value with spaces` log lines — hence MEDIUM, not HIGH — but the filter is the
last line of defense behind the "plaintext secrets never leak through logs" rule,
and this shape defeats it.

**Fix.** Make the unquoted value greedier for known-secret keys — match up to the
end of line or a clear delimiter (e.g. `[^\r\n]+` trimmed, or split on
`,`/`;` only when the surrounding text is a structured list) — accepting that
over-redaction of a trailing sentence is preferable to leaking secret bytes. Add a
test with a spaced unquoted secret.

---

### 5. No application-layer HTTP security headers; CSRF cookie is JS-readable — MEDIUM

**Files:** `backend/app/main.py:160-194`, `backend/app/auth/cookies.py:29-38`

**Explanation.** The app adds only CORS middleware (dev). It emits no
`Content-Security-Policy`, `X-Frame-Options`/`frame-ancestors`,
`X-Content-Type-Options`, or `Referrer-Policy` on any response, including the SPA
`index.html`. All header hardening is delegated to the operator's external proxy.
This matters more than usual because (a) the SPA renders attacker-influenced
scanner output (CVE descriptions, package names, image/repo metadata, secret
finding titles), giving a stored-XSS sink if any of it is rendered unsafely, and
(b) the CSRF design intentionally uses a **JS-readable** cookie
(`httponly=False`, `cookies.py:31`), so any XSS both reads the CSRF token and
rides the session — XSS fully defeats CSRF and session protection here.

**Fix.** Ship a conservative default `Content-Security-Policy` (self scripts/styles,
no inline where feasible) and `X-Frame-Options: DENY`, `X-Content-Type-Options:
nosniff`, `Referrer-Policy: no-referrer` from a small response middleware, so
containment doesn't depend on correct external-proxy configuration. Keep the
CSRF-token delivery but consider a double-submit via a response header /
meta-tag rather than a JS-readable cookie.

---

### 6. Outbound fetchers permit arbitrary internal/link-local destinations (SSRF) — LOW

**Files:** `backend/app/core/notifications.py:51-90`,
`backend/app/core/registry_check.py:76-101`, `backend/app/core/docker_proxy.py:81-84`

**Explanation.** Several endpoints make server-side requests to
admin-configured URLs with no destination allowlist: notification webhooks /
Discord / Matrix homeserver (`notifications.py`), the registry connectivity probe
(`registry_check.py` — an admin-supplied `registry_host`), and the Docker socket
proxy (`docker_proxy.py` — a per-environment `proxy_url`). Each can be pointed at
`http://169.254.169.254/…`, `http://localhost:…`, or an internal service to probe
reachability or (for the "send test" actions) relay a chosen message body. These
are admin-only and CSRF-gated, and the registry probe already refuses to forward
credentials to non-`https` realms and disables redirects — so this is a low-severity
hardening item, not an unauthenticated SSRF — but a compromised or over-permissioned
admin, or a confused-deputy on the test-send actions, can still reach the internal
network.

**Fix.** Where feasible, resolve the target host and refuse RFC-1918 / loopback /
link-local (`169.254.0.0/16`) addresses unless an explicit "allow internal
targets" setting is enabled (the Docker proxy legitimately needs an internal
host, so gate that one differently). At minimum, document the SSRF surface in the
security model so operators scope admin access accordingly.

---

### 7. Field-encryption AAD binds to the column, not the row — LOW (documented)

**File:** `backend/app/core/secret_store.py` (`SECRET_COLUMNS` / AAD scheme)

**Explanation.** Each secret's AAD is the `(table, column)` tag (e.g.
`"registries.secret"`), not the row primary key, so a ciphertext can be relocated
between two rows of the same column and still authenticate and decrypt (swap one
registry's `secret_ciphertext` into another, or one user's `mfa_secret_ciphertext`
into another user's row). This requires **DB write** access, which is outside §6's
DB-*read* threat model, and it is explicitly logged as an accepted residual in the
2026-07-04 audit entry — restated here for completeness, not as a regression.

**Fix (if/when revisited).** Bind AAD to the row id (e.g.
`"registries.secret:42"`); this invalidates existing ciphertexts and needs a
key-available re-encryption migration, which is why it was deferred.

---

### 8. Mandatory-MFA policy is not enforced on the OIDC login path — LOW (documented)

**File:** `backend/app/api/oidc.py` (callback, ~lines 492-511)

**Explanation.** `_mfa_required_for` (`required_all`/`required_admin`) is enforced
only on `/auth/login`; the OIDC callback deliberately skips it (documented as an
accepted limitation — Scrye delegates the second factor to the IdP for OIDC
accounts, which often have no local password). Operators running a mandatory-MFA
policy should understand it is not globally enforced once OIDC is enabled unless
the IdP itself enforces MFA. No code change recommended; surfaced so the security
model docs state it plainly.

---

### 9. Forced-MFA-enrollment window lets a password-only attacker bind their own TOTP — LOW

**File:** `backend/app/api/auth.py:159-181`

**Explanation.** When policy mandates MFA but an account has never enrolled, a
valid **password alone** yields the enrollment secret and lets the caller complete
enrollment via `/auth/mfa/verify`. During the window before the legitimate user
enrolls, an attacker who holds only the password — precisely the threat mandatory
MFA is meant to mitigate — can enroll **their own** authenticator and satisfy MFA
thereafter. This is inherent to enroll-on-first-login; the mitigation is
out-of-band/admin-driven enrollment.

**Fix.** For a hard guarantee, support admin-provisioned enrollment (or an
enrollment token delivered out of band) so first-factor compromise can't
self-complete second-factor setup. Otherwise, document the window in the security
model.

---

### 10. Auth rate-limiter and pending-MFA store grow unbounded by distinct key — LOW

**File:** `backend/app/core/ratelimit.py`

**Explanation.** The sliding-window rate limiter prunes each key's event deque on
access but never evicts idle keys, so a stream of distinct real client IPs grows
the backing dict without bound; `PendingMfaStore` similarly has no per-user cap on
concurrent challenges (bounded only by the shared IP limiter and a 300 s TTL).
Per-entry cost is small, it's a single-container process, and IPs can't be spoofed
past `--forwarded-allow-ips`, so this is a minor memory-growth concern, not a
practical DoS.

**Fix.** Add periodic eviction of keys whose window is fully expired (sweep on a
timer or opportunistically when the dict crosses a size threshold), and cap
concurrent pending-MFA challenges per user.

---

## Prioritized remediation table

| # | Severity | Finding | Location | Fix summary |
|---|----------|---------|----------|-------------|
| 1 | **HIGH** | `repository` scans bypass the filesystem allowlist → arbitrary local-path read by an operator | `workers/inprocess.py:330`, `api/scan_schemas.py:77` | Require repository targets to be remote clone URLs (or route local paths through `SCRYE_FILESYSTEM_SCAN_ROOTS`); add a regression test |
| 2 | MEDIUM | Restore trusts bundle scrypt params (`n/r/p`, `maxmem`) → pre-passphrase OOM DoS | `backup/bundle.py:263`, `core/passphrase.py:82` | Clamp `n/r/p` to a ceiling; cap `maxmem` at a fixed budget |
| 3 | MEDIUM | No entropy floor + unsalted single-pass HKDF on master key → weak-key brute-force of stolen DB | `core/crypto.py:79,167` | Reject/stretch low-entropy key material via a memory-hard KDF |
| 4 | MEDIUM | Redaction filter prefix-masks unquoted spaced secrets → tail leaks to logs | `core/logging.py:61` | Make the unquoted-value match consume the whole value for secret keys |
| 5 | MEDIUM | No app-layer security headers; JS-readable CSRF cookie → XSS defeats CSRF/session | `main.py:160`, `auth/cookies.py:31` | Add CSP + `X-Frame-Options`/`nosniff`/`Referrer-Policy` middleware |
| 6 | LOW | SSRF: outbound fetchers reach arbitrary internal/link-local hosts (admin-gated) | `core/notifications.py`, `core/registry_check.py`, `core/docker_proxy.py` | Block RFC-1918/loopback/link-local unless explicitly allowed; document |
| 7 | LOW | Secret AAD bound to column, not row (DB-write threat; documented) | `core/secret_store.py` | Bind AAD to row id via a re-encryption migration when revisited |
| 8 | LOW | Mandatory MFA not enforced on OIDC login (documented) | `api/oidc.py` | Document; rely on IdP MFA for OIDC accounts |
| 9 | LOW | Forced-enrollment window lets password-only attacker bind own TOTP | `api/auth.py:159` | Support admin/out-of-band enrollment; document the window |
| 10 | LOW | Rate-limiter / pending-MFA store grow unbounded by distinct key | `core/ratelimit.py` | Periodic eviction of expired keys; cap pending challenges per user |

**Overall:** the codebase is in strong shape for a self-hosted security tool —
crypto primitives, argv-injection defenses, CSRF/RBAC coverage, credential
handling, and container posture are all sound and reflect prior audit work. The
one finding that warrants a code change before it can be called clean is **#1**
(the repository-scan filesystem bypass); **#2–#5** are worthwhile
defense-in-depth hardening; **#6–#10** are low-severity or already-documented
residuals to track.
