# Scrye — Concurrency & Async-Path Review (2026-07-12)

> **Report-only review.** No code was changed. Scope: the in-process async scan worker
> (`backend/app/workers/`), both in-process schedulers, every `async def` path in the
> backend (API endpoints, scanner orchestration, notification dispatch, backup/restore),
> the SQLite engine/session configuration, and the shutdown/cancellation behavior of the
> whole single-container process. Reviewed against the categories requested: unawaited
> coroutines, blocking calls inside async handlers, race conditions on shared state,
> SQLite locking/WAL behavior under concurrent scans, task cancellation and cleanup on
> shutdown, unbounded task spawning, and silently swallowed worker failures.
>
> **Confidence markers** (same convention as `full-audit-2026-07-05.md`):
> **CONFIRMED** = verified against the actual source, with the triggering line cited.
> **PLAUSIBLE** = the mechanism is present in the source, but the trigger depends on
> runtime timing/volume that was not executed here.
>
> **Finding IDs:** `CON-1` … `CON-20`, ordered by severity. Cite them in commits/PRs.
>
> Context that framed severity: SQLite is configured with WAL + `busy_timeout=5000` +
> `check_same_thread=False` over a default QueuePool (5 + 10 overflow)
> (`backend/app/db/session.py:22-65`); FastAPI `def` endpoints run in a threadpool while
> `async def` endpoints and the worker/scheduler coroutines share one event loop; the
> hardened Compose file sets **no `stop_grace_period`**, so Docker's default **10 s**
> SIGTERM→SIGKILL budget applies.

---

## 0. Executive summary

The worker core is in good shape: the queued→running claim and the cancel endpoint use
mirrored atomic conditional `UPDATE`s (a correct design), heavy result persistence and
restore already hop to threads (API-2/API-5), `run_command` streams both pipes with a
byte cap and kills the child on timeout/cancel, and credential materialization is
cleaned up in `finally` blocks that run on cancellation.

The systemic gaps are at the edges of that design:

1. **Nothing anywhere handles SQLite lock contention** — one slow writer (a 10k-findings
   flush, a restore, a retention pass) pushes every other committer past the 5 s
   `busy_timeout` into an unhandled `OperationalError`, and the worker's own failure
   paths then compound it into scans stuck `running` forever with results deleted
   (CON-1).
2. **Subprocess kills signal only the direct child** — scanner/git grandchildren survive
   with credentials in their environment (CON-2).
3. **A class of sync work still runs on the event loop** — most visibly parsing a
   potentially multi-hundred-MB scanner JSON (CON-4), plus a family of small DB
   commits/reads in `async def` contexts that turn one slow writer into a whole-app
   freeze (CON-5).
4. **Shutdown arithmetic doesn't fit the container's stop budget** — the worker's 10 s
   drain grace alone consumes Docker's default grace, and non-cancellable thread hops
   extend it further, so a busy instance gets SIGKILLed mid-commit (CON-6/CON-7).
5. **Several failure paths are silent** and leave user-visible state lying (scans
   `queued`/`running` forever, schedules marked `ok` for runs that never happened,
   a "fresh" vuln DB that failed to update) — CON-1, CON-11, CON-12, CON-13.

A single new mechanism would retire several findings at once: a **stale-scan watchdog**
in the maintenance tick (re-submit orphaned `QUEUED` rows; fail `RUNNING` rows with no
live task) — it is the in-process equivalent of `recover()` that today only runs at
startup, and it converts CON-1's and CON-11's "stuck until restart" outcomes into
"self-heals within a minute."

Finding counts: **4 high · 9 medium · 7 low.**

---

## 1. High-severity findings

### CON-1 — SQLite lock contention is unhandled everywhere; worker failure paths compound it into stuck scans and lost results
- **Severity:** High · **CONFIRMED** (mechanism; the multi-step failure chain is PLAUSIBLE at volume)
- **Location:** `backend/app/workers/inprocess.py:414-423` (`_persist_success` commit),
  `backend/app/workers/inprocess.py:458-470` (`_fail`), `backend/app/backup/bundle.py`
  (restore's single wipe+rebuild write transaction), `backend/app/core/retention.py`
  (bulk deletes). Verified: `grep OperationalError` over `backend/app` matches only a
  comment in `db/session.py` — there is **no** lock-retry or `OperationalError` handler
  anywhere in the codebase.
- **Problem:** SQLite allows one writer at a time; `busy_timeout=5000` makes contenders
  wait at most 5 s. Several writers can legitimately hold the write lock longer than
  that: `_persist_success` commits a 10k+-row findings flush plus scan-row updates in
  one transaction; `restore_bundle` rebuilds every table in one transaction; retention
  bulk-deletes artifact rows. Any other committer that hits the 5 s ceiling raises
  `OperationalError` — unhandled.
- **Failure scenario:** Two scans finish while a restore (or a second scan's large
  flush) holds the write lock >5 s. Scan A's `_persist_success` commit raises after 5 s;
  the `except` path **unlinks the already-written raw-artifact files** (by design, to
  avoid orphans — but here the scan actually succeeded, so its results are permanently
  lost); `_execute`'s handler then calls `_fail`, whose *own* commit hits the same
  still-held lock and fails; `_fail` swallows that (`inprocess.py:468`), so the scan is
  left `status=running` **forever** — no subprocess, no owner, not cancellable (cancel
  only accepts `queued`), not deletable (delete refuses non-terminal), reconciled only
  by `recover()` on the next container restart.
- **Fix:** (a) Add a small bounded retry-with-backoff helper for the worker's
  commits (`_persist_success`, `_fail`, the claim update) — retry `OperationalError`
  "database is locked" a few times before giving up; (b) raise `busy_timeout` for the
  worker's sessions (they are in threads / short loop hops, so waiting 30 s is safe and
  vastly better than losing results); (c) add a stale-`RUNNING` watchdog to the
  maintenance tick (see summary) so even the worst case self-heals without a restart;
  (d) only unlink artifact files in `_persist_success` after the *final* commit attempt
  fails.

### CON-2 — Subprocess kills signal only the direct child; scanner/git grandchildren survive with credentials in their environment
- **Severity:** High · **CONFIRMED** (no process-group handling exists; orphan survival is PLAUSIBLE per child behavior)
- **Location:** `backend/app/scanners/base.py:173` (`create_subprocess_exec` without
  `start_new_session`), kill paths at `base.py:191/199/204`;
  `backend/app/scanners/credentials.py:185` (`_run_git_clone`). Verified:
  `grep start_new_session|setsid|killpg` over `backend/app` matches nothing.
- **Problem:** `proc.kill()` sends SIGKILL to the direct child only. `git clone` spawns
  `git-remote-https`; trivy/grype can spawn their own helpers. On timeout, output-cap
  overflow, or shutdown cancellation, the parent dies but grandchildren keep running.
- **Failure scenario:** Worker shutdown cancels a generic private-repo scan mid-clone:
  the `git` parent is SIGKILLed, but its `git-remote-https` child keeps running with
  `SCRYE_GIT_PASSWORD` and `GIT_ASKPASS` in its environment and keeps writing into
  `clone_dir` while `generic_repo_checkout`'s `finally` races it with
  `shutil.rmtree(ignore_errors=True)` — a leaked credential-bearing process plus a
  partially-removed checkout left on the `/cache` volume.
- **Fix:** Pass `start_new_session=True` to `create_subprocess_exec` and kill the whole
  group (`os.killpg(proc.pid, signal.SIGKILL)`, suppressing `ProcessLookupError`) on the
  three abort paths. This also covers every future scanner child.

### CON-3 — Restore's "no active scans" guard is check-then-act across an await; a racing scan corrupts the restored database
- **Severity:** High · **CONFIRMED** (ordering verified in source)
- **Location:** `backend/app/api/backups.py:245-266` — the `QUEUED`/`RUNNING` count check
  runs first, then `await read_upload_capped(...)` (a multi-MB upload read — a long
  await boundary), then `run_in_threadpool(restore_bundle, ...)`.
- **Problem:** The API-11 guard is not atomic with the restore. Between the count check
  and the table wipe, `POST /api/scans` (or the maintenance tick) can commit a queued
  scan and the worker can claim it.
- **Failure scenario:** Guard sees 0 active scans; while the 200 MB upload is read, an
  operator queues a scan and the worker starts it. `restore_bundle` wipes `scans` and
  re-inserts the bundle's rows while the scan runs. When `_persist_success` commits, its
  findings either violate the FK (scan row gone → the failure chain of CON-1) or attach
  to an unrelated restored scan that reused the same rowid — silently corrupting the
  restored history with post-backup findings.
- **Fix:** Re-check the active-scan count *inside* `restore_bundle`'s write transaction
  (after `BEGIN IMMEDIATE`, before the wipe) and abort with the same 409; additionally
  pause the worker (`_accepting = False` seam) for the duration of a restore so nothing
  new can be claimed while it runs.

### CON-4 — Scanner JSON parsing and normalization run on the event loop; a large report freezes the whole app (and can fail the container healthcheck)
- **Severity:** High · **CONFIRMED**
- **Location:** `backend/app/scanners/trivy.py:285` (`parse_output(result.stdout)` inside
  `async def _execute`), `backend/app/scanners/grype.py:186`, shared
  `load_json_output` at `backend/app/scanners/base.py:345`; also
  `trivy.py:260` (version-probe `json.loads`).
- **Problem:** API-5 moved result *persistence* off the loop but not the *parse*. Scanner
  stdout is allowed up to `SCRYE_SCANNER_MAX_OUTPUT_BYTES` (default **512 MiB**);
  `json.loads` plus the per-finding normalization loop over such a payload is seconds to
  tens of seconds of pure CPU executed directly on the event loop inside the worker
  coroutine.
- **Failure scenario:** A Trivy scan of a large image emits a 100–500 MB report
  (the archive's own verification run produced 7 072 findings from one image). During
  the parse, every HTTP request — including `/healthz`, which the container healthcheck
  polls with `timeout: 10s, retries: 3` — every other scan's pipe pump, and both
  schedulers freeze. A slow enough parse fails the healthcheck and gets the container
  restarted mid-scan.
- **Fix:** Run the parse in a thread: in each scanner's `_execute`,
  `findings = await anyio.to_thread.run_sync(parse_output, result.stdout)` (and the
  same for `load_json_output`-based helpers). CPU-bound and shares no session state —
  a safe, mechanical hop.

---

## 2. Medium-severity findings

### CON-5 — Synchronous SQLite commits/reads on the event loop in async contexts; a slow writer freezes the entire app for up to `busy_timeout`
- **Severity:** Medium · **CONFIRMED** (sites verified; the 5 s stall requires a
  concurrent long writer — PLAUSIBLE at volume)
- **Location (family):** `backend/app/workers/inprocess.py:201-211` (claim
  `UPDATE`+commit+`refresh` on the loop), `inprocess.py:124-137` (`recover()`),
  `inprocess.py:262-266` (`load_trivy_policy`/`load_grype_ignore` DB reads + secret
  decrypts in `_dispatch`), `backend/app/workers/db_update.py:41+81` (`_read_policy()`
  opens `SessionLocal` inline in async `maybe_update_scanner_dbs`, every 60 s tick),
  `backend/app/api/scans.py:129+143` (`_queue_scan`'s `flush`/`commit` in async
  endpoints), `backend/app/api/scan_schedules.py:253+` (`run_schedule_now`),
  `backend/app/api/oidc.py:247/381/506` (commits in async OIDC endpoints).
- **Problem:** Unlike a `def` endpoint (threadpool), these run on the loop. Each is
  small in isolation, but any of them arriving while a long writer (CON-1's list) holds
  the write lock blocks **the whole event loop** inside the C-level `busy_timeout` wait
  — up to 5 s during which no request, healthcheck, or subprocess read progresses.
- **Failure scenario:** A finished scan's threaded findings flush holds the write lock
  for 3 s; a user's `POST /api/scans` lands; `db.commit()` at `scans.py:143` blocks the
  loop for those 3 s — every in-flight request and both schedulers stall; at >5 s it
  raises `OperationalError` and the request 500s (no retry, CON-1).
- **Fix:** Adopt the rule the codebase already applies elsewhere (API-2/5/15):
  in async contexts, DB work goes through `anyio.to_thread.run_sync` /
  `run_in_threadpool`. Highest-value hops: the worker's claim/fail commits, `_queue_scan`,
  and `db_update._read_policy` (the one 60 s-cadence offender).

### CON-6 — Shutdown arithmetic exceeds Docker's default 10 s stop grace; busy instances are SIGKILLed mid-commit
- **Severity:** Medium · **CONFIRMED** (timing arithmetic; SIGKILL outcome PLAUSIBLE)
- **Location:** `backend/app/workers/inprocess.py:83+157` (`_SHUTDOWN_GRACE_SECONDS = 10`
  drain, then cancel+gather), `inprocess.py:240` (persist runs in
  `anyio.to_thread.run_sync`, default non-cancellable — a delivered cancel waits for
  the thread), `backend/app/workers/maintenance.py:66-75` / `backup_scheduler.py:49-58`
  (shutdown awaits a task that may be inside a non-cancellable threaded
  backup/retention pass), `docker/docker-compose.yml` (no `stop_grace_period` → 10 s
  default).
- **Problem:** The worker's drain grace *alone* equals the entire container stop budget.
  Anything after it — cancelling tasks whose cancellation must wait out a threaded
  10k-findings flush, then the schedulers' own waits — runs past SIGKILL.
- **Failure scenario:** `docker stop` lands while one scan is mid-flush and a scheduled
  backup is mid-scrypt: lifespan waits 10 s for the drain, the flush thread ignores the
  cancel, the backup thread likewise; at t=10 s Docker SIGKILLs the process — possibly
  between the backup store write and its DB commit (orphan bundle file), with the WAL
  left to recover on next start.
- **Fix:** (a) Set `stop_grace_period: 60s` (or similar) in the Compose file;
  (b) shrink `_SHUTDOWN_GRACE_SECONDS` so drain + cancel fits the budget;
  (c) bound the scheduler shutdowns with `asyncio.wait_for` and log if exceeded.
  SQLite+WAL makes SIGKILL non-corrupting, but interrupted scans/backups should be the
  documented exception, not the routine stop path.

### CON-7 — Lifespan shutdown sequence is unshielded; a forced second cancellation skips the worker shutdown entirely
- **Severity:** Medium · **CONFIRMED** (structure) / PLAUSIBLE (trigger)
- **Location:** `backend/app/main.py:96-102` — `finally: await maintenance.shutdown();
  await backup_scheduler.shutdown(); await worker.shutdown()`.
- **Problem:** The three awaits run sequentially and unshielded. If the lifespan task is
  cancelled again while awaiting the first (uvicorn forced-exit path, second SIGINT),
  the `CancelledError` aborts the `finally` mid-sequence: `worker.shutdown()` never
  runs, so no scan task is cancelled and `run_command`'s kill-on-cancel never fires —
  live trivy/grype subprocesses are abandoned until SIGKILL. An exception from one
  shutdown likewise skips the rest.
- **Fix:** Wrap each shutdown in its own `try/except Exception` (log and continue), and
  shield the sequence (`await asyncio.shield(...)` per call, or run the three
  concurrently via `asyncio.gather(..., return_exceptions=True)` and log failures).

### CON-8 — `PendingMfaStore` is not thread-safe but is shared across threadpool threads
- **Severity:** Medium · **CONFIRMED**
- **Location:** `backend/app/auth/mfa.py:101-104` (`_prune` iterates
  `self._pending.items()` with no lock); store used by the sync `def` endpoints
  `login` (`api/auth.py:122`) and `verify_mfa` (`api/auth.py:187`), which run on
  different threadpool threads. Its docstring says it "mirrors the rate limiter" —
  but `SlidingWindowRateLimiter` holds a `threading.Lock` (`core/ratelimit.py:29`)
  and this store does not.
- **Failure scenario:** Two logins land concurrently: thread A's `issue()` is mid-
  iteration in `_prune()` when thread B's `issue()` inserts its challenge →
  `RuntimeError: dictionary changed size during iteration` propagates → user A's
  otherwise-correct password login 500s.
- **Fix:** Add a `threading.Lock` around `issue`/`consume`/`_prune`, exactly like the
  rate limiter.

### CON-9 — Backup bundles are not a consistent snapshot; the scheduled path has no active-scan guard, so a mid-scan backup restores as torn state
- **Severity:** Medium · **CONFIRMED** (per-table reads) / PLAUSIBLE (torn restore)
- **Location:** `backend/app/backup/bundle.py:156` (`build_bundle` dumps each table with
  its own `db.execute(select(table))`; pysqlite's legacy isolation emits `BEGIN` only
  before DML, so each SELECT is its own implicit read transaction — there is no single
  snapshot across tables); `backend/app/backup/scheduled.py` (no queued/running-scan
  check at all, unlike the manual-restore guard).
- **Failure scenario:** A scheduled backup fires while a scan runs: the `scans` table is
  dumped with the scan `running`/`findings_count=0`; the scan's flush commits; the
  `findings` table is then dumped *including* that scan's rows. Restoring this bundle
  yields a scan permanently `running` (restore never runs `recover()`) whose findings
  exist but whose counts say zero — torn history presented as an authoritative restore.
- **Fix:** Take one real read transaction for the whole dump (execute a plain `BEGIN` /
  use a connection-level transaction before the first SELECT — WAL makes a long reader
  cheap), and either skip-and-log the scheduled backup while scans are active or accept
  the snapshot and additionally reconcile non-terminal scans on restore (mark them
  `failed`, mirroring `recover()`).

### CON-10 — Every executing scan pins a pooled connection for its full wall-clock; concurrency is silently bounded by pool size, then requests 500
- **Severity:** Medium · **CONFIRMED** (mechanism) / PLAUSIBLE (exhaustion needs high `max_concurrent_scans`)
- **Location:** `backend/app/workers/inprocess.py:211` — after the claim commit,
  `session.refresh(scan)` re-begins the session transaction, checking a connection out
  of the pool; it stays checked out across the minutes-long `await self._dispatch(...)`
  until the scan's final commit. Pool is the default 5 + 10 overflow
  (`db/session.py:64-65`); `max_concurrent_scans` has no upper bound
  (`core/config.py:148`).
- **Failure scenario:** An operator raises `SCRYE_MAX_CONCURRENT_SCANS` to 15 and a
  scheduled batch fires: 15 running scans each pin a connection for minutes; request
  handlers and scheduler threads then exhaust the pool and every API call 500s with
  "QueuePool limit … reached" for the duration.
- **Fix:** Don't hold the session across the subprocess: close it (or
  `session.rollback()` + `session.close()`) after the claim, and open a fresh session
  for persistence — the worker already re-reads what it needs. Alternatively size the
  pool from `max_concurrent_scans` at engine creation and cap the setting.

### CON-11 — Scans can be committed `queued` and never submitted; every caller reports success and nothing re-submits until a restart
- **Severity:** Medium · **CONFIRMED** (paths) / PLAUSIBLE (frequency)
- **Location:** `backend/app/workers/inprocess.py:111-113` (`submit()` during shutdown
  logs a warning and returns), `backend/app/api/scans.py:144` (`_queue_scan` still
  returns 201 after that no-op), `backend/app/workers/maintenance.py:91-93` (schedule
  fires are committed in a thread, then submitted one await at a time — a shutdown
  cancellation mid-loop strands the remainder), `backend/app/workers/schedules.py:64-66`
  (the schedule row records `last_status="ok"` for a firing whose scans may never run).
- **Failure scenario:** Lifespan shutdown begins as a tick fires 5 schedules: the thread
  commits 5 `QUEUED` rows; the first `await self._worker.submit()` raises
  `CancelledError`; 4 scans have no task, the worker stops accepting, the schedule says
  `ok`. If the container is *stopped* rather than restarted, they sit `queued`
  indefinitely; the API 201 case is the same lie for a user-submitted scan.
- **Fix:** The stale-scan watchdog from CON-1's fix retires this whole family: each
  maintenance tick, re-submit `QUEUED` scans older than a small threshold that have no
  live task (the worker can expose a `has_task(scan_id)` check or simply re-submit —
  the atomic claim makes double-submission harmless).

### CON-12 — Scanner-DB auto-update marks itself done *before* running; a failed update is silently not retried until the next full interval
- **Severity:** Medium · **CONFIRMED**
- **Location:** `backend/app/workers/db_update.py:91` — `_last_update_monotonic = now`
  is assigned before the two `await _run_update(...)` calls; `_run_update` converts
  every failure to a `logger.warning` and returns.
- **Failure scenario:** A transient registry outage at the due tick: both updates fail
  (warning logs only), the marker says "done", and no retry happens for up to
  `db_update_interval_hours` (configurable to days). The vulnerability DB silently goes
  stale while the UI setting implies freshness — every scan in the window runs against
  old data, which for a vulnerability scanner is a wrong-results bug, not a hygiene nit.
- **Fix:** Set the marker only when at least one update succeeded (have `_run_update`
  return a bool); on total failure leave it unset (retry next tick) or set a short
  backoff marker. Surface the last-update result somewhere visible (About tab already
  probes DB freshness — log correlation is enough).

### CON-13 — Maintenance tick is fully serialized; two 600 s-timeout DB updates can delay due schedules and retention by up to ~20 minutes
- **Severity:** Medium · **CONFIRMED** (structure) / PLAUSIBLE (full 20 min needs slow registry)
- **Location:** `backend/app/workers/maintenance.py:77-85` — `tick()` awaits
  `_fire_schedules`, then retention, then `maybe_update_scanner_dbs` (two subprocesses,
  each capped at `_DB_UPDATE_TIMEOUT_SECONDS = 600`); `_run_loop` only starts the next
  tick after `tick()` returns.
- **Failure scenario:** `auto_update_db` enabled and a slow mirror: the update pass
  grinds toward its 2×600 s cap inside one tick; cron schedules due in minute 1 of that
  window aren't even *evaluated* until it ends — scheduled scans fire up to ~20 minutes
  late every update interval. (Cron correctness survives — `is_due` compares against
  `last_run_at` — but timeliness doesn't.)
- **Fix:** Run the DB update concurrently (`asyncio.create_task` with the usual
  exception logging, or its own loop with its own cadence), keeping the tick itself to
  schedules + retention.

---

## 3. Low-severity findings

### CON-14 — `proc.kill()` unprotected against `ProcessLookupError` on all three abort paths; on the cancel path it can replace the cancellation itself
- **Severity:** Low · **CONFIRMED** (code) / PLAUSIBLE (race window)
- **Location:** `backend/app/scanners/base.py:191, 199, 204` — `kill()` is bare, while
  the adjacent `wait()` calls are wrapped in `contextlib.suppress(ProcessLookupError)`.
- **Failure scenario:** The child exits (and is reaped by asyncio's watcher) in the race
  window just as `wait_for` expires → `proc.kill()` raises `ProcessLookupError`,
  replacing the intended "Scan timed out after Ns" with an unexpected error → the scan
  records "Unexpected internal error" (lost diagnosis). On the `CancelledError` path
  (line 204), the same raise replaces the in-flight cancellation, so a shutting-down
  task stops unwinding and proceeds to mark the scan failed and dispatch notifications
  mid-shutdown.
- **Fix:** `with contextlib.suppress(ProcessLookupError): proc.kill()` on all three
  paths (subsumed by CON-2's `killpg` fix if that lands).

### CON-15 — Notification dispatch runs while the scan still holds its concurrency-semaphore slot; dead channels consume scan capacity
- **Severity:** Low · **CONFIRMED**
- **Location:** `backend/app/workers/inprocess.py:234/247` — `await self._notify(...)`
  is inside `_run`, which runs inside `async with self._semaphore` in `_execute`;
  `dispatch_scan_event` sends per-channel sequentially with ~10 s HTTP / 15 s SMTP
  transport timeouts (`core/notifications.py`).
- **Failure scenario:** `max_concurrent_scans=2`, three channels pointing at unreachable
  endpoints: two finishing scans each spend 30–45 s in timed-out sends while holding
  their slots; queued scans wait that long for no reason.
- **Fix:** Release the slot first (move notify outside the semaphore block), or gather
  the per-channel sends concurrently — both are safe since dispatch is already
  best-effort.

### CON-16 — Per-scan task exceptions outside `_execute`'s `try` are never retrieved; task spawning is unbounded
- **Severity:** Low · **CONFIRMED** (structure) / PLAUSIBLE (trigger)
- **Location:** `backend/app/workers/inprocess.py:114-116` (done callback is only
  `self._tasks.discard`), `inprocess.py:167` (`session = self._session_factory()` sits
  inside the semaphore block but *outside* the `try`). Every submit — API or scheduler —
  creates a task with no cap beyond the semaphore (which bounds *running*, not
  *created*).
- **Failure scenario:** Session-factory failure (engine disposed in a shutdown race)
  escapes the `try` → the task dies as a GC-time "Task exception was never retrieved";
  the scan stays `QUEUED` with nothing logged at failure time. Separately, a burst of
  thousands of submits (a hammering script; a huge backlog of due schedules) piles up
  unbounded pending tasks.
- **Fix:** Move the session creation inside the `try`; give the done callback an
  `task.exception()` check that logs; optionally cap queued submissions (the DB already
  holds the durable queue — tasks for scans beyond, say, 4× the semaphore could be
  deferred to the watchdog of CON-11).

### CON-17 — "Run now" races the cron tick: duplicate scans and a lost `last_scan_id`
- **Severity:** Low · **CONFIRMED** (no coordination) / PLAUSIBLE (same-minute click)
- **Location:** `backend/app/api/scan_schedules.py:253+` (`run_schedule_now` creates a
  scan without touching `last_run_at`), vs `backend/app/workers/schedules.py:57-66`
  (the tick fires on `last_run_at` and writes `last_scan_id`/`last_status` from a
  different session).
- **Failure scenario:** Operator clicks "Run now" in the same minute the cron is due:
  both paths insert a scan from the same template — two identical back-to-back scans
  (doubled scanner load, polluted diff/trend history) — and the two commits race on
  `last_scan_id`, which ends up pointing at whichever committed last.
- **Fix:** Have "run now" also set `last_run_at = now` (it *is* a run), or have the
  tick skip a schedule whose template produced a queued/running scan in the current
  minute.

### CON-18 — Dashboard `gather` without `return_exceptions` abandons in-flight probe subprocesses on DB error
- **Severity:** Low · **CONFIRMED** (structure)
- **Location:** `backend/app/api/dashboard.py:102` —
  `await asyncio.gather(run_in_threadpool(_load_dashboard_data, db), scanner_db_status())`.
- **Failure scenario:** The DB branch raises (e.g. CON-5's lock timeout) while the
  scanner probes are mid-subprocess: the endpoint 500s immediately, the probe
  tasks/subprocesses run on detached; repeated dashboard reloads during DB contention
  accumulate duplicate concurrent probe subprocess pairs (the TTL cache is only written
  on success).
- **Fix:** `gather(..., return_exceptions=True)` and handle each branch, or run the two
  sequentially (the probes are TTL-cached and cheap on the hit path anyway).

### CON-19 — Worker can notify for a scan that was just deleted (stale identity-map read)
- **Severity:** Low · **PLAUSIBLE** (milliseconds-wide window)
- **Location:** `backend/app/workers/inprocess.py:188` — `_notify`'s
  `session.get(Scan, scan_id)` is satisfied from the session's identity map
  (`expire_on_commit=False`), so a concurrent `DELETE /api/scans/{id}` (legal the
  instant the status is terminal) is invisible.
- **Failure scenario:** `_persist_success` commits `SUCCEEDED`; a UI user deletes the
  scan in the same instant; `_notify` then dispatches a webhook announcing a scan whose
  link 404s.
- **Fix:** Not worth complexity on its own; if touched anyway (CON-15), re-select the
  scan with `session.expire(scan)` / a fresh query before dispatch.

### CON-20 — Multi-GB checkout cleanup (`shutil.rmtree`) runs synchronously on the event loop
- **Severity:** Low · **CONFIRMED**
- **Location:** `backend/app/scanners/credentials.py:289-294` —
  `generic_repo_checkout`'s `finally` shreds the askpass file (tiny, fine) and then
  `shutil.rmtree`s the clone directory — which the docstring itself notes "can be
  arbitrarily large" — inline in the async context.
- **Failure scenario:** A repo scan of a multi-GB working tree finishes (or is
  cancelled): the rmtree walks and unlinks the whole tree on the loop — seconds of
  stall on a slow volume, during which all requests and other scans' pipe reads hang.
- **Fix:** `await anyio.to_thread.run_sync(shutil.rmtree, clone_dir, ...)` for the
  checkout (keep the tmpfs shred inline — it's a single small file). Note the finally
  runs under cancellation, so the hop needs `asyncio.shield` or a
  `CancelScope(shield=True)`-style guard to complete during shutdown.

---

## 4. What was checked and found sound

Recorded so the next reviewer doesn't re-litigate these:

- **The queued→running claim vs. cancel race** (`inprocess.py:201-207` vs
  `api/scans.py:470-474`): both sides use atomic conditional `UPDATE ... WHERE status =
  'queued'`; SQLite serializes the writes, exactly one wins. Correct.
- **`run_command` pipe handling** (`scanners/base.py:105-150`): stdout/stderr are pumped
  concurrently (no pipe-buffer deadlock), stdout is byte-capped (SCN-1), the sibling
  pump is cancelled in a `finally`, and the child is killed and reaped on timeout,
  overflow, and cancellation (modulo CON-2/CON-14).
- **Credential/tmpfs cleanup on cancellation**: `docker_config_env`,
  `generic_repo_checkout`, and the policy materializers all clean up in
  `finally`/context-exit paths that run on `CancelledError` (modulo CON-20's
  loop-blocking and CON-2's racing orphan).
- **Scheduler loops survive bad ticks**: both `_run_loop`s wrap only the tick body in
  `except Exception` and use `wait_for(stopping.wait(), timeout=...)` — a tick failure
  can't kill the loop, `CancelledError` propagates correctly, and shutdown skips the
  remaining sleep.
- **SMTP sends are off-loop** (`core/notifications.py:148`), webhook/Discord/Matrix use
  async httpx, and per-channel failures are isolated (`notification_dispatch.py:89-98`).
- **Heavy work already off-loop** per the P1 audit remediation: `_persist_success` /
  `_store_failure_output` (API-5), restore (API-2), dashboard aggregation (API-7),
  maintenance schedule-fire + retention (API-15), scheduled backups.
- **WAL + `busy_timeout` + `check_same_thread=False` + per-connection pragmas**
  (`db/session.py`) is a sound baseline for this single-process design; the gaps are
  the *handling* of contention (CON-1/CON-5), not the configuration.
- **Worker interface seam** (`workers/base.py` `ScanWorker`) is honored: API and
  schedulers depend on `submit()` only, per locked decision §3.

---

## 5. Suggested fix order

1. **CON-1 + CON-11** — one change-set: worker commit retries + the maintenance-tick
   stale-scan watchdog (re-submit orphaned `QUEUED`, fail task-less `RUNNING`). Retires
   the two "stuck forever" families.
2. **CON-2 + CON-14** — process-group kill with `ProcessLookupError` suppressed;
   one function, covers all abort paths. (Credential-exposure adjacent — highest
   security relevance in this report.)
3. **CON-4** — thread-hop the scanner JSON parse (mechanical, large availability win).
4. **CON-3** — re-check the restore guard inside the write transaction.
5. **CON-6 + CON-7** — `stop_grace_period` in Compose + shielded lifespan shutdown.
6. **CON-5, CON-8, CON-9, CON-10, CON-12, CON-13** in any order; the lows
   opportunistically alongside adjacent work.
