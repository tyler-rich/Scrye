# Phase 3 Security Review — Finding #2 Resolution

**Decision:** Option 1 — Self-clone into tmpfs for generic-host authentication.

**Rationale (for `docs/PLAN.md` §14):** go-git (used internally by Trivy for repo
scanning) does not invoke the system `git` binary, so it never consults
`GIT_ASKPASS`, `.netrc`, or `credential.helper` — all three are mechanisms the
system git binary triggers, and go-git implements the git protocol natively in
Go without shelling out. GitHub/GitLab already authenticate cleanly and
off-argv via Trivy's native `GITHUB_TOKEN`/`GITLAB_TOKEN` env vars. Generic git
hosts have no equivalent, so the only way to avoid credential-in-argv exposure
is to clone with the real system `git` binary — which *does* honor
`GIT_ASKPASS` — and hand Trivy a local checkout instead of a remote URL.

This adds `git` as an image dependency and a new clone path for generic hosts.
GitHub/GitLab scanning is unaffected and continues to use Trivy's native
token-env-var path.

---

## 1. Dockerfile change

Add `git` to the scanner-runtime image, pinned to a specific version — not the
floating `git` package name:

```dockerfile
# Pin explicitly; check `apk info git` on the target Alpine version for the
# current pinned version string before merging.
RUN apk add --no-cache git=<pinned-version>
```

Do not add `git-lfs`, `git-svn`, `openssh` (git-over-ssh support), or any
other git-adjacent package unless a specific generic host requires it. Every
added package is added attack surface on a security tool's own image — keep
this to the minimum that makes HTTP(S) clone with askpass work.

After merging, run this image through the same Trivy/Grype/Docker Scout cycle
used for Lacunarr's SARIF remediation, and note the new `git` package in the
`THIRD_PARTY_LICENSES/` inventory if it isn't already covered by the base
image's manifest.

---

## 2. New module: credential-scoped clone for generic hosts

Suggested location: `backend/app/services/scanning/generic_git_clone.py`
(adjust to match Scrye's actual module layout).

### 2.1 Responsibilities

- Given a generic-host repo URL, a ref, and a credential (username + token/
  password), produce a local checkout under a tmpfs-backed scan working
  directory.
- Never place the credential in argv, in an env var visible to the whole
  process tree, in a Compose/Dockerfile layer, or in application logs.
- Guarantee cleanup of both the checkout and the askpass script even if the
  clone or the subsequent Trivy scan fails.

### 2.2 tmpfs working directory

Scrye's container should mount a tmpfs scratch path for this purpose, e.g.:

```yaml
tmpfs:
  - /tmp/scrye-scan:size=256m,mode=1700
```

Size this per your expected repo sizes — 256 MB is a starting point, not a
hard recommendation. Each scan job gets its own subdirectory under this
mount, named by job ID, so concurrent scans don't collide.

### 2.3 Askpass script generation

For each generic-host scan job:

1. Create `/tmp/scrye-scan/<job_id>/askpass.sh`.
2. Write a minimal script — no logging, no echo of anything but the requested
   field:

   ```bash
   #!/bin/sh
   case "$1" in
     Username*) printf '%s' "$GIT_ASKPASS_USERNAME" ;;
     Password*) printf '%s' "$GIT_ASKPASS_TOKEN" ;;
   esac
   ```

3. `chmod 0600` immediately after writing, before it's ever referenced.
4. Set `GIT_ASKPASS_USERNAME` / `GIT_ASKPASS_TOKEN` **only in the subprocess
   environment passed to the `git clone` call** — not in `os.environ` at the
   process level. In Python, this means building an explicit `env=` dict for
   `subprocess.run(...)` rather than mutating the parent process's
   environment.

### 2.4 Clone invocation

```python
import subprocess

def clone_generic_repo(job_id: str, repo_url: str, ref: str,
                        username: str, token: str, workdir: Path) -> Path:
    askpass_path = workdir / "askpass.sh"
    _write_askpass_script(askpass_path)  # writes + chmod 0600, see 2.3

    checkout_path = workdir / "checkout"
    env = {
        "GIT_ASKPASS": str(askpass_path),
        "GIT_ASKPASS_USERNAME": username,
        "GIT_ASKPASS_TOKEN": token,
        "GIT_TERMINAL_PROMPT": "0",  # never fall back to interactive prompt
        "PATH": os.environ["PATH"],  # git needs PATH; nothing else from parent env
    }

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref,
             repo_url, str(checkout_path)],
            env=env,
            check=True,
            capture_output=True,   # never let clone output leak into app logs unredacted
            timeout=300,
        )
    except subprocess.CalledProcessError as exc:
        # Log the failure without echoing exc.stdout/exc.stderr verbatim —
        # git error text can sometimes echo back parts of the URL/host.
        raise ScanCredentialError(f"Clone failed for job {job_id}") from exc

    return checkout_path
```

Key points for Claude Code to preserve, not improvise:

- `capture_output=True` and don't log raw stdout/stderr — git's own error
  messages have been known to echo request URLs back verbatim.
- `GIT_TERMINAL_PROMPT=0` ensures a misconfigured askpass never silently
  falls through to an interactive prompt that hangs the worker.
- The `env=` dict passed to `subprocess.run` is intentionally minimal — don't
  pass `env=os.environ.copy()` and layer on top, since that reintroduces
  whatever else is in the worker process's environment to the git subprocess
  unnecessarily.

### 2.5 Pointing Trivy at the local checkout

Once cloned, invoke Trivy against `checkout_path` as a local filesystem
target (`trivy repo <local-path>`), not the remote URL. No further git auth
is needed from this point — Trivy operates on the already-checked-out files.

### 2.6 Cleanup — guaranteed, not best-effort

```python
try:
    checkout_path = clone_generic_repo(...)
    run_trivy_scan(checkout_path)
finally:
    shutil.rmtree(workdir, ignore_errors=False)  # let failures here surface, don't swallow
```

Use `try/finally` (or an equivalent context manager) around the whole
clone-scan sequence so the tmpfs directory — checkout and askpass script both
— is removed regardless of whether the clone or the scan raises. Since this
is tmpfs, there's no disk residue either way, but don't rely on that as the
cleanup mechanism; explicitly unlink so the credential material is gone the
moment the job ends, not whenever the container next restarts.

---

## 3. `docs/PLAN.md` §14 entry

```markdown
### Finding: Phase 3 Security Review #2 — generic-host git auth (RESOLVED)

go-git does not honor GIT_ASKPASS/.netrc/credential.helper, since it never
shells out to system git. Generic (non-GitHub/GitLab) private-repo scanning
previously relied on URL-embedded credentials, which are visible via argv/
/proc within the container's own PID namespace.

Resolved by adding a scoped system-git clone path for generic hosts:
git is added to the scanner image (pinned version), credentials are passed
via a per-job 0600 GIT_ASKPASS script written to tmpfs, the credential env
vars are scoped to the clone subprocess only (not the parent process), and
both the checkout and the askpass script are removed in a `finally` block
after the scan completes. GitHub/GitLab continue to use Trivy's native
GITHUB_TOKEN/GITLAB_TOKEN path, unaffected by this change.

Trade-off accepted: `git` is now an image dependency, tracked in the regular
Trivy/Grype/Scout scan cycle and the THIRD_PARTY_LICENSES inventory.
```

---

## 4. Verification checklist before merging

- [ ] `ps aux` (or equivalent) during a generic-host scan shows no credential
      in the `git clone` process's argv.
- [ ] Askpass script permissions are `0600` at the moment `git clone` reads
      them — verify with a test that inspects the file mode mid-clone if
      feasible, not just post-hoc.
- [ ] Killing the worker mid-scan (SIGKILL, not SIGTERM) — confirm whether
      tmpfs residue survives a hard kill vs. a clean failure path. tmpfs
      contents disappear on remount/reboot regardless, but note this
      explicitly in the PR rather than assuming it.
- [ ] Trivy scan output for a generic-host repo is functionally identical to
      a GitHub-hosted repo scan (same finding categories, same report shape).
- [ ] New `git` package shows up in the post-merge Trivy/Grype/Scout scan of
      Scrye's own image, and any findings are triaged the same way Lacunarr's
      were.
- [ ] `docs/PLAN.md` §14 entry is committed alongside the code change, not as
      a follow-up.
