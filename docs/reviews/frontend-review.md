# Frontend review — Mantine v7 + TypeScript SPA

**Date:** 2026-07-11
**Scope:** the whole `frontend/src/` tree (~7,200 lines): TypeScript strictness and `any`
usage, error/loading/empty states on data-fetching components, accessibility on the finding
tables and forms, XSS risk where scanner output is rendered, state-management smells,
unnecessary re-renders, and consistency with the teal ramp / design tokens.
**Method:** independent per-dimension sweeps over the full tree, followed by a verification
pass that re-read every cited line; everything below was confirmed against the source at
review time. Line numbers refer to the tree as of this review.

Accepted decisions were **not** re-flagged: the hand-rolled `fetch` API client (FE-2,
logged deviation), base Mantine `Table` instead of `mantine-datatable`, the absent frontend
test runner (FE-10, deferred), and the custom Tailwind-teal ramp with
`primaryShade { light: 7, dark: 6 }`.

## What's in good shape

Worth stating up front, because the baseline is strong:

- **No `any`, no `@ts-ignore`/`@ts-expect-error`, no `dangerouslySetInnerHTML`, no
  `innerHTML`, no `window.open`/`location.href` sinks anywhere in `src/`.** `strict: true`
  is on. React's default escaping covers essentially all scanner-derived text (titles,
  targets, packages, errors, tags) — the one exception is P1-1 below.
- Colors are consistently Mantine tokens — zero hardcoded hex/rgb outside `theme.ts`.
- Severity and status badges render **text**, not color alone; most `ActionIcon`s carry
  `aria-label`s; settings-panel inputs are labeled.
- Dashboard has proper loading/error/empty states, uses `Anchor component={Link}` for row
  navigation, and its fetch has an unmount guard.
- Mutations mostly go through `@mantine/form` with surfaced `ApiError` messages, and the
  destructive flows (scan delete, restore) confirm first.

## Priority 1 — fix first

### P1-1 · XSS: scanner-derived `primary_url` rendered as an unvalidated `href`

`frontend/src/pages/ScanDetailPage.tsx:430`

```tsx
<Anchor href={f.primary_url} target="_blank" size="sm">
  {f.vuln_id}
</Anchor>
```

`primary_url` comes from normalized scanner JSON. For registry-image scans the URL
usually originates in the vuln DB, but scan targets are not always trusted: an uploaded
SBOM, a scanned repository, or a malicious image can influence reference URLs that Trivy/
Grype echo into their output. The href scheme is never validated, and React 18 only
*warns* about `javascript:` URLs in development — it still renders them. The CSRF cookie
(`scrye_csrf`) is deliberately JS-readable, so a clicked `javascript:` link executes in the
app origin with full ability to read the CSRF token and drive the API as the victim
(operator or admin).

**Fix:** validate the scheme before rendering as a link — render plain text unless
`primary_url` parses as `http:`/`https:` (e.g. `new URL(...)` in a small
`safeHttpUrl()` helper in `src/lib/`). Belt-and-braces: add `rel="noopener noreferrer"`.
This is the only raw-HTML/URL sink in the tree; fixing it closes the XSS dimension.

### P1-2 · Settings forms clobber user input (and can silently write defaults) — async `setValues` pattern

Three components share the pattern of rendering an editable form immediately with
hardcoded defaults, then calling `form.setValues`/`setFieldValue` when a fetch resolves:

- `frontend/src/components/settings/RetentionPanel.tsx:14–21` — form starts as
  `{ enabled: false, max_age_days: 90 }` and Save is enabled from first paint. On a slow
  connection an admin can click **Save before the GET resolves and silently disable
  artifact retention** (writes `enabled: false` over a live policy); alternatively the
  late response overwrites their in-progress edits. `GeneralPanel.tsx` has the same shape.
- `frontend/src/components/settings/BackupsPanel.tsx:58–73` — `load()` calls
  `scheduleForm.setValues(...)` on **every** invocation, and `load()` re-runs after every
  unrelated mutation (create backup, delete backup, restore). Editing the schedule
  (interval, retention, passphrase) and then deleting a stale backup resets the unsaved
  schedule edits with no warning.
- `frontend/src/pages/NewScanPage.tsx:144–162` — the FEAT-7 prefill applies instance
  defaults via `setFieldValue` when `getScannerSettings()` resolves. The `active` flag
  only guards unmount, not user edits — the comment says it runs "before the user edits
  the form", but nothing enforces that. On a slow backend, a user who has already
  narrowed the severity filter or toggled *Ignore unfixed* gets both silently reverted to
  the defaults, then launches a scan with options they explicitly deselected.

**Fix (one pattern, three sites):** don't render the form as editable until the initial
GET resolves (loading state + disabled Save), and only apply fetched values when the form
is not dirty (`form.isDirty()`); in `BackupsPanel`, split the schedule-form hydration out
of the shared `load()` so list mutations stop re-hydrating it.

### P1-3 · Scan-detail poller never stops or backs off on errors, and pins a stale "running" status

`frontend/src/pages/ScanDetailPage.tsx:96–107, 143–147`

The 2.5 s poll is gated on `isActive(scan.status)`, but a failed `loadScan()` only sets
the error string and **keeps the previous scan object in state** — so `isActive` stays
true and the interval keeps firing forever. If the backend restarts, the session expires,
or another admin deletes the scan, the page hammers a failing endpoint every 2.5 s
indefinitely while the status badge continues to claim "running".

**Fix:** on poll failure, either stop the interval after N consecutive failures with a
retry affordance, or apply exponential backoff; treat a 404 as terminal (scan gone →
navigate back with a notification).

### P1-4 · History fetch has no stale-response guard — table can contradict the filter controls

`frontend/src/pages/ScansPage.tsx:98–118`

The 250 ms debounce delays *sending* requests but never cancels in-flight ones, and
`load()` has no latest-wins check before `setData(result)`. Sequence: filter
`status=running` (slow request A), then clear the filter (fast request B) — B renders,
then A resolves and overwrites the table and total with results for the old filter. The
rows and the `Pagination` widget now silently contradict the visible filter state until
something triggers a reload.

**Fix:** pass an `AbortController` through `listHistory` and abort on effect cleanup, or
keep a request sequence number and ignore out-of-order resolutions. The same guard
belongs in `ScanDetailPage.loadFindings` (see P2-3).

## Priority 2 — correctness and accessibility gaps

### P2-1 · Tag draft is wiped every 2.5 s while a scan is active

`frontend/src/pages/ScanDetailPage.tsx:96–107 (line 100)`

`loadScan()` unconditionally does `setTagDraft(s.tags)`, and the status poll calls
`loadScan` every 2.5 s while the scan is queued/running. An operator typing tags into the
`TagsInput` on an active scan has the half-entered draft silently reset to the server's
list on every poll tick. **Fix:** only reset the draft on id change or when the draft is
pristine, not on every poll refresh.

### P2-2 · Navigating between scan details mixes two scans' state

`frontend/src/pages/ScanDetailPage.tsx:150–163`

React Router reuses the component instance when only `:scanId` changes, and no state is
reset on id change. The artifacts/findings effects are gated on `scan?.status` — which
still holds the *previous* scan — so navigating from a succeeded scan #5 to a running
scan #7 immediately fires `listArtifacts(7)`/`listFindings(7)` (gated by #5's
"succeeded"), while the header still shows scan #5's summary until `loadScan(7)` lands.
**Fix:** reset `scan`/`findings`/`artifacts`/`tagDraft` in an effect keyed on `id` (or
key the route element by `scanId`).

### P2-3 · Findings panel: empty-state flash, stale rows during filter changes, no loading flag

`frontend/src/pages/ScanDetailPage.tsx:403`

`findings` initializes to `[]` with no loading flag, so a succeeded scan renders
*"No findings match the current filters."* until the first `listFindings` resolves — a
false statement about a scan with thousands of findings. Changing the severity/class
filter keeps rendering the previous filter's rows (no spinner, no dimming) until the new
response lands, and there is no stale-response guard for rapid filter toggles. **Fix:**
track a loading flag (render `Loader`/skeleton instead of the empty-state text while
pending) and apply the same latest-wins guard as P1-4.

### P2-4 · Unguarded mutations double-fire — including minting an invisible API token

No in-flight disable/loading state on:

- `frontend/src/components/settings/ApiTokensPanel.tsx:210` — double-clicking **Create**
  mints two tokens; `setPlaintext` shows only the second, leaving an **active bearer
  token the user has never seen and cannot copy** — a real credential-hygiene problem in
  a security tool. (`UsersPanel` create shares the pattern.)
- `frontend/src/components/settings/ScheduledScansPanel.tsx:204` — double-clicking
  **Run now** queues duplicate scans; the row's Delete icon double-fires too.
- `frontend/src/pages/AccountPage.tsx:164, 183` — double-clicking **Confirm & enable**
  sends `activateMfa` twice: the first enables MFA, the second is rejected and its catch
  overwrites the status with a red failure alert — the user believes enrollment failed on
  an account where MFA is now active. **Disable MFA** and session **Revoke**
  (`AccountPage.tsx:276`) share the missing guard.

**Fix:** the codebase already has the right idiom (`loading={savingTags}` /
`loading={deleting}` on ScanDetailPage, `busy` on BackupsPanel) — apply it to these
handlers.

### P2-5 · History table is unusable by keyboard: click-only sorting and click-only row navigation

`frontend/src/pages/ScansPage.tsx:566–578 (SortableTh), 485–495 (row cells)`

- `SortableTh` is a `Table.Th` with `onClick` and a pointer cursor — no button element,
  no `tabIndex`/key handler, no `aria-sort`. Keyboard users cannot sort at all;
  screen-reader users are never told the sort column/direction (WCAG 2.1.1, 4.1.2).
- Opening a scan's detail is `onClick` on two `Table.Td` cells; the only focusable
  control in a row is the compare checkbox, so keyboard users **cannot open any scan from
  the history table** (they must know the URL).

**Fix:** wrap header content in an `UnstyledButton` (focusable, Enter/Space) and set
`aria-sort` on the active `Th`; make the target cell content an `Anchor
component={Link}` to `/scans/:id` (the Dashboard's recent-scans table already does this
correctly).

### P2-6 · Unlabeled form controls (accessible-name gaps)

- `frontend/src/pages/ScanDetailPage.tsx:384–399` — severity/class filter `Select`s are
  placeholder-only; once a value is chosen the placeholder disappears and the comboboxes
  have no accessible name at all.
- `frontend/src/pages/ScanDetailPage.tsx:326` — the tags `TagsInput` is
  placeholder-only.
- `frontend/src/pages/NewScanPage.tsx:236–261` — the *Target type* and *Scanner*
  `SegmentedControl`s are "labeled" by adjacent `Text` with no
  `aria-label`/`aria-labelledby` association: two anonymous radio groups.
- `frontend/src/pages/AccountPage.tsx:181` — the MFA-enrollment `PinInput` has no
  `aria-label`; the LoginPage instance (`LoginPage.tsx:136`) already sets
  `aria-label="Authentication code"` — copy it.

**Fix:** add `label` or `aria-label` at each site.

### P2-7 · All navigation disappears below the `sm` breakpoint

`frontend/src/App.tsx:43`

`NavLinks` is wrapped in `Group visibleFrom="sm"` with no burger/drawer alternative.
On a phone — or for a low-vision user at 400 % zoom (WCAG 1.4.10 reflow) — the app has
**no navigation at all**; pages are reachable only by editing the URL. **Fix:** add the
standard Mantine `Burger` + `AppShell.Navbar`/`Drawer` fallback below `sm`.

## Priority 3 — polish, consistency, hardening

### P3-1 · History filters live only in memory — Back loses everything

`frontend/src/pages/ScansPage.tsx:78–96`. Filters, sort, and page state are `useState`
only. Building a filter set, opening a scan, and pressing Back remounts `ScansPage` with
`EMPTY_FILTERS` on page 1; filtered views can't be bookmarked or shared, even though
history is the app's primary deep-linkable view (plan §4.4 — saved presets only partially
compensate). **Fix:** mirror filters/sort/page into `useSearchParams`.

### P3-2 · Compare selection drifts from the visible table

`frontend/src/pages/ScansPage.tsx:90, 194–211`. `compare` stores full `Scan` snapshots
that survive filter/page changes: the bar can claim "1/2 selected" for a row that is no
longer visible (its checkbox unreachable except via the blanket clear), and a selected
scan deleted elsewhere still navigates to a diff that 404s. Minor UX; consider clearing
selections on filter change or storing ids + re-validating on compare.

### P3-3 · Silent empty catches hide real failures

`frontend/src/pages/NewScanPage.tsx:104` — if the registry/git-credential option fetch
fails, the pickers silently render empty; an operator assumes no credentials are
configured and launches a private-image scan anonymously, which fails minutes later with
an opaque auth error. `frontend/src/pages/ScansPage.tsx:125–127` does the same for filter
options/presets. **Fix:** surface a non-blocking warning (notification or inline hint)
instead of an empty `catch`.

### P3-4 · Auth refresh can resurrect a logged-out session (narrow race)

`frontend/src/auth/AuthContext.tsx:44–57`. `refresh()` unconditionally replaces auth
state; there is no sequencing against the `scrye:auth-invalidated` event, so a stale
in-flight `fetchAuthStatus` (answered before revocation) can restore a dead `user` after
a 401 already dropped the UI to the login screen — the shell flashes back until the next
401. Low likelihood, self-healing; a monotonic token/timestamp check in `refresh` closes
it.

### P3-5 · 500-row findings table re-renders on every unrelated keystroke

`frontend/src/pages/ScanDetailPage.tsx`. The findings table (up to `FINDINGS_LIMIT` = 500
rows × ~7 cells) lives in the same component as `tagDraft`, so every keystroke in the
tags editor — and every 2.5 s poll `setScan` on an active scan — re-renders all rows.
With the 500-row cap this is jank, not a hang (the cap plus "download the raw artifact"
note is a sensible design). **Fix cheaply:** extract the table into a memoized child that
takes only `findings`, or wrap rows in `memo`. The paginated 25-row history table is fine
as-is.

### P3-6 · Loading states are silent for screen readers; chart ARIA is inert

Mantine `Loader` (App.tsx:69, ScansPage.tsx:418, ScanDetailPage.tsx:188, etc.) renders a
bare SVG — no `role="status"`/`aria-live`, so loads are announced as nothing. The
dashboard's `ScansOverTime` bars (`Dashboard.tsx:53–64`) put `aria-label` on plain `div`s
without a `role`, which most screen readers ignore — the chart has no useful text
alternative. **Fix:** wrap loaders in a `role="status"` container with visually hidden
text; give the chart a `role="img"` + summary label on the container.

### P3-7 · Theme-token drift (small, but the kind that compounds)

- `frontend/src/pages/Dashboard.tsx:141–142, 196, 201` — severity colors are re-stated
  as `"red"`/`"orange"` literals instead of `SEVERITY_COLOR` from `SeverityBadge.tsx`,
  the map that is supposed to be the single source (drift risk if the severity palette is
  ever tuned).
- `frontend/src/pages/Dashboard.tsx:60` — the chart pins
  `var(--mantine-color-teal-6)`, i.e. the *dark-mode* primary shade, in both schemes;
  `var(--mantine-primary-color-filled)` would track `primaryShade` per mode.
- Widespread explicit `color="teal"` on `Loader`/`Pagination`/badges is redundant with
  `primaryColor: 'teal'` and would silently pin these controls if the primary ever
  changed. Harmless today; worth normalizing opportunistically, not as a dedicated pass.

Otherwise the teal ramp is used consistently and nothing hardcodes colors that break in
either scheme — light/dark posture is genuinely first-class.

### P3-8 · TypeScript strictness — residual gaps, not violations

- The tree has **zero** `any` and `strict` is on; the remaining type-safety hole is the
  systemic `(await response.json()) as T` in `api/client.ts:74/107` — every API response
  is a blind cast. This is inherent to the accepted hand-rolled client (FE-2), so it's
  noted as residual risk, not re-litigated: if the client is ever revisited, generating
  types from the OpenAPI schema (per CLAUDE.md § Coding standards) or adding a thin
  runtime guard on the few security-relevant payloads is the upgrade path.
- `noUncheckedIndexedAccess` is off (`tsconfig.app.json`); current index accesses are
  guarded by inspection (`compare[0]` behind a length check, `SCANNERS_FOR[targetType]`
  over a closed union), so enabling it is cheap now and prevents the class.
- ESLint runs `tseslint.configs.recommended` (not type-aware); `no-floating-promises`
  etc. are absent — the codebase self-polices with `void` prefixes today, but the rule
  would enforce it.
- The `onChange={(v) => patch({ scanner: (v as Scan['scanner']) ?? null })}`-style casts
  on `Select` handlers (ScansPage.tsx:265–300, ScanDetailPage.tsx:390/398) are safe while
  `data` stays a closed list; a typed `Select` wrapper would remove the pattern.

## Suggested fix order

1. **P1-1** (XSS href guard) — small, closes the only security finding.
2. **P1-2** (async form clobber ×3) — one shared pattern; prevents silent
   misconfiguration of retention/backups and wrong scan options.
3. **P1-3 + P1-4 + P2-3** (poller backoff, latest-wins guards, findings loading flag) —
   same fetch-lifecycle theme, naturally one PR.
4. **P2-4** (mutation in-flight guards) — mechanical, existing idiom.
5. **P2-5/6/7** (keyboard table access, labels, mobile nav) — the accessibility batch.
6. P2-1/2, then the P3 items opportunistically.
