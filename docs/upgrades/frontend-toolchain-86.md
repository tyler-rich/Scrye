# Frontend toolchain sweep (#86 / #145 / #153) — scoping and sequence

> **Status:** scoping only. Nothing in this document has been applied. No dependency
> version, lockfile, or config file was changed by the session that produced it.
>
> **Scope:** the frontend tooling majors tracked in
> [`docs/ROADMAP.md`](../ROADMAP.md) § Track A → *"Frontend tooling majors from
> Dependabot #86"*, whose currently-open expression is
> [#153](https://github.com/tyler-rich/Scrye/pull/153).
>
> **What this replaces:** #153 is one PR carrying eleven majors with a single red
> check. That gives no signal about which bump caused what. This document turns it
> into an ordered series of independently verifiable steps.
>
> **Date of the evidence:** 2026-08-09. Every version number, peer range, and
> engine constraint below was read from the npm registry or from the published
> package tarball on that date. Where a claim comes from a migration guide rather
> than package metadata, the guide is named.
>
> **One constraint is dated and will expire:** the TypeScript ceiling of 6.0.3
> holds only while `typescript-eslint`'s `typescript` peer range does. **§3.1
> carries the one-command re-check** — run it before treating that ceiling as
> current.
>
> **Corrected 2026-08-09, after step 1 landed as #171:** §0.3's original claim
> that the typescript-eslint bump leaves the resolved rule set fully unchanged
> was wrong — it diffed one of three layers in a composite config and
> generalised. See §0.3 for the correction and the method note it adds, binding
> on every step below that has not yet run. Sequence membership and ordering are
> unchanged; only claims and method notes were corrected. `docs/ARCHIVE.md` §14
> carries the full record, dated 2026-08-09.

---

## 0. Headline findings

Four things are true that the existing records do not say, and one thing they say
is wrong.

1. **TypeScript 7 is not part of this sweep — as of 2026-08-09.** `typescript@7.0.2`
   is the Go-native compiler. Its `"."` export is `./lib/version.cjs` — importing
   `'typescript'` yields the version string and nothing else. The classic compiler
   API (`lib/typescript.js`) is not in the package. `@typescript-eslint/typescript-estree`
   calls `require("typescript")` in 11 places and uses 114 distinct `ts.*` symbols
   from that API. No `typescript-eslint` published **as of 2026-08-09** accepts
   TypeScript 7 — its peer range is `>=4.8.4 <6.1.0` right up to the current canary.
   **The TypeScript ceiling for this sweep is 6.0.3.** This is a dated ceiling, not
   a permanent blocker — **§3.1 gives the one-command way to re-check it**, and
   anyone reading this more than a few weeks after 2026-08-09 should run that check
   before treating the ceiling as current.

2. **#153's red check is not lint churn.** `Frontend — lint + build` failed after
   **6 seconds**, at `npm ci`, with `ERESOLVE`: `typescript-eslint@8.66.0` peer
   `typescript@">=4.8.4 <6.1.0"` against the proposed `typescript@7.0.2`. ESLint
   never ran. The `docs/ROADMAP.md` Track A entry and `docs/ARCHIVE.md` §14
   (2026-08-09) both describe this failure as *"the type-aware-ESLint churn that
   roadmap item predicts, arriving on schedule."* That characterisation is
   incorrect and is corrected in the §14 entry accompanying this document.

3. **CORRECTED 2026-08-09, after step 1 landed — the typescript-eslint bump does
   not leave rule *selection* fully unchanged, and an unchanged rule set would not
   have implied an unchanged set of findings anyway.** What was actually verified,
   and remains true: the shipped **`dist/configs/recommended-type-checked.js`**
   file is **byte-for-byte identical** between 8.19.0 and 8.66.0 — the same 50
   rules at the same severities (verified by diffing that one file from both
   tarballs). What was **not** verified, and turned out to be false when checked:
   `tseslint.configs.recommendedTypeChecked` is a **three-layer composite**
   (`base` + `eslint-recommended` + `recommended-type-checked`), and only the
   third layer was diffed; the finding was then generalised to the whole
   composite. The undiffed `dist/configs/eslint-recommended-raw.js` layer went
   **22 → 23 entries** across the same span, adding `no-with: 'off'`. Because
   `frontend/eslint.config.js` extends `js.configs.recommended` **before** the
   tseslint layers, that addition changes the fully-resolved config this repo
   actually lints with: `eslint --print-config` shows `no-with` going from
   `error` (`[2]`) to `off` (`[0]`) across all three file classes (app `.tsx`,
   library `.ts`, test override). So the resolved rule set **did** change — one
   core rule was disabled — not "nothing added, removed, or re-severitied" as
   this section previously claimed. (The disablement was accepted, not restored,
   after independent verification that `with` is unreachable here regardless: a
   probe `with` statement fails `tsc -b` with `TS1101`/`TS2410` under this
   repo's `"strict": true` tsconfigs. See `docs/ARCHIVE.md` §14, 2026-08-09,
   "#86 sweep step 1 landed", for the full account.)

   Separately, **even a genuinely unchanged rule set does not predict an
   unchanged set of reports.** Rule *implementations* get stricter across a
   47-minor span independent of which rules are selected — step 1 alone produced
   two new `@typescript-eslint/no-unnecessary-type-assertion` reports on code
   that had been in the tree, unedited, the whole time. Read every "Expected
   breakage" row in §6 as a floor on what a step can surface, not a ceiling —
   it names the known, artifact-verified deltas; report volume from
   implementation changes is separate and was never boundable without running
   the step.

   > **Method note, binding on every step below that has not yet run.** Do not
   > trust this document's characterisation of a step's config or rule-set
   > impact — re-verify against the **installed** tree when the step is
   > actually executed, and check **every layer** of any composite config, not
   > just the plugin's own top-level config file. The check that would have
   > caught the `no-with` miss, and is the one to run before and after each
   > remaining step: resolve the **fully-merged** config with
   > `eslint --print-config <file>` for one representative file of each file
   > class (app `.tsx`, library `.ts`, test override) and diff the two outputs —
   > not a diff of the plugin's own shipped config file, which only shows one
   > layer of what actually gets applied.

4. **ESLint 10 removes a live HIGH advisory from the tree.** `eslint@10.8.1` no
   longer depends on `@eslint/eslintrc`, which is this repo's only path to
   `js-yaml` — one of the two HIGH findings in the current baseline (§1).

5. **GHSA-qwww-vcr4-c8h2 was re-cut upstream — confirmed at the GitHub Advisory
   Database itself, not inferred from npm.** The advisory record now carries **two
   separate `affected` entries** — `react-router` `[7.12.0, 7.18.2)` and
   `react-router` `[8.0.0, 8.3.0)` — where it previously carried one contiguous
   `>= 7.12.0, < 8.3.0`. It is an **upstream amendment, not a registry-side
   quirk**; the evidence is in §9. This is exactly the change `docs/ROADMAP.md`
   § Track A asks for under *"Ask GitHub to re-cut GHSA-qwww-vcr4-c8h2's affected
   range for the 7.18.2 backport"*, including its "leave the 8.x range as it is"
   condition. Reported here, not acted on; `docs/ROADMAP.md` was deliberately left
   unedited.

---

## 1. Baseline (current `dev`, unmodified)

Recorded so every step below has something to be compared against.

| | |
|---|---|
| Commit | `83aa52e` (branch point for this doc's branch) |
| `frontend/package-lock.json` last touched | `004d2b5` (#147, 2026-08-03) |
| Node (this sandbox) | 22.22.2 · npm 10.9.7 |
| Node (CI + image) | 24 — `ci.yml` `node-version: "24"`; `docker/Dockerfile:27` `node:24-bookworm-slim@sha256:235600a8…` |
| `npm ci` | clean install from the committed lockfile; lockfile SHA-256 unchanged afterwards |
| `npm run lint` | **pass**, 0 problems |
| `npm run format:check` | **pass**, all files match Prettier style |
| `npm test` | **pass** — 21 files, 79 tests (4 `*.test.ts` under `node`, 17 `*.test.tsx` under `jsdom`) |
| `npm run build` | **pass** — `vite v6.4.3`, 7035 modules, `index.js` 645.18 kB (gzip 193.61), `index.css` 201.38 kB (gzip 29.30), 7.19 s |
| `npm audit` | **2 high, 0 critical/moderate/low** |

Source surface: 51 `.tsx`, 28 `.ts`, 10 513 lines under `frontend/src/`; 23 files
using `useEffect`, 15 using `useMemo`/`useCallback`, 12 importing `react-router-dom`.

### The two HIGH advisories, and what actually clears them

| Package | Path | Advisory range | Installed | Clears by |
|---|---|---|---|---|
| `js-yaml` | `eslint@9.39.4 → @eslint/eslintrc@3.3.5 → js-yaml@4.3.0` | `4.0.0 – 4.3.0` | 4.3.0 | **lockfile refresh alone** — eslintrc's range is `^4.3.0` and 4.3.1 exists. Permanently removed by Step 2 (ESLint 10 drops `@eslint/eslintrc`). |
| `nanoid` | `postcss@8.5.25 → nanoid@3.3.16` | `<3.3.17` | 3.3.16 | **lockfile refresh alone** — postcss's range is `^3.3.16` and 3.3.18 exists. `postcss@8.5.26` additionally raises the floor to `^3.3.17`. |

Neither needs any part of this sweep. Both are inside existing semver ranges, so
`npm update js-yaml nanoid` is a lockfile-only change.

> This differs from the record in `docs/ARCHIVE.md` §14 (2026-08-03), which stated
> that `npm audit`'s only finding was the `react-router` HIGH. Both of these are
> newer advisories, and the `react-router` one is gone (§0.5).

---

## 2. The real inventory

Every package #153 proposes, plus what it is actually current at today. **"Majors
crossed"** counts the major boundaries between the pinned and proposed version,
not the arithmetic difference.

| Package | Pinned | #153 proposes | Latest 2026-08-09 | Majors crossed | Verdict |
|---|---|---|---|---|---|
| `typescript` | 5.7.2 | **7.0.2** | 7.0.2 | **2** (→6, →7) | **Cap at 6.0.3.** 7 is unusable (§3.1) |
| `eslint` | 9.39.4 | 10.8.0 | **10.8.1** *(stale)* | 1 | Take 10.8.1 |
| `@eslint/js` | 9.39.4 | 10.0.1 | 10.0.1 | 1 | Take; pairs with `eslint` |
| `typescript-eslint` | 8.19.0 | 8.66.0 | 8.66.0 | 0 (47 minors) | **Take first** — it is the gate (§3.2) |
| `vite` | 6.4.3 | 8.2.0 | **8.2.1** *(stale)* | **2** (→7, →8) | Take 8.2.1, with plugin-react |
| `@vitejs/plugin-react` | 4.3.4 | 6.0.5 | 6.0.5 | **2** (→5, →6) | Lockstep with Vite 8 (§3.3) |
| `vitest` | 3.2.7 | 4.1.10 | 4.1.10 | 1 | Independent of the Vite major (§3.4) |
| `jsdom` | 26.1.0 | 30.0.1 | 30.0.1 | **4** (→27,28,29,30) | Take; raises the Node floor (§6.5) |
| `eslint-plugin-react-hooks` | 5.1.0 | 7.1.1 | 7.1.1 | **2** (→6, →7) | **Peer-forced by ESLint 10** (§3.5) |
| `eslint-plugin-react-refresh` | 0.4.16 | 0.5.3 | 0.5.3 | 1 (0.x minor) | Not forced; take anyway, no config edit (§6.4) |
| `@types/node` | 24.13.3 | 26.1.2 | **26.2.0** *(stale)* | 2 | **Not needed** (§4) |
| `globals` | 17.8.0 | 17.9.0 | 17.9.0 | 0 | Routine minor |
| `@testing-library/user-event` | 14.6.1 | 14.6.3 | 14.6.3 | 0 | Routine patch |

**Not in #153 but available and relevant:** `postcss` 8.5.25 → **8.5.26**
(2026-08-06) — moves the `nanoid` floor past the HIGH above.

**Three of #153's targets are already stale**, which is expected: the PR was cut
2026-08-07 from `004d2b5` and `eslint`, `vite`, and `@types/node` all published
newer releases on 2026-08-06/07. This is the ordinary cost of leaving a Dependabot
PR open as a reminder surface — it is a snapshot of a moment, not a live shopping
list. Read the targets from the registry when the work starts, not from the PR.

---

## 3. The dependency graph

Every constraint below is cited to one of two kinds of source: **[peer]** = a
`peerDependencies` range in a published package on the npm registry, or
**[guide]** = a statement in upstream's migration guide/changelog. Nothing here is
inferred from version-number proximity.

### 3.1 TypeScript ← typescript-eslint (the cap, as of 2026-08-09, and how to re-check it)

> **This constraint has a shelf life. Re-check it before acting on it.**
>
> ```sh
> npm view typescript-eslint@latest peerDependencies.typescript
> # 2026-08-09 → >=4.8.4 <6.1.0     (TypeScript 6.0.x is the ceiling)
> # if the upper bound is ever >=7.0.0, TypeScript 7 is back on the table
> ```
>
> **What to watch:** the `typescript` entry of **`typescript-eslint`'s**
> `peerDependencies` (the umbrella package this repo pins). It is the single field
> that decides the ceiling — `@typescript-eslint/typescript-estree` and
> `@typescript-eslint/parser` carry the same range and move together, so checking
> the umbrella is sufficient. Watch the **stable `latest`** tag; a `canary`/`rc-v8`
> tag admitting TS 7 is a signal that work has started, not that it has shipped.
> Upstream's process is documented — see the **[guide]** citation at the end of
> this section — and pins a *"New TypeScript Version"* tracking issue per release.
>
> **The likely shape of the answer, so a widened range is not over-read:** because
> TypeScript 7 replaces the API rather than changing it (below), support is
> expected to arrive as a **new typescript-eslint major** built against the
> `./unstable/*` surface, not as a point-release range widen. Treat a jump in the
> major version number alongside the range change as the real signal.

**[peer]** `typescript-eslint@8.66.0` (published 2026-08-03, `latest` on
**2026-08-09**) declares `typescript: ">=4.8.4 <6.1.0"`. Its canary,
`8.66.1-alpha.10` (2026-08-07), declares the same. **As of that date, no published
version of `typescript-eslint` accepts TypeScript 7.**

The cap is not upstream being cautious. From the published `typescript@7.0.2`
tarball:

```
package.json  "exports": { ".": "./lib/version.cjs", "./unstable/sync": …,
                           "./unstable/async": …, "./unstable/ast": …, … }
package.json  "bin":     { "tsc": "bin/tsc" }          ← tsserver removed
lib/                     getExePath.js  tsc.js  version.cjs   ← no typescript.js
dependencies             20 × @typescript/typescript-<os>-<arch>@7.0.2 (native binaries)
unpackedSize             2 497 498 bytes   (5.7.2: 22 739 967 · 6.0.3: 24 346 827)
```

`import ts from 'typescript'` in TS 7 resolves to `lib/version.cjs`. The real API
lives behind `./unstable/*` subpaths and talks to the Go binary over
`vendor/vscode-jsonrpc`. Against that, from the published
`@typescript-eslint/typescript-estree@8.66.0` tarball: `require("typescript")`
appears 11 times in `dist/*.js`, referencing **114 distinct `ts.*` symbols**
including `ts.createProgram`. This is not a version-range formality; the API
`typescript-eslint` is built on does not exist in the package any more.

**[guide]** typescript-eslint's *Dependency Versions* doc states the supported
range is whatever the package's peer range says, that they mirror DefinitelyTyped's
two-year support window, and that they *"will always endeavor to support the latest
stable version of TypeScript"* — with support tracked per release under the
*"New TypeScript Version"* issue label. There is no published TS 7 support, and
the shape of the change (a whole new async/RPC API surface, itself marked
`unstable`) means it is a rewrite upstream, not a range widen.

**Upstream says the same thing from the TypeScript side.** The TypeScript 6.0
release notes describe 6.0 as *"a significant transition release, designed to
prepare developers for TypeScript 7.0, the upcoming native port of the TypeScript
compiler"*, and state that it *"continues to be **API compatible with TypeScript
5.9**"*. That is the sentence that makes **Step 4 safe and Step 4-plus-one not**:
`typescript-eslint` works against 6.0 because 6.0 keeps the 5.9 API, and cannot
work against 7.0 because 7.0 does not. Options that 6.0 merely *deprecates* are
*"removed entirely in TypeScript 7.0"*.

**Also true, and worth recording so nobody re-derives it:** `tsc -b` survives.
Running the TS 7.0.2 native binary directly, `--build, -b` is still in `tsc --help`
(*"Build one or more projects and their dependencies, if out of date"*), so
`npm run build`'s `tsc -b && vite build` is not what blocks TS 7. Only the linter is.

**Ceiling:** `typescript@6.0.3` (2026-04-16) — the newest release inside
`<6.1.0`, and the last JS-based TypeScript. The current pin 5.7.2 → 6.0.3 crosses
one usable major.

### 3.2 typescript-eslint gates everything else

**[peer]** The `typescript-eslint` peer ranges, read across every stable release
from the current pin forward, and reported only where the range changed:

| First version | Published | `eslint` peer | `typescript` peer |
|---|---|---|---|
| 8.19.0 *(pinned)* | 2024-12-30 | `^8.57.0 \|\| ^9.0.0` | `>=4.8.4 <5.8.0` |
| 8.26.0 | 2025-03-03 | `^8.57.0 \|\| ^9.0.0` | `>=4.8.4 <5.9.0` |
| 8.39.0 | 2025-08-04 | `^8.57.0 \|\| ^9.0.0` | `>=4.8.4 <6.0.0` |
| **8.56.0** | 2026-02-16 | **`… \|\| ^10.0.0`** | `>=4.8.4 <6.0.0` |
| **8.58.0** | 2026-03-30 | `… \|\| ^10.0.0` | **`>=4.8.4 <6.1.0`** |

Two consequences:

- **ESLint 10 requires `typescript-eslint >= 8.56.0`.** The pinned 8.19.0 caps at
  ESLint 9.
- **TypeScript 6.0.x requires `typescript-eslint >= 8.58.0`.** The pinned 8.19.0
  caps at TypeScript 5.7 — it will not even accept 5.8.

`typescript-eslint` therefore has to move **before** both other steps, and moving
it to the current `8.66.0` satisfies both at once. This is why the "it's only a
minor, take it in routine triage" reading (rejected in `docs/ARCHIVE.md` §14,
2026-08-03) was right to be rejected — but for a sharper reason than recorded
there: it is not merely that it would need reviewing twice, it is that it is the
**only** unblocking move in the set.

### 3.3 `@vitejs/plugin-react` 6 requires Vite 8 — it does not merely tolerate it

Both kinds of evidence agree:

- **[peer]** `@vitejs/plugin-react@6.0.5` declares `vite: "^8.0.0"` — Vite 6 and 7
  are excluded. (4.3.4 declares `^4.2.0 || ^5.0.0 || ^6.0.0`; 5.0.0 adds `^7.0.0`;
  6.0.0 narrows to `^8.0.0` only.)
- **[guide]** The plugin's `CHANGELOG.md` for 6.0.0 (2026-03-12) has a heading
  *"Drop Vite 7 and below support ([#1124])"* — *"Vite 7 and below are no longer
  supported. If you are using Vite 7, please upgrade to Vite 8."*

So `vite` and `@vitejs/plugin-react` move together, in one step, and there is no
version of the plugin that spans the boundary. (`@vitejs/plugin-react@5.x` supports
Vite 6 and 7, so a Vite-6→7-only step is possible with plugin 5 — but it buys
nothing, since Vite 7 is not a destination.)

### 3.4 Vitest 4 does **not** require a Vite major

Both kinds of evidence agree, in the opposite direction:

- **[peer]** `vitest@4.1.10` declares `vite: "^6.0.0 || ^7.0.0 || ^8.0.0"` (a
  required peer, `optional: false`, and also a real `dependencies` entry at the
  same range). The pinned `vite@6.4.3` satisfies it.
- **[guide]** The Vitest 4 migration guide opens with a *Prerequisites* callout:
  *"Vitest 4.0 requires **Vite >= 6.0.0** and **Node.js >= 20.0.0**."*

Vitest 4 can therefore land on the current Vite 6, and should — see the ordering
argument in §5.

### 3.5 ESLint 10 forces `eslint-plugin-react-hooks` 7, which forces a decision

**[peer]** `eslint-plugin-react-hooks@5.1.0` (pinned) declares
`eslint: "^3 || ^4 || ^5 || ^6 || ^7 || ^8.0.0-0 || ^9.0.0"` — **no `^10`**. So do
6.0.0, 7.0.0, and 7.0.1. The `^10.0.0` clause first appears in **7.1.0**
(2026-04-16). Taking ESLint 10 with the pinned plugin is an `npm ci` ERESOLVE, the
same class of failure that killed #153.

And 7.x is where the React Compiler lands. From the published 7.1.1 bundle
(`cjs/eslint-plugin-react-hooks.development.js`):

```js
const basicRuleConfigs = {
  'react-hooks/rules-of-hooks': 'error',
  'react-hooks/exhaustive-deps': 'warn',
};
const recommendedRuleConfigs =
  Object.assign({}, basicRuleConfigs, recommendedCompilerRuleConfigs);
const configs = { recommended: { plugins, rules: recommendedRuleConfigs }, … };
```

`frontend/eslint.config.js:31` spreads exactly that object:
`...reactHooks.configs.recommended.rules`. Under 5.1.0 it contributes **2 rules**.
Under 7.1.1 it contributes those two **plus every React Compiler lint rule whose
preset is `Recommended`** — 14 more, enumerated from the same bundle:

| Severity | Rules added to `configs.recommended` by 7.1.1 |
|---|---|
| `error` (12) | `config`, `error-boundaries`, `gating`, `globals`, `immutability`, `preserve-manual-memoization`, `purity`, `refs`, `set-state-in-effect`, `set-state-in-render`, `static-components`, `use-memo` |
| `warn` (2) | `incompatible-library`, `unsupported-syntax` |

(A further 11 compiler rules ship at preset `Off`, and `void-use-memo` is in
`recommended-latest` only. `component-hook-factories` is present but deprecated as
of 7.1.0.)

The plugin also gains real runtime dependencies it did not have — `@babel/core`,
`@babel/parser`, `hermes-parser`, `zod`, `zod-validation-error` (5.1.0 had none) —
and its bundle grows from 87 kB to 2.04 MB.

**This is a decision, not a side effect**, and §5 splits it into its own step.

### 3.6 `@eslint/js` — convention, not a hard peer

**[peer]** `@eslint/js@10.0.1` declares `eslint: "^10.0.0"` but marks it
**optional** (`peerDependenciesMeta.eslint.optional: true`), so npm will not block
a mismatch. It still has to move with ESLint 10 for two real reasons:

- `eslint@10.8.1` **no longer lists `@eslint/js` in its own `dependencies`**
  (9.39.4 did, pinned exactly to `9.39.4`). In ESLint 10 it is fully external.
- **[guide]** The ESLint 10 migration guide's *"`name` property added to ESLint
  core configs"* section describes the property being restored to the configs
  exported from `@eslint/js` v10 — confirmed in the shipped artifact:
  `@eslint/js@10.0.1`'s `eslint-recommended.js` begins
  `Object.freeze({ name: "@eslint/js/recommended", rules: … })`, which 9.39.4's
  does not.

`@eslint/js@10.0.1` is dated 2026-02-06 and has not moved since — it is current,
not stale, even though `eslint` itself is eight minors ahead.

### 3.7 Summary graph

```
typescript-eslint 8.19.0 → 8.66.0        ← nothing depends on it; it gates everything
        │
        ├──► eslint 9 → 10 (+ @eslint/js 10.0.1)      [needs t-eslint ≥ 8.56.0]
        │        └──► eslint-plugin-react-hooks 7.1.1  [peer-forced: ^10 first in 7.1.0]
        │        └──► eslint-plugin-react-refresh 0.5.3 [not forced; 0.4.16 peer is >=8.40]
        │
        └──► typescript 5.7.2 → 6.0.3                  [needs t-eslint ≥ 8.58.0]
                 ✗ typescript 7  — no t-eslint accepts it; API removed from the package

vite 6.4.3 → 8.2.1  ◄──lockstep──►  @vitejs/plugin-react 4.3.4 → 6.0.5   [peer: vite ^8.0.0]
        (independent of the ESLint/TypeScript chain)

vitest 3.2.7 → 4.1.10        [peer: vite ^6||^7||^8 — no Vite major needed]
jsdom 26.1.0 → 30.0.1        [no coupling; raises the Node floor]
```

---

## 4. The locked-decision boundary

**React 18 and Mantine v7 do not move.** Checked against every package in the
sweep, using published peer metadata rather than reputation:

| Package (proposed version) | Declares a `react` / `@mantine/*` peer? |
|---|---|
| `typescript`, `typescript-eslint`, `eslint`, `@eslint/js` | none |
| `vite@8.2.1` | none (peers are all optional build tooling: `esbuild`, `sass`, `terser`, `@types/node`, …) |
| `@vitejs/plugin-react@6.0.5` | **none** — peers are `vite ^8.0.0` plus optional `@rolldown/plugin-babel`, `babel-plugin-react-compiler` |
| `vitest@4.1.10`, `jsdom@30.0.1` | none |
| `eslint-plugin-react-hooks@7.1.1` | **none** — `eslint` only |
| `eslint-plugin-react-refresh@0.5.3` | `eslint ^9 \|\| ^10` only |

**Nothing in the sweep pulls, requires, or peer-pressures a React or Mantine
major.** The React Compiler rules in `eslint-plugin-react-hooks@7.1.1` are static
analysis with no React runtime dependency — they lint React 18 source. They apply
*pressure of a different kind* (their model is the compiler's, and satisfying
`immutability` / `purity` / `static-components` on a React 18 codebase may mean
real refactors), but that is a code-volume question, not a locked-decision breach.

### One adjacent package that **is** a locked-decision blocker

`docs/ROADMAP.md` § Track A says `react-router` 7 → 8 *"belongs with the tooling
majors above"* and suggests doing them together. **It cannot ride along.**

**[peer]** `react-router@8.3.0` declares `react: ">=19.2.7"` and
`react-dom: ">=19.2.7"` (and `engines.node: ">=22.22.0"`). This repo pins
`react@18.3.1` / `react-dom@18.3.1`, locked by decision §2. `react-router` 8 is a
**React 19 requirement**, full stop — it is a separate decision about a locked
item, not a quiet inclusion in a tooling sweep.

(It is also not in #153, and `react-router-dom@7.18.2` remains the current 7 line
— `latest` for that package name. The v8 fold of `react-router-dom` back into
`react-router` moves all 12 import sites in `frontend/src/`, as the roadmap says;
that cost is real but secondary to the React peer.)

**Recommendation:** move the `react-router` 7 → 8 item out of the "do these
together" grouping in `docs/ROADMAP.md` and record the React-19 peer as its
blocking constraint. Not done here — this session did not edit `docs/ROADMAP.md`.

---

## 5. `@types/node`, specifically

**The sweep does not need it. Keep it on the 24 line.**

- `@types/node`'s major tracks Node's. This repo builds and runs on **Node 24** —
  `docker/Dockerfile:27` and `ci.yml`'s `node-version: "24"`. `tsconfig.node.json`
  sets `"types": ["node"]`, so types ahead of the pinned runtime describe APIs the
  build does not have and feed them into the type-aware ESLint gate. That is the
  reasoning already recorded in `docs/ARCHIVE.md` §14 (2026-08-03) when #145's
  `@types/node` 26 was narrowed to 24.13.3, and nothing in this sweep changes it.
- **No package in the sweep requires it.** The only `@types/node` constraints in
  play are optional peers: `vite@8.2.1` wants `^20.19.0 || >=22.12.0` and
  `vitest@4.1.10` wants `^20.0.0 || ^22.0.0 || >=24.0.0`. The pinned **24.13.3
  satisfies both.** There is no step below that fails on it.
- **Why #153 proposes 26.1.2 anyway.** `.github/dependabot.yml` carries an
  `@types/node` major-ignore, added on `dev` by #147 on 2026-08-03 — and #153 was
  cut from `004d2b5`, which *is* #147. The rule was in the tree the PR branched
  from and had no effect, because **Dependabot reads its configuration, `ignore`
  list included, from the repository's default branch (`main`)**, and #147 has not
  been promoted. `git show origin/main:.github/dependabot.yml` has no `@types/node`
  stanza. This is diagnosed in full in `docs/ARCHIVE.md` §14 (2026-08-09), and the
  maintainer **declined** promoting the config file to `main` on its own to close
  the lag. So the offer will keep arriving until the next release, and it is inert
  each time.
- 24.13.3 (2026-07-08) is still the head of the 24 line; there is nothing newer to
  take within it.

**Action: none.** If a step below ever needs a newer `@types/node`, it will be
because the Node major moved, and that is the separate roadmap item.

---

## 6. Proposed PR sequence

Seven steps. Each moves one thing whose failure has one plausible cause. Steps 1–3
are the ESLint/TypeScript chain and **must** run in order — that is a hard
constraint from the peer ranges in §3.2, not a preference. Steps 4–7 carry no
dependency on that chain or on each other, so their order is a **judgement about
verification cost**, not a requirement: they could be interleaved or parallelised
across branches. The order given (Vitest → jsdom → Vite) spends the cheap, total
oracle before the expensive, partial one; the reasoning is under Step 7's *"Why 6
and 7 swapped"*.

Every step's exit criteria are the same four commands plus CI, so they are stated
once: `npm ci` · `npm run lint` · `npm run format:check` · `npm test` ·
`npm run build`, then the three required checks green on the PR into `dev`
(`Backend — lint + tests`, `Frontend — lint + build`, `Image — build + dogfood
self-scan`, plus the three CodeQL contexts). Anything step-specific is called out.

---

### Step 0 — Lockfile-only advisory refresh *(optional, not part of #86)*

| | |
|---|---|
| **Moves** | `js-yaml` 4.3.0 → 4.3.1, `nanoid` 3.3.16 → 3.3.18 (transitive; both inside existing ranges). Optionally `postcss` 8.5.25 → 8.5.26. |
| **Config changes** | none |
| **Expected breakage** | none |
| **Verifies it** | `npm audit` reports 0 vulnerabilities |
| **Judgement?** | mechanical |
| **Effort / risk** | 15 min / very low |

Listed first because it clears the baseline's two HIGHs *now*, without waiting for
the sweep, and because leaving them in place makes every later step's `npm audit`
noisy. It is genuinely independent — skip it if you would rather not touch the
lockfile outside the sweep.

---

### Step 1 — `typescript-eslint` 8.19.0 → 8.66.0

| | |
|---|---|
| **Moves** | `typescript-eslint` only |
| **Config changes** | **none authored**, but the resolved config is not fully unchanged either — see the corrected **Expected breakage** row. `tseslint.config()`, `tseslint.configs.recommendedTypeChecked`, and `parserOptions.projectService` are unedited across the span; what moved is the composite `recommendedTypeChecked` *resolves to*, not anything in this repo's own config file. |
| **Expected breakage** | **[UPDATED post-landing, 2026-08-09 — this step has run; see `docs/ARCHIVE.md` §14, "#86 sweep step 1 landed."]** Two things happened, not one. (1) `no-with` moved from `error` to `off` in the fully-resolved config — `recommendedTypeChecked`'s undiffed `eslint-recommended-raw.js` layer gained `no-with: 'off'` (22 → 23 entries); accepted after independent verification that `with` cannot compile here (`tsc -b` → `TS1101`/`TS2410`) under this repo's strict tsconfigs. (2) New reports from the 50 already-selected rules: `@typescript-eslint/no-unnecessary-type-assertion` fired twice on unedited code (`NewScanPage.tsx:139-140`), fixed by hand at those two sites, no bulk autofix. Both are corrections of the original prediction here, which said the rule set was identical and only detection would improve — see §0.3. |
| **Verifies it** | `npm run lint` is the whole test. If it is clean, this step is done. |
| **Judgement?** | Mechanical to apply; **judgement** on each new report — fix the code or add a scoped disable with a comment. Do not blanket-disable a rule to get green. |
| **Effort / risk** | **S–M** — 1–3 h, dominated by however many reports appear. **Risk: low–medium.** Lint-only; cannot affect the shipped bundle. |

**Why first:** it is the only move that unblocks anything (§3.2). It also isolates
47 minors of rule churn from every other variable, which is the single most useful
thing this sequence does — under #153's grouping, a `no-floating-promises` report
and a Rolldown bundling difference arrive in the same red check.

---

### Step 2 — ESLint 10 family, rule set held constant

| | |
|---|---|
| **Moves** | `eslint` 9.39.4 → **10.8.1**, `@eslint/js` 9.39.4 → **10.0.1**, `eslint-plugin-react-hooks` 5.1.0 → **7.1.1** *(peer-forced)*, `eslint-plugin-react-refresh` 0.4.16 → **0.5.3** |
| **Config changes** | **One required edit** in `frontend/eslint.config.js` — see §7.1. Replace the `...reactHooks.configs.recommended.rules` spread (line 31) with the two rules written out, so the plugin's 5→7 major does **not** silently enable 14 React Compiler rules in the same PR as the ESLint major. |
| **Expected breakage** | (a) three rules newly in `eslint:recommended` — `no-unassigned-vars`, `no-useless-assignment`, `preserve-caught-error` (verified in the shipped `@eslint/js@10.0.1` config, and named in the migration guide); (b) **JSX reference tracking** — ESLint 10 now resolves `<Card />` to the imported `Card`, which changes `no-unused-vars` / `no-undef` results across 51 `.tsx` files; (c) `no-shadow-restricted-names` now reports `globalThis` by default; (d) **`eslint-plugin-react-refresh` 0.4.16 → 0.5.3 is bundled into this step and is not a routine bump** — 0.5.0 is **ESM-only and requires flat config** (this repo has been flat-config since Phase 0, so that requirement is a no-op here — confirmed, not assumed), renames the `customHOCs` option to `extraHOCs` (this repo's one usage, `frontend/eslint.config.js`'s `react-refresh/only-export-components` rule, sets no HOC option at all, so the rename is also a no-op here), and tightens HOC validation generally. Re-verify the option-name point against the installed 0.5.3 package when this step actually runs, per the method note in §0.3 — it was not re-checked against a live install for this scoping pass. |
| **Doesn't apply here** | The eslintrc removal (this repo has been flat-config since Phase 0), `eslint-env` comments (none), `--flag v10_config_lookup_from_file` (not used), POSIX character classes (no bracket expressions in any glob), the `stylish` formatter's colour handling (CI output only), and every plugin/integration-developer change (no custom rules). |
| **Verifies it** | `npm run lint`; plus confirm `npm ls @eslint/eslintrc` reports nothing — that is the js-yaml path gone. |
| **Judgement?** | **Judgement**, mostly on JSX reference tracking's fallout and on whether each new-rule report is a real defect. |
| **Effort / risk** | **M** — 2–5 h. **Risk: medium.** Lint-only, but the widest blast radius of any step. |

---

### Step 3 — Adopt the React Compiler rules *(separate decision; may be declined)*

| | |
|---|---|
| **Moves** | no dependency versions — `eslint.config.js` only |
| **Config change** | restore `...reactHooks.configs.recommended.rules` (undo Step 2's holding edit) |
| **Expected breakage** | 14 new rules across 51 `.tsx` files: 12 at `error` (`config`, `error-boundaries`, `gating`, `globals`, `immutability`, `preserve-manual-memoization`, `purity`, `refs`, `set-state-in-effect`, `set-state-in-render`, `static-components`, `use-memo`) and 2 at `warn`. On a codebase with 23 files using `useEffect` and 15 using `useMemo`/`useCallback`, `set-state-in-effect`, `preserve-manual-memoization`, and `purity` are the ones most likely to fire in volume. |
| **Verifies it** | `npm run lint`, and a judgement about whether the rules are earning their keep |
| **Judgement?** | **Entirely judgement.** This is adopting a new static-analysis regime, not a version bump. |
| **Effort / risk** | **Unbounded until measured** — could be 0 reports or could be a multi-day refactor. **Risk: high**, in the sense that it is the one step that can demand real code change rather than config change. |

**Why it is its own step:** it is the only way its failure has one cause. Folded
into Step 2, a `purity` error and a JSX-reference-tracking error land in the same
red check, which is #153's problem in miniature. It is also the one step where
"decline it" is a legitimate outcome: keeping the two classic rules and skipping
the compiler set is a supported configuration and costs nothing.

> **This step's held-back rule is being closed out in two parts.** Step 3 landed
> the compiler rule set with one exception: `react-hooks/set-state-in-effect` is
> still `'off'` by an override in `frontend/eslint.config.js`, because it reports
> 18 findings of which only 6 are worth changing. Retiring that override is
> tracked by **[#176](https://github.com/tyler-rich/Scrye/issues/176)** and is
> being done across two sessions, not one:
>
> - **Part 1 (landed 2026-08-11).** Findings **1, 2, 3 and 5** — `LoginPage`'s
>   `oidc_error` banner, `OidcLinkCard`'s `oidc_link*` banners, `NewScanPage`'s
>   scanner clamp, and `ScanDetailPage`'s findings loading state — refactored,
>   behaviour preserved, each with a test proven to fail against the pre-refactor
>   version of its own file. **The override was deliberately left in place.**
> - **Part 2 (open).** Findings **4** and **6** — `ScanDetailPage`'s per-`:scanId`
>   reset and `ScansPage`'s compare-selection reconciliation — plus the removal of
>   the override. Both effects are deliberate, both closed real bugs, and both
>   have regression tests; #176 says so, and finding 4's idiomatic replacement is
>   a `key` prop in a different file. That is why they were not folded into part 1.
>
> Part 2 also has to settle something #176 does not currently answer: the 12
> fetch-on-mount findings are out of scope *and* reported at `error`, so removing
> the override cannot leave `npm run lint` clean on its own. `docs/ARCHIVE.md` §14
> (2026-08-11, "#176 part 1") carries the full account, including the probe
> evidence that finding 5's line still reports after its genuine synchronous
> setState was removed.

---

### Step 4 — TypeScript 5.7.2 → **6.0.3** *(not 7)*

| | |
|---|---|
| **Moves** | `typescript` only |
| **Prerequisite** | Step 1 (`typescript-eslint >= 8.58.0`) |
| **Config changes** | **One recommended, none strictly required** — see §7.2. TS 6.0 changes the default of `types` from "everything in `node_modules/@types`" to `[]`; add an explicit `"types": []` to `tsconfig.app.json` to pin that rather than inherit it. `tsconfig.node.json` already sets `"types": ["node"]`. |
| **Expected breakage** | Now characterised from the actual release notes (§7.2). The default changes that bite most projects — `types: []` and `rootDir: "."` — are **no-ops here** (verified). What remains is the **`this`-less function context-sensitivity** inference change, which can produce genuinely new errors in generic callback positions, plus whatever the type-aware lint rules make of changed inference. |
| **Verifies it** | `npm run build` (the `tsc -b` half) **and** `npm run lint` — both consume the compiler. Watch for `TS6xxx` deprecation diagnostics as well as errors. |
| **Judgement?** | **Judgement** on each type error. |
| **Effort / risk** | **M** — 2–5 h. **Risk: medium**, and now the *best*-characterised of the judgement-heavy steps rather than the worst. |

**State plainly in the PR that this stops at 6.0.3, why, and when that was last
checked** (§3.1), so the next Dependabot offer of `typescript@7.x` is neither read
as an oversight nor waved through on a stale reading. A note in
`.github/dependabot.yml` is *not* recommended: per the standing rule there, an
ignore says "a bot may not make this decision", and TypeScript 7 is wanted — just
not until `typescript-eslint` ships support.

**Edits this step makes** — this is the checklist, not a pointer to one. §7.2 is
the reasoning; the actions are here so they land with the version bump rather than
being read as background:

- [ ] `frontend/package.json` — `"typescript": "5.7.2"` → `"6.0.3"`.
- [ ] **`frontend/tsconfig.app.json` — add `"types": []`.** TypeScript 6.0 changes
      this option's default from "enumerate everything in `node_modules/@types`" to
      `[]`, and upstream names it the change that *"will affect many projects"*,
      recommending an explicit array *"to improve build performance and
      predictability"*. It is a **no-op for this repo** — verified, not assumed
      (§7.2) — which is exactly why it must be written down: an invisible no-op is
      the kind of edit that gets skipped now and rediscovered as a mystery later,
      and the explicit array also pins the behaviour against TypeScript 7, where
      the old enumerate-everything default is gone for good.

      ```jsonc
      // frontend/tsconfig.app.json — alongside the existing strictness flags
        "noUncheckedIndexedAccess": true,
        "types": []                        // TS 6.0's new default, made explicit
      ```
- [ ] `frontend/tsconfig.node.json` — **no change.** It already sets
      `"types": ["node"]` explicitly.
- [ ] Fix whatever `tsc -b` reports from the `this`-less-function inference change
      (§7.2) — the one TS 6.0 change no config audit can pre-empt.
- [ ] State in the PR description that this stops at **6.0.3**, why, and that the
      ceiling was last checked on **2026-08-09** (§3.1).

**`ignoreDeprecations: "6.0"` exists as an escape hatch** and should not be used
here: it silences 6.0's deprecation diagnostics, and those diagnostics are the
free preview of what TypeScript 7 removes outright. Taking them now is the point
of the step.

---

### Step 5 — Vitest 3.2.7 → 4.1.10

| | |
|---|---|
| **Moves** | `vitest` only (stays on the pinned `vite@6.4.3`) |
| **Config changes** | **None required.** All three things this repo relies on were confirmed present in the shipped `vitest@4.1.10` tarball: `dist/config.d.ts` still contains `declare module "vite"` (so `/// <reference types="vitest/config" />` + `defineConfig` from `'vite'` in `vite.config.ts:1,10` still types the `test` key); project configs still accept `extends?: string \| true` (so `vite.config.ts:32,40` are fine); `projects` is already the current spelling, so the `workspace` → `projects` rename is a no-op here. |
| **Expected breakage** | Low. The v4 changes that bite are coverage (this repo configures none), `poolOptions` (none), reporters (defaults), and the narrowed default `exclude` — v4 stops auto-excluding `dist`, but both project `include` globs are `src/**`, so nothing new is collected. Residual risk is the `vite-node` → Vite ModuleRunner swap changing module resolution under the 17 jsdom tests. |
| **Verifies it** | `npm test` — expect **21 files / 79 tests** unchanged |
| **Judgement?** | mechanical |
| **Effort / risk** | **S** — under 1 h if the suite passes. **Risk: low.** |

**Ordered first among 5–7 deliberately:** Vitest 4 is supported on Vite 6 by both
its peer range and its migration guide (§3.4), so it can go first, and it is the
test *runner* — settling it before the DOM implementation underneath it (Step 6)
means a jsdom failure is attributable to jsdom. Do not combine it with either
neighbour in one PR.

---

### Step 6 — jsdom 26.1.0 → 30.0.1

> **Re-ordered.** This was Step 7 in the first draft, behind the Vite major. It
> moved ahead of it once the 27/28/29 changelogs were read — rationale under
> "Why 6 and 7 swapped" below.

| | |
|---|---|
| **Moves** | `jsdom` only |
| **Config changes** | **None in `vite.config.ts`** — jsdom is reached only through Vitest's `environment: 'jsdom'`; nothing in `frontend/src/` imports it. **Two docs edits are required** (§7.4) for the raised Node floor. |
| **What 27/28/29 actually changed** | From the upstream `Changelog.md` (present through tag `v29.0.0`, removed at `v30.0.0`). **27.0.0** is the substantial one: the CSS selector engine was swapped `nwsapi` → `@asamuzakjp/dom-selector` ("closing over 20 selector-related bugs"), `element.click()` now fires a `PointerEvent` instead of a `MouseEvent`, certain events became passive by default, the user-agent stylesheet was re-derived from the HTML Standard, CSS `display` resolution was fixed, and many `Window`-object conformance fixes landed (named properties, data → accessor properties). **28.0.0** overhauled resource loading and added MIME sniffing to frames. **29.0.0** replaced the whole CSSOM implementation (`@acemir/cssom` + `cssstyle` → internal `css-tree`-based), added real media-query parsing, and raised the Node 22 floor to 22.13.0. **30.0.0** is unknown (§9). |
| **Which of those actually reach this suite** | Mapped onto the real test code rather than assumed — see the channel table below. Two channels are live, four are provably inert, and the loudest-sounding change (the CSSOM overhaul) is among the inert ones. |
| **Prerequisite check** | ✅ **Resolved — no action needed.** **[peer]** `jsdom@30.0.1` `engines.node: "^22.22.2 \|\| ^24.15.0 \|\| >=26.0.0"`. CI resolves `node-version: "24"` to 24.18.0 (seen in #153's job log). The pinned `node:24-bookworm-slim@sha256:235600a8…` in `docker/Dockerfile:27` ships **Node 24.18.1** (§9, resolved), which satisfies `^24.15.0`. There is no `.npmrc`, so `engine-strict` is off and a mismatch would have been a non-fatal `EBADENGINE` warning rather than a failed build — which is why it was worth resolving by hand rather than trusting a green CI run. |
| **Verifies it** | `npm test` — expect **21 files / 79 tests** |
| **Judgement?** | mechanical, unless a test fails |
| **Effort / risk** | **S–L** — ~1 h if the suite is green first run, up to half a day if the selector-engine swap shifts query results. **Risk: medium** — held, not raised; reasoning below. |

**Channel analysis — every 27/28/29 change against what the suite actually does.**
Counts are from `frontend/src/**/*.test.tsx` (12 files, 17 of the 79 tests).

| Change | Reaches this suite? | Evidence |
|---|---|---|
| Selector engine `nwsapi` → `@asamuzakjp/dom-selector` (27.0.0) | **LIVE, but narrower than the call count suggests** | **116 Testing Library query call sites** (34 `getByRole`, 28 `getByLabelText`, 21 `getByText`, plus `find*`/`query*` variants). All bottom out in `querySelectorAll` — but read the installed `@testing-library/dom@10.4.1` and the engine's *discriminating power* varies by query type: `getByText`'s candidate selector is `'*'` (`queries/text.js:11`) and `getByLabelText`'s are `'label'`, `'label,input'`, `'*'` — an engine cannot change "every element", so filtering there is pure JS. The real exposure is `getByRole`: `querySelectorAll(makeRoleSelector(role))` (a union of bare tag names plus one `*[role~="X"]`) followed by `node.matches(selector)` against aria-query's element-role selectors (`input[type="checkbox"]`, `a[href]`, …). Those are simple tag/attribute selectors — **not** the complex-selector territory (`:has()`, `:is()`, `:scope`, nesting) where jsdom's "over 20 selector-related bugs" lived. |
| UA stylesheet re-derived + CSS `display` resolution fixed (27.0.0) | **LIVE — narrow, one path** | Reaches the tests only through Testing Library's accessibility filter: in the installed `@testing-library/dom@10.4.1`, `isSubtreeInaccessible()` reads `getComputedStyle(element).display` and `isInaccessible()` reads `.visibility`; `config.js` sets `defaultHidden: false` and the repo never calls `configure()`, so **all 34 `getByRole` sites run that filter**. |
| CSSOM implementation replaced (29.0.0) | **Inert** | `vite.config.ts`'s `test` block sets **no `css` key**, so Vitest's default `css: false` applies and Mantine's stylesheets are never injected into jsdom. There is no author CSS in the CSSOM to re-parse — only UA defaults, which is the row above. |
| `element.click()` → `PointerEvent` (27.0.0) | **Inert** | **No `.click()` anywhere in `frontend/src/`.** All interaction is `userEvent.click` (8) or `fireEvent.click` (6), both of which construct and dispatch their own events rather than calling `HTMLElement.prototype.click()`. |
| Certain events passive by default (27.0.0) | **Inert** | **No `preventDefault` anywhere in `src/`**, and no `onWheel`/`onTouch`/`onScroll` handlers or matching `addEventListener` calls. |
| Resource loading overhaul + MIME sniffing (28.0.0), bad-port blocking (29.0.0) | **Inert** | No test loads a subresource; `fetch` is stubbed per test. |
| `Window` conformance: data → accessor properties (27.0.0) | **Benign** | `src/test/setup.ts` assigns `window.matchMedia` / `window.ResizeObserver`, neither of which exists in jsdom 26.1.0, 29.1.1, or 30.0.1 (zero files in the shipped `lib/`), so the assignments create own properties. This also retires the "polyfill silently steps aside" risk the first draft flagged. |

**Why the estimate widened but the risk did not rise.** Reading the changelogs
pushed in both directions and the two roughly cancel:

- *Upward:* the selector-engine swap is a genuinely wide, live surface — 116 query
  sites — and its failure mode is *"unable to find an element with the role…"*,
  which is less diagnosable than a lint error carrying a rule name and a line
  number. That is why the effort band now runs to **L** rather than stopping at M.
- *Downward:* four of the seven channels are provably inert, including the two
  that sound worst in the changelog (the CSSOM rewrite and the `click()` change).
  The CSS surface in particular is nearly absent because Vitest does not process
  CSS by default.
- *Unchanged, and decisive for the risk rating:* **detection here is near-total and
  immediate** — `npm test` runs **79 tests / 151 `expect` calls** in ~15 s. The
  qualifier matters and is argued rather than asserted in §8 under *"Does a green
  run actually prove anything?"*: a green suite is a strong oracle for this step,
  but not a tautologically complete one, and the residual is what the checklist
  item below exists to close. Contrast Step 7, where a CSS-minifier regression
  fails nothing and reaches a user.

So: **effort S–L, risk medium.** Not "low", because of the selector surface and
jsdom 30.0.0's unreadable notes; not "high", because the drift audit in §8 shows
the suite pins the elements its queries resolve to, and the one residual is
closable in ~20 lines of throwaway instrumentation.

**Checklist item — close the silent-drift residual (≈20 min, do it once).**
§8's audit shows ~17 of the 116 query sites are *interaction targets* rather than
assertion subjects, so in principle a query could resolve to a different element
post-swap and still leave the suite green. That residual is measurable rather than
arguable, so measure it:

- [ ] **Before** touching the version, add a temporary `setupFiles` shim that wraps
      `screen`'s query methods and appends `element.outerHTML.slice(0, 120)` to a
      log keyed by test name + call index. Run `npm test`. Keep the log.
- [ ] Bump `jsdom`, run `npm test` again with the same shim, and **`diff` the two
      logs**. An empty diff proves no query changed which element it resolved to —
      which is the thing a green suite alone does not prove.
- [ ] Delete the shim before opening the PR. It is a measurement, not a fixture.

If the diff is non-empty, every differing line is a query worth reading before
deciding the step is done — that is the whole point, and it costs one extra test
run.

---

### Step 7 — Vite 6.4.3 → 8.2.1 **+** `@vitejs/plugin-react` 4.3.4 → 6.0.5

> **Re-ordered.** This was Step 6 in the first draft. It moved behind jsdom —
> rationale immediately below.

| | |
|---|---|
| **Moves** | both, in lockstep — peer-forced, no version of the plugin spans the boundary (§3.3) |
| **Config changes** | **None required in `vite.config.ts`.** The repo uses `plugins: [react()]` with no `babel` option (so plugin-react 6's Babel removal is a no-op), no `build.rollupOptions`, no `esbuild` options, no `optimizeDeps`, and no `manualChunks`. The `server.proxy`, `build.outDir`, and `build.sourcemap` keys are untouched by either major. |
| **Expected breakage** | **This is the only step that can change what ships.** Vite 8 replaces Rollup+esbuild with Rolldown+Oxc: JS transform, minification, and dependency optimisation all change engine, and **CSS minification moves to Lightning CSS** — which matters here because Mantine emits 201 kB of CSS. Also: the default browser target rises to Chrome/Edge 111, Firefox 114, Safari 16.4; CommonJS `default`-import interop changes; Vite 7's `splitVendorChunkPlugin` and Sass legacy API removals (neither used here). |
| **Verifies it** | `npm run build`, then **compare the emitted bundle against the baseline in §1** (645.18 kB JS / 201.38 kB CSS), then **actually run the app** — `docker compose up` and click through the SPA in both light and dark mode. A CSS-minifier change does not fail a build; it fails a render. |
| **Judgement?** | Mechanical to apply; **judgement** on whether any output difference is acceptable. |
| **Effort / risk** | **L** — half a day including a real UI pass. **Risk: medium–high**, and uniquely *runtime* rather than lint-time. |

**Why 6 and 7 swapped.** The first draft ran Vite 8 before jsdom. Reading the
jsdom changelogs did not change either step's content, but it made the ordering
argument concrete enough to act on:

1. **Group by oracle, and spend the cheap oracle first.** Steps 5 and 6 are both
   verified by `npm test` alone — automated, ~15 s, total. Step 7 is verified by a
   build plus a **human** pass over the running SPA, because its worst failure
   mode is invisible to CI. Settling both test-harness steps first means the
   expensive human verification happens once, at the end, against a harness that
   is no longer moving.
2. **Vite 8 changes the transform pipeline Vitest runs on.** With jsdom already
   moved, a test failure during Step 7 points at Rolldown/Oxc. In the original
   order, the last test-harness change (jsdom) landed on a just-swapped bundler,
   which is the one arrangement where a test failure has two plausible causes.
3. **Front-load the least predictable of the mechanical steps.** jsdom's band runs
   to half a day and jsdom 30.0.0's notes are unreadable; learning that cost early
   is worth more than learning it after the longest step.

**The original order was not wrong** — every step is verified green before the
next begins, so attribution is sound either way, and no dependency constraint
forces this. It is a preference for cheap-and-total verification before expensive-
and-partial. **Membership is unchanged**; only these two swapped.

---

### Step 8 — the routine minors

`globals` 17.8.0 → 17.9.0, `@testing-library/user-event` 14.6.1 → 14.6.3, and
`postcss` 8.5.25 → 8.5.26 if not already taken in Step 0. Mechanical, no config
change, no coupling. Fold into whichever step is convenient, or take alone.

> One inherited caution: `globals` feeds `eslint.config.js:20`'s `globals.browser`.
> A `globals` bump can silently *shrink* a set, leaving lint green while losing
> coverage — inspect the set rather than trusting a green run, as was done for the
> 15 → 17 bump (`docs/ARCHIVE.md` §14, 2026-08-03). 17.8 → 17.9 is a minor, so this
> is a spot-check, not an investigation.

---

## 7. The config-migration surface — actual required edits

Everything below is a concrete edit to a named file. Where an edit is *not*
required, that is stated too, because "no change needed" is the more useful finding
for most of these.

### 7.1 `frontend/eslint.config.js` — one required edit (Step 2)

The `extends:` array, `tseslint.config()`, `projectService`, `tsconfigRootDir`,
the `{ ignores: ['dist'] }` block, and the test-file override all survive ESLint 10
unchanged. This repo has never had an `.eslintrc`, so the eslintrc removal — the
headline v10 breaking change — is a no-op for it.

The one edit is at **line 31**, and it exists to stop the `eslint-plugin-react-hooks`
5 → 7 major from smuggling a rule-set expansion into the ESLint-10 PR:

```js
    rules: {
      ...reactHooks.configs.recommended.rules,                                    // remove
      'react-hooks/rules-of-hooks': 'error',                                      // add
      'react-hooks/exhaustive-deps': 'warn',                                      // add
      // ^ eslint-plugin-react-hooks 7's `configs.recommended` adds the React
      //   Compiler rule set on top of these two. Adopting it is tracked
      //   separately — see docs/upgrades/frontend-toolchain-86.md, Step 3.
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
    },
```

The two values are exactly what 5.1.0's `configs.recommended.rules` contains
(verified against the shipped bundle), so this edit is behaviour-preserving on its
own.

**Not required, though the v10 docs mention them:** `globalIgnores()` from
`eslint/config` as a replacement for `{ ignores: [...] }` (the object form still
works); `@eslint/compat` (no removed `SourceCode` methods are used); the
`@eslint/v9-to-v10` codemods (they target eslintrc configs, custom rules,
`RuleTester`, and `Linter`/`ESLint` API usage — this repo has none of those).

### 7.2 `frontend/tsconfig.app.json` / `tsconfig.node.json` — one recommended edit (Step 4)

Established from the **TypeScript 6.0 release notes**, checked option by option
against both tsconfigs. TS 6.0 is a transition release: it is API-compatible with
5.9 and mostly *deprecates* rather than removes, with removal deferred to 7.0.

**Recommended edit — pin `types` rather than inherit the new default.** This is
carried as a checklist item in **§6, Step 4 ("Edits this step makes")**; the
reasoning is here, the action is there.

```jsonc
// frontend/tsconfig.app.json
  "noUncheckedIndexedAccess": true,
  "types": []                        // add: TS 6.0's new default, made explicit
```

TS 6.0 changes the default `types` from "enumerate everything in
`node_modules/@types`" to `[]`, and upstream names this the change that *"will
affect many projects"*, recommending an explicit array *"to improve build
performance and predictability"*. **It is a no-op for this repo, verified rather
than assumed:** `frontend/src/` contains **zero** references to `process`,
`Buffer`, `__dirname`, or `__filename`, no `NodeJS.` namespace use, every test
file imports `describe`/`it`/`expect` from `'vitest'` rather than relying on
globals, and timers go through `window.setTimeout` (DOM lib, not `@types/node`).
`@types/react` is unaffected — it is resolved through the `'react'` module
specifier, not through global type-root inclusion. `tsconfig.node.json` already
sets `"types": ["node"]` explicitly and needs nothing.

**Defaults that changed but this repo already sets explicitly — no edit:**
`strict` (already `true`), `module` (already `ESNext`), `target` (already
`ES2022`; the new floating default is `es2025`), `noUncheckedSideEffectImports`
(already `true`).

**`rootDir` now defaults to `.` instead of the inferred common prefix.** No edit:
both projects set `noEmit: true`, so there is no output layout to shift, and with
`include: ["src"]` every input is already under `.`.

**Deprecations that do not apply here** — none of these appears in either
tsconfig: `target: es5`, `--downlevelIteration`, `--moduleResolution node`
(this repo uses `bundler`), `--moduleResolution classic`, `--baseUrl`,
`--esModuleInterop false` / `--allowSyntheticDefaultImports false` (unset, so
`true`), `--alwaysStrict false`, `outFile`, `amd`/`umd`/`systemjs` module values,
legacy namespace `module` syntax, `asserts` on imports, `no-default-lib`
directives. `libReplacement` now defaults to `false` — not set here, and inert
without other configuration.

**`tsc` CLI:** *"Specifying command-line files when `tsconfig.json` exists is now
an error"* (`TS5112`). `npm run build` runs bare `tsc -b`, passing no file
arguments, so this does not fire.

**The one change that can produce real new errors:** *"Less context-sensitivity on
`this`-less functions"* — TypeScript 6.0 narrows when it will infer a callback
parameter's type from an expected type. This is a type-inference change, not a
config flag, so it cannot be pre-audited from the config files; it surfaces as
errors from `tsc -b` at generic callback sites. Two smaller ones worth knowing:
the `dom` lib now contains `dom.iterable` and `dom.asynciterable` (making
`tsconfig.app.json`'s explicit `"DOM.Iterable"` redundant but harmless), and
`--stableTypeOrdering` is a new opt-in flag for 6→7 migration that this repo does
not need while `noEmit` is set.

**Do not set `"ignoreDeprecations": "6.0"`.** It silences exactly the diagnostics
that preview what TypeScript 7.0 removes.

### 7.3 `frontend/vite.config.ts` — no required edit (Steps 5 and 7)

- **Vitest 4:** `/// <reference types="vitest/config" />` (line 1), `defineConfig`
  imported from `'vite'` (line 2), and `test.projects[].extends: true` (lines 32,
  40) are all still supported — confirmed in the 4.1.10 tarball (§6, Step 5).
- **Vite 8:** the config uses none of the deprecated or removed surface.
  `build.rollupOptions` is absent, so the `rollupOptions` → `rolldownOptions`
  rename does not apply; there are no `esbuild` / `optimizeDeps` / `manualChunks`
  keys. `plugins: [react()]` takes no options, so plugin-react 6's removal of the
  `babel` option is a no-op.
- **If anything is ever added here**, note for the future: `build.rollupOptions`
  and `worker.rollupOptions` are deprecated in favour of `*.rolldownOptions`, the
  object form of `output.manualChunks` is removed outright, and `build.esbuild`
  options are auto-translated to `oxc` but deprecated.
- `frontend/postcss.config.cjs` (Mantine's `postcss-preset-mantine` +
  `postcss-simple-vars`) is untouched by Vite 8 — PostCSS still runs; only CSS
  *minification* moves to Lightning CSS.

### 7.4 `README.md` and `CONTRIBUTING.md` — required edits (Step 6)

Both currently state **"Node 22+"** for native development —
`README.md:229` and `CONTRIBUTING.md:19`. `jsdom@30.0.1` requires
`^22.22.2 || ^24.15.0 || >=26.0.0`, so a contributor on Node 22.13 (which satisfies
"22+", and satisfies ESLint 10) is *below* jsdom 30's floor and `npm test` will run
on an unsupported runtime. Raise both statements to **Node 22.22.2+ / 24.15+**, or
simply to "Node 24" to match the image and CI.

### 7.5 `.github/workflows/ci.yml` and `docker/Dockerfile` — no edit needed

`node-version: "24"` resolves to the current 24.x and satisfies every `engines`
constraint in the sweep. **The Dockerfile's digest pin was checked and passes:**
`node:24-bookworm-slim@sha256:235600a8…` ships **Node 24.18.1**, above jsdom 30's
`^24.15.0` floor (§9, resolved). No digest refresh is needed for this sweep.

---

## 8. Effort and risk at a glance, and what to do with #153

### Per-step summary

| # | Step | Effort | Risk | Nature | Blocks |
|---|---|---|---|---|---|
| 0 | lockfile advisory refresh | 15 min | very low | mechanical | — |
| 1 | `typescript-eslint` → 8.66.0 | S–M | low–med | mechanical + per-report judgement | 2, 4 |
| 2 | ESLint 10 family | M | **medium** | judgement | 3 |
| 3 | React Compiler rules | unbounded | **high** | pure judgement; **may be declined** | — |
| 4 | TypeScript → 6.0.3 | M | medium | judgement | — |
| 5 | Vitest → 4.1.10 | S | low | mechanical | — |
| 6 | jsdom → 30.0.1 | **S–L** | medium | mechanical | — |
| 7 | Vite 8 + plugin-react 6 | L | **med–high** | mechanical + output review | — |
| 8 | routine minors | 15 min | very low | mechanical | — |

Total: roughly **2–4 focused days** if nothing surprising appears, front-loaded on
steps 2, 4, and 7. Step 3 is deliberately not in that estimate — it is a decision
with an unbounded tail, and pricing it alongside version bumps is how it would end
up taken by accident.

**Revised in the second pass** (after the jsdom 27/28/29 changelogs became
readable): jsdom's effort band widened **S–M → S–L**, its risk stayed **medium**,
and it swapped places with the Vite step. Every other row is unchanged and was
re-checked rather than left standing — the reasoning is in §6, Step 6.

**Audited in the third pass:** jsdom's rating rested on an unqualified claim that
a green test run leaves no failure mode behind. That claim was challenged, tested
against the suite, and **narrowed** — the rating survives, the wording does not.
See *"Does a green run actually prove anything?"* below; the residual it could not
argue away is now a checklist item on Step 6 rather than a footnote here.

### Relative risk — the ranking, stated plainly

Because "which step is riskiest" drives what gets scheduled when, and one plausible
reading of the sequence is wrong:

1. **Step 3 — React Compiler rules.** Highest, and the only step that can demand
   real refactors rather than config edits. Mitigated by being optional.
2. **Step 7 — Vite 8.** Highest among the steps that must happen, for one specific
   reason: it is the **only step whose worst failure passes CI**. A Lightning CSS
   minification difference in Mantine's 201 kB of CSS fails no check and reaches a
   user; everything else in the sequence announces itself in a lint run or a test
   run.
3. **Step 6 — jsdom** and **Step 2 — ESLint 10 family**, roughly level.
4. **Step 4 — TypeScript 6**, now better characterised than at first draft (§7.2).
5. **Step 1 — typescript-eslint**, then the mechanical remainder.

**Is jsdom now the highest-risk step rather than typescript-eslint?** Half of that
is right and half rests on a mistaken premise. jsdom **is** riskier than
typescript-eslint — but it already was in this document's first draft (Step 1
low–med, jsdom medium), so the changelogs *confirmed* that relative order rather
than overturning it. And **typescript-eslint was never the top of the ranking**:
Step 3 and the Vite step have outranked it since the first draft. What actually
changed is the gap: Step 1's risk fell further once the *diffed* portion of its
rule set was proven identical across the span (§0.3 — since corrected: one
undiffed composite layer did change, and was accepted after separate
verification), while jsdom's surface became concrete. The correction narrows
the claim; it does not raise Step 1's risk rating, since the one change found
was independently verified as safe rather than merely assumed unchanged.

**jsdom is not the highest-risk step either.** It sits third, and the property
that keeps it there is the strength of its oracle. That property was originally
asserted here rather than argued — *"no failure mode that survives a green run"* —
which is too strong as an unqualified claim. It is replaced by the audit below.

### Does a green run actually prove anything? (the silent-drift check)

A green suite catches a query that finds **nothing** or finds **too much**. The
harder question is whether a query could resolve to a *different* element after
the selector-engine swap while every downstream assertion still passes — silent
drift, which is not a failure and which a green run would not catch. The raw
counts look like they leave room for it: **116 query call sites, 79 tests**. They
do not, for four reasons, in descending order of how much work each does.

**1. `getBy*` semantics make most drift loud, not silent.** `getBy*` throws on
**zero** matches *and* on **more than one**. Silent one-to-one drift therefore
needs the engine to stop matching element A *and* start matching exactly one
different element B, in the same pass. Any widening that catches a second
candidate raises *"found multiple elements"* instead — a failure, not drift.

**2. 62 of the 116 sites are discriminated by name, not by selector.** All 34
`getByRole(role, {name})` and 28 `getByLabelText(text)` sites filter candidates by
**accessible name / label text, computed in JavaScript** by Testing Library and
`dom-accessibility-api` — the selector engine only assembles the candidate pool.
For a result to drift from A to B, B must carry an *identical* accessible name to
A. Two same-named elements in scope is precisely the ">1 match" condition that
throws today. And per §6's channel table, the engine's actual discriminating power
in these queries is bare tag names and simple attribute selectors, not the complex
selectors where jsdom's fixed bugs lived.

**3. 85 of the 116 sites are assertion subjects, measured not estimated.**
Categorising every call site by how its result is consumed: **74** appear directly
inside `expect(...)`; **11** more are assigned to a variable or wrapped across
lines and then asserted on (`expect(save).toBeDisabled()`,
`expect(value.previousElementSibling).toHaveTextContent('Version')`, …). Drift at
any of those 85 changes what is asserted, so it is not silent. The suite also runs
**151 `expect` calls**, not 79 — 79 is the *test* count, and quoting it as an
assertion count (as an earlier draft of this document did) understates assertion
density by roughly half.

**4. The one set-valued query is pinned by exact equality.** Set-valued queries
(`*AllBy*`) carry no uniqueness guarantee and are the natural home for silent
drift. There is **exactly one** in the entire suite —
`getAllByText(/^(UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL)$/)` in
`NewScanPage.prefill.test.tsx:54` — and it feeds a helper whose result is asserted
with `toEqual(['UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL'])`: an exact, ordered
deep-equality check. A changed set fails it. That helper is also the suite's only
raw selector use (`el.closest('[role="option"]')`), so the same assertion pins
that too. There is no `within(...)` scoping anywhere.

**What remains, honestly: ~17 interaction targets.** Sites like
`await user.click(screen.getByRole('button', { name: 'Refresh' }))`, where the
resolved element is acted on rather than asserted on. Most are followed by
assertions that would fail if the wrong element were hit — `BackupsPanel.test.tsx`
clicks delete and then asserts `toHaveBeenCalledWith(BACKUP.id)`;
`ScansPage.urlstate.test.tsx` types into a search box and then asserts the URL it
produced. But "most" is not "all", and proving the rest by inspection is more work
than measuring it. **So the residual is not argued away — it is handed to Step 6
as a checklist item** (a resolved-element snapshot, diffed across the bump), which
converts it from a judgement into a two-run measurement.

**Net effect on the rating: none.** The audit made the oracle's strength
*specific* rather than assumed, and every specific came back favourable — the one
genuinely drift-prone construct in the suite turned out to be pinned by a `toEqual`
on the whole array. jsdom stays at **medium** and stays third. Step 7 keeps the
opposite property — a Lightning CSS regression fails nothing at all, and no
checklist item can turn that into a test — which is why it still outranks a step
crossing four majors to its two.

### Recommendation on #153: **keep it open, correct the note attached to it**

- **Do not merge it.** It is not mergeable and never was: `typescript@7.0.2` +
  `typescript-eslint@8.66.0` is an unsatisfiable graph, so `npm ci` fails before
  anything is evaluated. It is not "red pending some lint fixes"; it is red at
  dependency resolution.
- **Do not cherry-pick from it.** Its two innocuous bumps (`globals` 17.9.0,
  `@testing-library/user-event` 14.6.3) cannot be split out without rewriting the
  branch, and they are Step 8 here anyway.
- **Keep it open as the reminder surface**, which is the standing decision recorded
  in `docs/ROADMAP.md` § Track A and `docs/ARCHIVE.md` §14 (2026-08-09). Closing it
  buys nothing: Dependabot regenerates an equivalent grouped PR on the next weekly
  run, at newer targets, with the same unsatisfiable TypeScript pairing, because
  the toolchain majors are deliberately not in the `ignore` list.
- **What should change is the note, not the PR.** Both `docs/ROADMAP.md` and the
  2026-08-09 §14 entry state that #153's red `Frontend — lint + build` *is* the
  predicted type-aware-ESLint churn. It is not (§0.2). Anyone triaging the queue
  who believes that will keep re-deriving the ERESOLVE. The §14 entry accompanying
  this document records the correction.
- **Close it only when Step 7 lands**, at which point the remaining offers will
  have collapsed to `typescript@7.x` (declined, §3.1) and `@types/node@26.x`
  (declined, §5), and a fresh grouped PR is more honest than a nine-month-old one.

---

## 9. Open questions — resolved and still open

Four of the six questions this document opened with have since been answered at
source. They are kept here, marked, rather than deleted, so the method is on the
record and nobody re-runs a lookup that already succeeded — or trusts a "blocked"
note that is no longer true.

### ✅ Resolved

**1. TypeScript 6.0's breaking changes — RESOLVED.** The release notes are in the
**`microsoft/TypeScript-Website` repository**, on its **`v2`** branch, at
`packages/documentation/copy/en/release-notes/TypeScript 6.0.md`, and
`raw.githubusercontent.com` serves it (785 lines). `typescriptlang.org` and
`devblogs.microsoft.com` remain egress-blocked — the fix was to stop looking for
the rendered page and fetch the source markdown the site is built from. The full
option-by-option audit against both tsconfigs is now in **§7.2**; the headline is
that the two changes which "affect many projects" (`types` defaulting to `[]`,
`rootDir` defaulting to `.`) are **no-ops for this repo**, and the one change that
can produce real errors is an inference change no config audit can pre-empt.

**2a. jsdom 27 / 28 / 29 breaking changes — RESOLVED.** The upstream
`Changelog.md` **does** exist, at tags up to and including **`v29.0.0`**; it was
removed at `v30.0.0`. The earlier "all candidate paths 404" finding was a
**tag-naming error on my part** — jsdom tags are `v30.0.0`, not `30.0.0`, so the
first round of probes asked for refs that do not exist and the 404s said nothing
about the file. Corrected path:
`raw.githubusercontent.com/jsdom/jsdom/refs/tags/v29.0.0/Changelog.md`. Contents
summarised in **§6, Step 6**.

**4. The Node version behind the pinned digest — RESOLVED: Node 24.18.1**, which
satisfies jsdom 30's `^24.15.0`. **`docker run` was not available** — the Docker
CLI is installed but no daemon is running — so the digest was resolved against the
registry by **two independent methods that agree**:

- **Docker Hub tag metadata.** Paging `hub.docker.com/v2/repositories/library/node/tags?name=bookworm-slim`
  for a tag whose `digest` equals `sha256:235600a8…` matches exactly two tags,
  **`24.18.1-bookworm-slim`** and `24.18-bookworm-slim`, both last updated
  2026-07-30.
- **The image config blob.** The pinned digest is an OCI image index; its
  `linux/amd64` manifest (`sha256:a09aabc6…`) points at config blob
  `sha256:c825877c…`, whose `config.Env` contains **`NODE_VERSION=24.18.1`**
  (`created: 2026-07-30T19:05:08Z`). Note for whoever repeats this: Docker Hub
  serves manifests directly but **307-redirects blobs to
  `production.cloudfront.docker.com`, which is egress-blocked here**, so the blob
  was fetched through **`mirror.gcr.io`** — a pull-through cache of Docker Hub
  that serves blobs on its own domain — using its own token endpoint.

**Advisory verification (new).** §0.5's claim was re-checked against the **GitHub
Advisory Database record itself**, not the npm registry's derived view:
`raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/07/GHSA-qwww-vcr4-c8h2/GHSA-qwww-vcr4-c8h2.json`.
**Verdict: an upstream re-cut, not a registry-side quirk.** Three legs:

- The GHSA record now contains **two `affected` entries** for `react-router` —
  `introduced 7.12.0 / fixed 7.18.2` and `introduced 8.0.0 / fixed 8.3.0`.
- Its timestamps show an amendment: `published` and `github_reviewed_at` are both
  **2026-07-24T16:44:43Z**, while `modified` is **2026-08-07T18:14:58Z** — the
  record was edited **fourteen days after review**.
- That window is corroborated inside this repo: `docs/ARCHIVE.md` §14
  (2026-08-03, v0.3.0 release prep) records `npm audit` reporting the
  `react-router` HIGH as one contiguous range, **`7.12.0 - 8.2.0`**. The split is
  therefore datable to between 2026-08-03 and the `modified` stamp of 2026-08-07.

  *Caveat on the word "revision history":* GitHub renders a per-revision history
  on the advisory's web page, which is unreachable here, and the advisory-database
  repo's git log is not readable through `raw.githubusercontent.com`. The
  `modified` ≠ `published` timestamp is the amendment evidence available; the
  individual diff between revisions is not.

### ◻ Still open

| # | Open question | Why it could not be answered | What would answer it |
|---|---|---|---|
| 2b | **jsdom 30.0.0's own breaking changes.** 27–29 are resolved above; 30 is not. | jsdom **deleted `Changelog.md` at `v30.0.0`** — verified by probing eight candidate filenames at the correct `refs/tags/v30.0.0` ref, all 404, against `Changelog.md` returning 200 at `v29.0.0`. Its notes now live only in GitHub Releases: `github.com` returns 403 through the proxy and `api.github.com` is scoped to `tyler-rich/Scrye`. | Read `jsdom/jsdom`'s GitHub Release notes for 30.0.0 from an unrestricted network. **Partly mitigated:** the specific risk the first draft flagged was checked directly against the shipped `lib/` of 26.1.0, 29.1.1, and 30.0.1 — `matchMedia`, `ResizeObserver`, and `scrollIntoView` are implemented in **none** of them, so `src/test/setup.ts`'s polyfill guards behave identically. Step 6's `npm test` remains the oracle for the rest. |
| 3 | **Is there an upstream `typescript-eslint` issue tracking TypeScript 7 support, and a rough timeline?** This decides whether TS 7 is a next-quarter item or a next-year one. | The typescript-eslint issue tracker is not reachable (same GitHub scoping as above). Their docs describe a *"New TypeScript Version"* pinned-issue process but the issues themselves cannot be listed. | Search `typescript-eslint/typescript-eslint` issues for label `New TypeScript Version`. **No browser needed for the decision itself:** §3.1's `npm view typescript-eslint@latest peerDependencies.typescript` answers "can we take TS 7 yet" directly from the registry. The issue tracker only adds a timeline. |
| 5 | **How many lint reports each of steps 1, 2, 3, and 4 actually produces.** Every effort estimate above is a range because of this. | Answering it means installing the candidate toolchain and running it, which mutates the lockfile — explicitly out of scope for this session. | Executing the sequence. This is not a gap in the scoping; it is the reason the sequence is ordered the way it is — each step's report count is measured against exactly one changed variable. |
| 6 | **Whether Vite 8's Lightning CSS minification changes Mantine's rendered output.** | Requires building and looking at the app. | Step 7's verification: build, diff the emitted CSS against the §1 baseline, and run the SPA in both colour schemes. |

---

## Appendix — how the evidence was gathered

So the next person can re-run it rather than re-derive it.

- **Peer ranges, engines, dist-tags, publish dates:** the npm registry JSON API
  (`https://registry.npmjs.org/<pkg>` and `/<pkg>/<version>`), read directly. This
  is the same data npm resolves against, so it is the authority for anything
  phrased as **[peer]**.
- **Advisory ranges:** `POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk`
  for the npm-derived view, and the **GitHub Advisory Database record itself** —
  `raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/<YYYY>/<MM>/<GHSA>/<GHSA>.json`
  — for the authoritative one. `api.osv.dev` is egress-blocked here;
  `github.com/advisories/…` returns 403; the advisory-database repo is the
  reachable route to the same data.
- **Container images without a Docker daemon:** manifests from
  `registry-1.docker.io` (token from `auth.docker.io`), tag↔digest mapping from
  `hub.docker.com/v2/repositories/library/<image>/tags`, and **config blobs from
  `mirror.gcr.io`** — Docker Hub 307-redirects blobs to
  `production.cloudfront.docker.com`, which is blocked.
- **Docs that live on a blocked site:** fetch the **source markdown from the
  documentation repository** instead of the rendered page. TypeScript's release
  notes are in `microsoft/TypeScript-Website` on the **`v2`** branch, not `main`.
  Note also that **jsdom's git tags carry a `v` prefix** — `refs/tags/v29.0.0`,
  not `29.0.0` — and a wrong ref returns the same 404 as a missing file, which is
  how the changelog was first mis-reported as absent.
- **Package internals:** published tarballs downloaded and unpacked into a
  scratch directory — `typescript@7.0.2`, `@typescript/typescript-linux-x64@7.0.2`,
  `@typescript-eslint/typescript-estree@8.66.0`,
  `@typescript-eslint/eslint-plugin@8.19.0` and `@8.66.0`, `@eslint/js@9.39.4` and
  `@10.0.1`, `eslint-plugin-react-hooks@5.1.0` and `@7.1.1`,
  `eslint-plugin-react-refresh@0.5.3`, `@vitejs/plugin-react@6.0.5`,
  `vitest@4.1.10`, `jsdom@30.0.1`. Config diffs and rule enumerations come from
  these, not from documentation.
- **Migration guides and changelogs:** fetched as raw markdown from each project's
  own repository — `eslint/eslint` `docs/src/use/migrate-to-10.0.0.md`,
  `vitejs/vite` `docs/guide/migration.md` (at `main` for v8 and at tag `v7.3.6` for
  v7), `vitest-dev/vitest` `docs/guide/migration.md` at tag `v4.1.10`,
  `vitejs/vite-plugin-react` `packages/plugin-react/CHANGELOG.md`,
  `ArnaudBarre/eslint-plugin-react-refresh` `CHANGELOG.md`,
  `typescript-eslint/typescript-eslint` `docs/users/Dependency_Versions.mdx`.
  Anything phrased as **[guide]** comes from one of these.
- **#153's failure:** the raw job log for check run `93006217895`
  (`Frontend — lint + build`, run `31221286073`), read in full rather than inferred
  from the job name.
- **Baseline:** `npm ci` from the committed lockfile, then `npm run lint`,
  `npm run format:check`, `npm test`, `npm run build`, `npm audit`. The lockfile's
  SHA-256 was captured before and re-checked after, and `git status` was clean
  throughout.
