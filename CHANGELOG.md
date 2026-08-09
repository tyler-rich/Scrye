# Changelog

All notable changes to Scrye are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Regression test for the `:scanId` per-scan state reset (`L17` / `P2-2`)** —
  `frontend/src/pages/ScanDetailPage.scanIdReset.test.tsx`. The reset effect has
  guarded against two scans' state mixing since 2026-07-13, but nothing tested
  it: the three existing `ScanDetailPage` suites (`findingsTable`, `latestwins`,
  `poller`) never navigate between two `:scanId` values, so the effect could
  have been deleted with the whole suite staying green. The gap was found while
  auditing [#176](https://github.com/tyler-rich/Scrye/issues/176), which lists
  that effect as one of six sites a future change may touch.

  The test renders `/scans/1`, edits the tag draft away from the server value,
  navigates to `/scans/2` with the second fetch held open, and asserts that none
  of scan 1's header, findings, artifacts or tag draft survives — then that the
  stale draft does not reappear once scan 2 lands. Verified to catch the
  regression, not merely to pass: with the reset effect temporarily deleted it
  fails on the first in-flight assertion, with scan 1's target still rendered.
  **No production code changed** — `ScanDetailPage.tsx` is byte-identical to
  `dev`, and none of the other five findings #176 tracks was touched.

### Security

- **Frontend lockfile refreshed, closing two HIGH advisories in the build/dev
  toolchain: GHSA-5p4m-2wfm-xmqj (`js-yaml`) and GHSA-2v37-7h3g-55p8
  (`nanoid`).** Both are transitive devDependencies, and both fixed versions
  already sat inside the ranges their requiring packages declare, so this is a
  `package-lock.json` change only — `package.json` is untouched and no package
  moved a major.

  - **`js-yaml` 4.3.0 → 4.3.1** — GHSA-5p4m-2wfm-xmqj, HIGH (CVSS 7.5,
    CWE-407): quadratic CPU consumption resolving a `!!omap`, the
    CVE-2026-59870 fix not having been backported to the 3.x/4.x lines.
    Affected range `>=4.0.0 <4.3.1`. Reached by one path only —
    `eslint@9.39.4` → `@eslint/eslintrc@3.3.5` → `js-yaml` — whose declared
    range is `^4.1.1`. Verified at source rather than from the advisory's
    metadata: diffing the two published tarballs, 4.3.1's sole functional
    change is in the `!!omap` duplicate-key check, which replaces an array
    plus a linear `indexOf` scan per key (the quadratic path) with an object
    and an `Object.prototype.hasOwnProperty` lookup.
  - **`nanoid` 3.3.16 → 3.3.18** — GHSA-2v37-7h3g-55p8, HIGH (CVSS 5.9,
    CWE-835): a custom generator can loop indefinitely when `size` is zero.
    Affected range `<3.3.17`. Reached by one path only — `postcss@8.5.25` →
    `nanoid` — whose declared range is `^3.3.16`. The advisory's fixed version
    is 3.3.17; the refresh resolves to **3.3.18**, the highest release in that
    range, which is a follow-up to the same defect — comparing the two
    tarballs, 3.3.18 extends 3.3.17's zero-size guard to the async native
    entry point, which 3.3.17 left unguarded.

  **Neither package ships in the Scrye image.** Both are marked `dev` in the
  lockfile and neither appears in the built SPA (`nanoid` runs inside PostCSS
  at build time; `js-yaml` only ever parses this repo's own ESLint config).
  The runtime stage of `docker/Dockerfile` copies `frontend/dist` out of the
  builder and no `node_modules`, so the vulnerable code never reaches a
  deployed instance — the fix is for the build and development toolchain.

  The lockfile diff is exactly those two entries — six lines each way, the
  `version`/`resolved`/`integrity` triple per package — with no transitive
  requirement moved and no unrelated churn. After the refresh `npm audit`
  reports 0 vulnerabilities at every severity, and the frontend suites are
  unchanged: ESLint clean, Prettier clean, 79 tests across 21 files passing,
  and a build of 7,035 modules to 645.18 kB JS / 201.38 kB CSS — byte-for-byte
  the sizes recorded for the pre-refresh baseline.

- **`cryptography` bumped 49.0.0 → 50.0.0, closing CVE-2026-69247** (HIGH) — a
  Bleichenbacher-style oracle in the PKCS7 decryption helpers, where
  `pkcs7_decrypt_der` and its variants exposed distinguishable errors and timing
  while unwrapping an encrypted key. Upstream's fix substitutes a random key on
  failure, per RFC 3218. Verified against pyca/cryptography's own `CHANGELOG.rst`
  rather than the scanner's `FIXED IN` column: the entry is recorded under
  **50.0.0 (2026-07-31)**, and 49.0.0 (2026-06-12) predates it.

  **Scrye was never exposed.** It uses four symbols from the library, all in
  `backend/app/core/crypto.py` — `AESGCM`, `HKDF`, `hashes` and `InvalidTag` — and
  never calls PKCS7 at all, so the vulnerable code path is unreachable. The bump
  is taken because the finding is *fixable*, which is what the dogfood gate keys
  on (`CLAUDE.md` § Dependency hygiene), not because the path was live.

  50.0.0 is a major, and its breaking changes miss Scrye's surface: FFDH is
  deprecated, X.509 verification APIs stabilised, and SCT/X.509 validation
  tightened — none of which Scrye touches. (The ChaCha20 counter change landed in
  49.0.0 and was already absorbed.) `backend/requirements.lock` was regenerated
  with the pinned `uv 0.8.17` command from `CONTRIBUTING.md` § Backend dependency
  lock; the diff is that one package and its hashes, with no transitive churn.

### Changed

- **Vite 6.4.3 → 8.2.1 and `@vitejs/plugin-react` 4.3.4 → 6.0.5** — step 7 of
  the frontend toolchain sweep in `docs/upgrades/frontend-toolchain-86.md`,
  crossing two majors on each package. The two move in lockstep because
  `@vitejs/plugin-react@6.0.5` declares `vite: "^8.0.0"` as a **required**
  (non-optional) peer — it does not merely tolerate Vite 8. These are the only
  two packages bumped; `frontend/vite.config.ts`, both tsconfigs,
  `eslint.config.js` and every source and test file are untouched.

  **Vite 8 replaces Rollup + esbuild with Rolldown + Oxc, and CSS minification
  moves to Lightning CSS.** This is the one step in the sweep that changes what
  ships, so the emitted bundle was compared against the pre-bump baseline
  rather than assumed equivalent:

  | | Vite 6.4.3 | Vite 8.2.1 | Δ |
  |---|---|---|---|
  | modules transformed | 7,035 | 7,018 | −17 |
  | JS | 645.14 kB (gzip 193.61) | 630.29 kB (gzip 187.36) | −14.85 kB (−2.30%) |
  | CSS | 201.38 kB (gzip 29.30) | 196.79 kB (gzip 28.63) | −4.59 kB (−2.28%) |
  | build time | 7.30 s | 1.28 s | −5.7× |

  **The module delta is entirely CommonJS-interop scaffolding, not application
  code.** Both bundlers' module lists were captured and diffed: the 19 ids
  present only under Vite 6 are `commonjsHelpers.js` plus the
  `?commonjs-es-import` / `?commonjs-exports` / `?commonjs-module` proxy
  modules `@rollup/plugin-commonjs` mints when converting `react`, `react-dom`,
  `scheduler`, `cookie`, `fast-deep-equal` and `set-cookie-parser` to ESM.
  Rolldown handles CommonJS natively and mints none. Exactly one id is new
  (`vite/preload-helper.js`, a Vite-internal helper). **No application or
  library module was added or removed.**

  **The CSS was verified declaration by declaration, because a Lightning CSS
  regression fails no test.** Both stylesheets were parsed, their comma-joined
  selector lists split into individual selectors (so the minifiers' rule
  merging and splitting cancels out), colours canonicalised, and the shorthands
  Lightning CSS introduced expanded back to longhands. Result: **1,171
  (context, selector) keys on each side, none gained, none lost, and zero
  declarations added or dropped.** Every difference is a semantics-preserving
  minifier rewrite — 29 vendor prefixes removed where the unprefixed property
  is present (`-moz-appearance` ×14, `-webkit-appearance` ×14,
  `-webkit-transform`), `transparent` → `#00000000`, `center` → `50%`,
  `0rem` → `0`, `.15s ease` → `.15s` (`ease` is the initial
  `transition-timing-function`), `top/right/bottom/left: 0` → `inset: 0`,
  `padding-inline-start/end` → `padding-inline`, `:nth-of-type(1)` →
  `:first-of-type`, `*:before` → `:before`, adjacent rules with identical
  declaration blocks merged, and the six `::-webkit-*` spin/search-button
  selectors **split** out of one comma list into six rules — which is a
  correctness improvement, since a browser that fails to parse one selector in
  a comma list discards the whole rule.

  **Rendering was compared pixel by pixel, with a calibrated noise floor.** Six
  routes (dashboard, scans list, new scan, scan detail, settings, account) were
  rendered from both builds against a stubbed API in headless Chromium, in
  **both light and dark mode**. A first pass diffed non-zero, and re-running the
  *same* build twice showed a ~135-pixel noise floor from in-flight animations —
  so that pass measured nothing. With animations frozen the noise floor is
  **exactly zero across all twelve views**, and against it **all twelve views
  are pixel-identical between Vite 6 and Vite 8.**

  **The one genuine behaviour change is the browser target.** Vite 8's default
  build target is `baseline-widely-available`, which resolves to **Chrome 111,
  Edge 111, Firefox 114, Safari 16.4** — up from esbuild's `modules` default
  (roughly Chrome 87 / Firefox 78 / Safari 14). Every syntax Lightning CSS
  newly emitted is inside that target: Media Queries Level 4 range syntax
  (`(device-width<=31.25em)`, Safari 16.4+), multi-position gradient colour
  stops (Safari 12.1+), and unprefixed `appearance` (Safari 15.4+). No project
  document states a browser floor, so none needed correcting.

  **No `vite.config.ts` change was required**, as the sweep document predicts:
  the config has no `build.rollupOptions` (so the `rollupOptions` →
  `rolldownOptions` rename does not apply), no `esbuild`, `optimizeDeps` or
  `manualChunks` keys, and `plugins: [react()]` passes no options.

  **`@vitejs/plugin-react` 6.0.0 removed every Babel feature — and this repo
  passed no `babel` option, so nothing had to move to `@rolldown/plugin-babel`
  and nothing was dropped.** There is no `.babelrc`, no `babel.config.*`, and
  no `babel` key anywhere in `frontend/`. React Fast Refresh now runs through
  Oxc; the dev server was smoke-tested to confirm it still serves
  `/@react-refresh` and still injects `$RefreshReg$` into `.tsx` transforms,
  even though the `react-refresh` npm package has left the tree.

  The lockfile moves 339 → 305 packages, every movement attributable: 30 added
  (`rolldown` + 15 platform bindings, `lightningcss` + 12 platform bindings,
  `@oxc-project/types`, `@rolldown/pluginutils`, `detect-libc`), 61 removed
  (`esbuild` + 25 `@esbuild/*`, `rollup` + 25 `@rollup/rollup-*`, plugin-react
  4's Babel subtree, and `react-refresh`), and 3 bumped (the two targets plus a
  `picomatch` dedupe). `@babel/core` and `@babel/parser` remain in the tree,
  but their only requirer is now `eslint-plugin-react-hooks@7.1.1` rather than
  plugin-react. Lint, `format:check` and `npm audit` (0 vulnerabilities) are
  clean, and the suite is unchanged at **80 tests across 22 files**, compared
  per test name rather than by total.

- **jsdom 26.1.0 → 30.0.1** — step 6 of the frontend toolchain sweep in
  `docs/upgrades/frontend-toolchain-86.md`, crossing four majors (27, 28, 29,
  30). **`jsdom` is the only package bumped**; `vite` stays at 6.4.3 (step 7),
  and no config, source or test file changed. jsdom is a devDependency reached
  only through Vitest's `environment: 'jsdom'` — nothing in `frontend/src/`
  imports it — so the emitted bundle is unchanged down to its content hashes
  (7,035 modules → 645.14 kB JS `index-Vvdzytcz.js` / 201.38 kB CSS
  `index-D2wHtcHV.css`, identical to the pre-bump baseline).

  **The Node floor rises, which is the one change with a reach outside the test
  run.** `jsdom@30.0.1` declares `engines.node: "^22.22.2 || ^24.15.0 ||
  >=26.0.0"`. All three runtimes that matter satisfy it — CI's
  `node-version: "24"` resolves to 24.19.0, and `docker/Dockerfile`'s pinned
  `node:24-bookworm-slim@sha256:235600a8…` ships Node 24.18.1 (confirmed by two
  independent registry reads) — so neither `ci.yml` nor the Dockerfile needed a
  change. `README.md` and `CONTRIBUTING.md` did: both said "Node 22+", under
  which a contributor on Node 22.13 would install cleanly and then run `npm
  test` on a runtime jsdom does not support. Both now say **Node 22.22.2+ or
  24.15+**.

  **The selector-engine swap was measured, not argued.** jsdom 27.0.0 replaced
  the CSS selector engine (`nwsapi` → `@asamuzakjp/dom-selector`), and a
  Testing Library query can resolve to a *different* element after such a swap
  while every downstream assertion still passes — drift a green suite cannot
  catch. Per the sweep document's Step 6 checklist, a throwaway `setupFiles`
  shim wrapped every `screen` query method and logged each resolved element's
  DOM index path plus its normalised `outerHTML`; the suite was run on both
  jsdom versions and the two logs diffed. **176 query resolutions across 46
  tests in 17 files — the diff is empty.** Every query resolved to the same
  element on both sides. The shim was deleted before this PR; it was a
  measurement, not a fixture.

  Four further changes across the span were re-verified inert against the
  *installed* tree rather than inherited from the scoping document: the 29.0.0
  CSSOM rewrite has no author CSS to act on (`vite.config.ts`'s `test` block
  sets no `css` key, so Vitest's default `css: false` applies and Mantine's
  stylesheets never enter jsdom); 27.0.0's `element.click()` → `PointerEvent`
  change is unreachable (no `.click()` anywhere in `frontend/src/` — all 26
  interactions go through `userEvent`/`fireEvent`, which build their own
  events); passive-by-default events cannot bite (no `preventDefault` in
  `src/`); and `matchMedia`, `ResizeObserver` and `scrollIntoView` are
  implemented in **zero** files of the shipped `lib/` in both 26.1.0 and
  30.0.1, so `src/test/setup.ts`'s `if (!…)` polyfill guards behave
  identically.

  The lockfile moves 338 → 340 packages: 12 added, 10 removed, 19 bumped, every
  one attributed to jsdom or its transitive closure by resolving each package's
  requirers in both lockfiles. The new selector engine and the `css-tree`-based
  CSSOM arrive (`@asamuzakjp/dom-selector`, `css-tree`, `mdn-data`,
  `@bramus/specificity`, `bidi-js`, `require-from-string`,
  `@csstools/css-syntax-patches-for-csstree`), `undici` replaces the
  `ws`/`http-proxy-agent`/`https-proxy-agent`/`agent-base` stack, and
  `cssstyle` → `rrweb-cssom` and `whatwg-encoding` → `iconv-lite` →
  `safer-buffer` are orphaned along with `nwsapi`. Nothing outside that closure
  moved: `vite`, `vitest`, `typescript`, `eslint`, `postcss`, `react` and
  `react-dom` are unchanged in the resolved tree, and the top-level
  `lru-cache@5.1.1` Babel depends on is untouched (jsdom's `11.5.2` copies are
  all nested). Lint, `format:check`, build and `npm audit` (0 vulnerabilities)
  are unchanged, and the test suite holds at **80 tests across 22 files** —
  compared per test, not per total: both runs were captured with
  `--reporter=json` and reduced to sorted `file :: full test name :: status`
  triples, which diff empty.

- **Vitest 3.2.7 → 4.1.10** — step 5 of the frontend toolchain sweep in
  `docs/upgrades/frontend-toolchain-86.md`. **`vitest` is the only package
  bumped**, and it stays on the pinned `vite@6.4.3`: `vitest@4.1.10` declares
  `vite: "^6.0.0 || ^7.0.0 || ^8.0.0"` as a required (non-optional) peer, so
  Vitest 4 needs no Vite major and does not have to wait for step 7. `jsdom`
  stays at 26.1.0 (step 6) and `vite` at 6.4.3 (step 7).

  **`frontend/vite.config.ts` needed no change**, confirmed against the shipped
  4.1.10 artifact rather than the migration guide: `dist/config.d.ts` still
  carries `declare module "vite" { interface UserConfig { test?: … } }`, so the
  `/// <reference types="vitest/config" />` plus `defineConfig` from `'vite'`
  arrangement still types the `test` key; `extends?: string | true` is still on
  the project-configuration type; and `projects` is already the current
  spelling, so the `workspace` → `projects` rename is inert. Vitest 4's other
  breaking changes have no consumer here — no `coverage`, `poolOptions`,
  `reporters`, `deps.*` or `css` keys in the config, no snapshots, and no
  test-options-as-third-argument call sites. The narrowed default `exclude`
  (v3's five patterns down to `node_modules` and `.git`) collects nothing new,
  because both projects' `include` globs are confined to `src/**`.

  **One type error had to be fixed, in test code**, and it is the one thing the
  sweep document's Step 5 row did not predict. Vitest 4 widened `vi.fn`'s
  type-parameter constraint from `Procedure` to `Procedure | Constructable` (the
  change that lets `vi.spyOn` mock constructors), so the alias
  `ReturnType<typeof vi.fn>` — which instantiates a generic at its *constraint*,
  not its default — now resolves to `Mock<Procedure | Constructable>` and no
  longer satisfies a plain call signature. `tsc -b` failed at
  `OidcLinkCard.test.tsx:65`, where such a mock is passed to
  `.mockImplementation()` on a `History.replaceState` spy. Fixed at that one
  site by typing the mock against the real method signature
  (`Mock<typeof window.history.replaceState>`) instead of the loose alias, which
  is more accurate than what it replaced. No autofix was run, in bulk or
  otherwise. The sibling `ReturnType<typeof vi.fn>` at line 49 still compiles —
  its mock is only ever asserted on — and was deliberately left alone.

  **`vi.restoreAllMocks()` changed meaning, and it reaches one suite — but no
  test's outcome depends on it.** In Vitest 4 it restores only spies created
  with `vi.spyOn`, where Vitest 3 also reset plain `vi.fn()` implementations.
  Measured on both versions with a standalone probe rather than read from the
  guide: v3 reports the `vi.fn()` implementation gone after the call, v4 reports
  it surviving; `vi.spyOn` spies are restored under both.
  `OidcLinkCard.test.tsx` is the only file combining a `vi.mock` factory's
  `vi.fn()`s with `vi.restoreAllMocks()` in `afterEach`, so its three mocks now
  carry implementations across tests. Instrumenting the real suite shows the
  carryover is real and inert: `startOidcLink`/`unlinkOidcIdentity` retain an
  implementation from the test that sets it onward, yet are invoked **zero**
  times in every later test, and every one of the ten tests sets
  `getOidcLinkStatus`'s own resolved value before rendering.

  **Suites, from a fresh `rm -rf node_modules && npm ci`:** lint clean,
  `format:check` clean, **80 tests across 22 files** — identical to the
  pre-bump baseline down to per-test name and status — `npm audit` 0
  vulnerabilities, and a build of 7,035 modules whose emitted assets carry the
  **same content hashes** as the baseline (`index-Vvdzytcz.js` 645.14 kB,
  `index-D2wHtcHV.css` 201.38 kB), which is the proof that a test-runner
  devDependency changed nothing that ships.

- **TypeScript 5.7.2 → 6.0.3, and `frontend/tsconfig.app.json` pins
  `"types": []`** — step 4 of the frontend toolchain sweep in
  `docs/upgrades/frontend-toolchain-86.md`. **`typescript` is the only package
  that moved**: the lockfile diff is one entry's `version`/`resolved`/
  `integrity` triple, 346 packages before and after, nothing added, removed, or
  bumped transitively, `lockfileVersion` still 3. No source file changed.

  **This stops at 6.0.3 deliberately, and 6.0.3 is the ceiling, not the
  latest.** `typescript@7.0.2` is the Go-native compiler: its `"."` export is
  `./lib/version.cjs`, `lib/typescript.js` and `tsserver` are gone, and
  `@typescript-eslint/typescript-estree` uses 114 distinct `ts.*` symbols from
  that removed API. Re-checked at the registry on **2026-08-09** rather than
  taken from the scoping document: `typescript-eslint@8.66.0` (`latest`) and its
  `8.66.1-alpha.10` canary both peer `typescript: ">=4.8.4 <6.1.0"`, and
  `@typescript-eslint/parser` and `/typescript-estree` carry the same range —
  so no published typescript-eslint accepts TypeScript 7. 6.0.3 (2026-04-16) is
  the highest release inside `<6.1.0` and the last JS-based TypeScript. A future
  `typescript@7.x` offer from Dependabot is expected and is **not** an oversight;
  re-run `npm view typescript-eslint@latest peerDependencies.typescript` before
  treating the ceiling as stale. No `ignore` rule was added — TypeScript 7 is
  wanted, just not before typescript-eslint supports it.

  **`"types": []` is written out rather than inherited.** TypeScript 6.0 changes
  the option's default from "enumerate every package in `node_modules/@types`"
  to `[]`. It is a no-op for `src/` — **verified, not assumed, and verified
  twice**: `src/` has zero references to `process`, `Buffer`, `__dirname` or
  `__filename` and no `NodeJS.` namespace use, all 22 test files import their
  globals from `'vitest'` (Vitest's `globals` option is not set), and timers go
  through `window.setTimeout` from the DOM lib. The empirical leg is the
  stronger one: the edit was applied **under 5.7.2 first**, where the old
  enumerate-everything default was still live, and `tsc -b --force` plus
  `npm run lint` stayed clean — so nothing in `src/` was relying on the ambient
  `@types` enumeration that 6.0 withdraws. `frontend/tsconfig.node.json` needed
  no change; it already sets `"types": ["node"]` for `vite.config.ts`, which is
  the one file that does use `process`.

  **The inference change the scoping document flags as unpre-emptable did
  surface — silently, and it is benign.** TypeScript 6.0's "less
  context-sensitivity on `this`-less functions" produced **no error and no
  deprecation diagnostic**; `tsc -b --force` is clean. It shows up only in
  inferred types, found by emitting declarations under both compilers and
  diffing them: the sole difference across 79 `.d.ts` files is `FindingsTable`
  in `frontend/src/pages/ScanDetailPage.tsx`, where the `React.memo` overload
  resolved for a `this`-less named function expression moves from
  `NamedExoticComponent<FindingsTableProps>` to
  `MemoExoticComponent<(props: FindingsTableProps) => JSX.Element>`. The public
  contract is unchanged — a type probe confirms both compilers accept the exact
  prop object and reject an extra and a missing prop identically — and the repo
  emits no declarations (`noEmit: true`), so nothing consumes the printed form.
  It is the only `memo`/`forwardRef` site in `src/`.

  **Nothing else moved.** `eslint --print-config` on an app `.tsx`, a library
  `.ts` and a test override is **byte-identical** before and after, 135 rules
  each. Lint clean, `format:check` clean, **80 tests across 22 files**,
  `npm audit` 0 vulnerabilities, and the build emits the **same content hashes**
  as before (`index-Vvdzytcz.js` 645.14 kB, `index-D2wHtcHV.css` 201.38 kB,
  7,035 modules) — the proof that a compiler-only step changed nothing that
  ships.

- **React Compiler lint rules adopted from `eslint-plugin-react-hooks@7.1.1`,
  with `react-hooks/set-state-in-effect` held back** — step 3 of the frontend
  toolchain sweep in `docs/upgrades/frontend-toolchain-86.md`. **No dependency
  version moved**; `frontend/package.json` and `frontend/package-lock.json` are
  byte-identical. Step 2's holding edit in `frontend/eslint.config.js` is
  replaced by the `...reactHooks.configs.recommended.rules` spread it was
  standing in for, so the resolved rule set goes **121 → 135 rules** — verified
  with `eslint --print-config` on an app `.tsx`, a library `.ts` and a test
  override, all three moving identically. The 14 added are 11 at `error`
  (`config`, `error-boundaries`, `gating`, `globals`, `immutability`,
  `preserve-manual-memoization`, `purity`, `refs`, `set-state-in-render`,
  `static-components`, `use-memo`), 2 at `warn` (`incompatible-library`,
  `unsupported-syntax`), and `set-state-in-effect` at `off`. Nothing else in
  the resolved config moved at any severity.

  **Twelve of the fourteen report nothing against the current tree** —
  including `immutability`, `purity` and `preserve-manual-memoization`, which
  the scoping document expected to fire in volume. The whole adoption cost is
  two rules and 24 findings.

  **`react-hooks/refs` — 6 findings, all fixed by hand.** All six are one
  idiom in `frontend/src/pages/ScansPage.tsx`: a `useRef(viewFromParams(…))`
  whose `.current` was read during render to seed six `useState` initializers.
  Reading a ref during render is what the rule forbids, so the ref is replaced
  by a lazy `useState` initializer — `const [initialView] = useState(() =>
  viewFromParams(searchParams))` — which runs `viewFromParams` exactly once on
  first render, as the ref did. Behaviour is unchanged and the History
  deep-linking tests (`P3-1`) still pass. This is the sweep's first step to
  change runtime code, so unlike steps 1 and 2 the emitted bundle moves:
  `index-BNB6IweX.js` 645.18 kB → `index-Vvdzytcz.js` 645.14 kB. The CSS is
  untouched and keeps its hash (`index-D2wHtcHV.css`).

  **`react-hooks/set-state-in-effect` — 18 findings, rule left `off` with the
  reason in the config and the work tracked in
  [#176](https://github.com/tyler-rich/Scrye/issues/176).** Only **6** of the 18
  are the synchronous setState-in-effect the rule's rationale describes, and
  two of those are deliberate effects that each closed a real bug —
  `ScanDetailPage`'s `:scanId` reset (`L17`/`P2-2`) and `ScansPage`'s compare
  reconcile (`P3-2`) — so #176 names them explicitly rather than leaving a
  future session to "fix" them blind. The other **12** are the fetch-on-mount
  idiom, where every `setState` runs after an `await`; they are deliberately
  **not** in #176's scope, because a three-shape probe against the installed
  7.1.1 showed the report tracks what the compiler can see rather than a
  behavioural difference: with `load` defined in the component body
  `void load()` reports while the semantically identical
  `void (async () => { await load(); })()` does not, and moving `load` behind a
  custom hook silences every shape. There is no fix for those 12 that is an
  improvement — only hiding the call from the analyser, or a data-fetching
  refactor that is its own decision.

- **ESLint 9.39.4 → 10.8.1, with `@eslint/js` 9.39.4 → 10.0.1,
  `eslint-plugin-react-hooks` 5.1.0 → 7.1.1 and `eslint-plugin-react-refresh`
  0.4.16 → 0.5.3** — step 2 of the frontend toolchain sweep in
  `docs/upgrades/frontend-toolchain-86.md`, unblocked by step 1
  (`typescript-eslint@8.66.0` is the first release to peer `eslint ^10.0.0`).
  Lint-only: no source file changed, `npm test` and `npm run build` are
  unchanged, and the emitted bundle carries the **same content hashes** as
  before (`index-BNB6IweX.js`, `index-D2wHtcHV.css`). `typescript` stays at
  5.7.2 and no other package in `frontend/package.json` moved.

  **`eslint-plugin-react-hooks` is peer-forced, and its rule-set expansion is
  deliberately held inert.** 5.1.0 peers `eslint` only up to `^9`; the `^10.0.0`
  clause first appears in 7.1.0, so ESLint 10 cannot resolve against the old
  pin. But 7.x's `configs.recommended.rules` folds in the React Compiler set —
  resolved from the installed package, it is **16 rules (13 `error`, 3 `warn`)**
  where 5.1.0's was 2. `frontend/eslint.config.js` spread that object, so the
  bump alone would have enabled 14 new rules. The spread is replaced by the two
  rules it contained under 5.1.0 — `react-hooks/rules-of-hooks: 'error'` and
  `react-hooks/exhaustive-deps: 'warn'`, verified against 5.1.0's shipped
  config — making the edit behaviour-preserving. Adopting the compiler set is
  step 3 and remains a separate decision. Confirmed at the resolved config, not
  assumed: `eslint --print-config` reports exactly those two `react-hooks/*`
  rules, at their original severities, for all three file classes.

  **The resolved rule set moved by three rules, and every movement was checked
  with `eslint --print-config` on an app `.tsx`, a library `.ts`, and a test
  override — before and after.** All three classes moved identically, 118 → 121
  rules:

  - **Added at `error`, all three from `@eslint/js` 10.0.0's revised
    `eslint:recommended`:** `no-unassigned-vars`, `no-useless-assignment`,
    `preserve-caught-error`. Attributed by resolving the shipped config object
    from both packages rather than reading release notes — 9.39.4's recommended
    carries 61 rules, 10.0.1's carries 64, and the delta is exactly those three
    with nothing removed and nothing re-severitied.
  - **`no-shadow-restricted-names`** — its `reportGlobalThis` default flips
    `false` → `true`, so `globalThis` is now reported. The one genuine
    behaviour change among the severity-carrying rules; it finds nothing here.
  - **Two entries changed shape without changing behaviour:**
    `no-constant-binary-expression` gains a new option
    (`checkRelationalComparisons`, default `false`, so opt-in) and
    `no-unused-vars` materialises a full default-option object. Both are ESLint
    10 adding or revising `meta.defaultOptions`, not a print-config formatting
    change — 25 of the 72 core rules in this config carry `defaultOptions` and
    only these two moved. `no-unused-vars` is at severity `0` here regardless,
    disabled by typescript-eslint in favour of its own rule.

  **`@eslint/eslintrc` and `js-yaml` are now absent from the tree entirely** —
  `eslint@10.8.1` no longer depends on eslintrc, which was this repo's only path
  to `js-yaml`. `npm ls` reports nothing for either. That permanently removes
  the path behind GHSA-5p4m-2wfm-xmqj, which the lockfile refresh above had
  closed by version alone.

  **None of ESLint 10's removals reach this repo, checked rather than assumed:**
  there has never been an `.eslintrc*` file (flat config since Phase 0), there
  are no `eslint-env` comments anywhere, no custom rules or `SourceCode` /
  rule-context API use, no `RuleTester` or `Linter`/`ESLint` API consumers, and
  no bracket expressions in any ignore glob. The new engine floor
  (`^20.19.0 || ^22.13.0 || >=24`) is satisfied by CI's Node 24 and by the
  `node:24-bookworm-slim` digest the image pins.

- **`typescript-eslint` 8.19.0 → 8.66.0** — step 1 of the frontend toolchain
  sweep in `docs/upgrades/frontend-toolchain-86.md`, taken alone because it is
  the only unblocking move in that sequence: the pinned 8.19.0 capped
  `typescript` at `<5.8.0` and `eslint` at `^9`, and 8.66.0 raises those to
  `<6.1.0` and `^10.0.0`. No other package in `frontend/package.json` moved and
  no ESLint or TypeScript config was edited.

  **Two of the scoping document's predictions did not hold, and both are worth
  carrying into the remaining steps.**

  - **An existing rule's implementation got stricter.** The rule *set* is
    unchanged, exactly as predicted — `recommended-type-checked.js` is identical
    across the 47-minor span, 50 entries either side. But
    `@typescript-eslint/no-unnecessary-type-assertion` now catches what it
    previously missed, reporting two redundant `'' as string` assertions in
    `NewScanPage.tsx`'s `useForm` initial values. Both were removed by hand;
    `tsc -b` confirms the inferred form type is unchanged, and the emitted
    bundle is byte-identical (same content hashes), since the assertions erase
    at compile time. **"No new rules" does not mean "no new findings."**
  - **The effective rule set did change, in the relaxing direction.** The
    document's claim that the shipped `recommendedTypeChecked` is byte-for-byte
    identical is wrong, not merely incomplete: it diffed one of the three files
    that config composes. The layer it did not diff,
    `eslint-recommended-raw.js`, gains **`no-with: 'off'`** (22 → 23 entries),
    which drops `no-with` from `error` to `off` in the resolved config. Accepted
    rather than restored — `with` is a hard compile error under this repo's
    tsconfigs (verified at the compiler: `TS1101` plus `TS2410`), so the rule is
    genuinely redundant here.

  The lockfile change is confined to the `typescript-eslint` subtree: the ten
  `@typescript-eslint/*` packages plus `ts-api-utils` 1.4.3 → 2.5.0 and nested
  `minimatch`/`brace-expansion` bumps; two new first-party splits
  (`project-service`, `tsconfig-utils`); and three nested copies that exist only
  because the top-level ones stay pinned for ESLint 9. `typescript-estree`'s
  swap from `fast-glob` to `tinyglobby` — already present in the tree at a
  satisfying version — orphans 17 packages, each checked to have no surviving
  requirer. Net 374 → 362 packages, `npm audit` still 0 at every severity, and
  the suites are unchanged: ESLint clean, Prettier clean, 79 tests across 21
  files, and a build of 7,035 modules to 645.18 kB JS / 201.38 kB CSS.
- **Bundled scanner binaries updated: Trivy 0.72.0 → 0.73.0, Grype 0.115.0 →
  0.116.1, Syft 1.46.0 → 1.50.0** — the current upstream releases, verified by
  resolving each project's tags rather than from any advisory or summary. No
  breaking changes, deprecations, or CLI changes in any release crossed, and
  Syft's JSON schema moves only at patch level (16.1.5 → 16.1.10), so Scrye's
  JSON parsing and the persisted-SBOM format are unaffected. Highlights: Trivy
  gains native discovery of VEX documents stored as OCI artifacts; Grype 0.116
  adds lightweight Go reachability analysis that reduces false positives and
  dedupes govulndb/GHSA twins; Syft picks up vcpkg and macOS `.app` cataloging.
  The CI dogfood gate's `aquasec/trivy` / `anchore/grype` scan images (pinned to
  the bundled versions by design) and the weekly re-scan move in lockstep, with
  digests resolved from the registry. `THIRD_PARTY_LICENSES/` re-verified at the
  new tags: every bundled `LICENSE` (and Trivy's `NOTICE`) is byte-identical
  upstream, and Grype/Syft still ship no `NOTICE`, so only the version table
  changes.
- **`uvicorn[standard]` 0.52.0 → 0.52.1 and `alembic` 1.18.5 → 1.19.1**, the
  mergeable half of Dependabot **#157**, reapplied by hand because Dependabot
  edits `pyproject.toml` only and leaves `backend/requirements.lock` stale — its
  own branch fails CI's lock-drift gate. `requirements.lock` was regenerated with
  the pinned `uv 0.8.17` command from `CONTRIBUTING.md` § Backend dependency lock;
  the diff is those two packages and their hashes, with no transitive churn.
  Neither release changes a deployed Scrye's behaviour, configuration or schema.
  - **uvicorn 0.52.1** is four WebSocket-only fixes (closing handshake, write
    flow control, connection loss during a backpressured write, and denial-
    response headers). Scrye serves no WebSocket route and the SPA opens no
    socket, so none of it is reachable here — pure currency.
  - **alembic 1.19.1, not the 1.19.0 Dependabot proposed.** 1.19.0 (2026-08-04)
    added named-CHECK-constraint autogenerate detection; 1.19.1 (2026-08-08,
    published after #157 opened) fixes a defect in exactly that feature, where
    column-bound check constraints produced wrong autogenerate results. Both
    changes are confined to the migration-*authoring* path — no shipped migration
    and no runtime behaviour is affected.
- **Routine dependency currency across the backend, frontend and CI**, triaged
  from the three grouped Dependabot PRs opened after v0.3.0 (#144, #145, #146)
  and reapplied by hand rather than merged as-built. No change to a deployed
  Scrye's behaviour, configuration or schema.
  - **Backend.** `fastapi` 0.140.13 → 0.141.1 (the release adds an
    `app.frontend()` dev-server convenience Scrye does not use) and
    `uvicorn[standard]` 0.51.0 → 0.52.0 (adds an **opt-in** experimental
    `--http zttp` parser, which upstream marks not-for-production and the image
    never selects — `docker/entrypoint.sh` passes no `--http` flag, so the
    default parser is unchanged). `starlette` holds at 1.3.1 and
    `backend/requirements.lock` was regenerated with the pinned `uv`. `ruff`
    0.16.0 → 0.16.1 (dev tooling only).
  - **Frontend.** `@mantine/*` 7.15.2 → 7.17.8 (a minor inside the locked v7
    line), `@tabler/icons-react` 3.46.0, `@testing-library/react` 16.3.2,
    `@testing-library/jest-dom` 7.0.0, `postcss-preset-mantine` 1.18.0,
    `globals` 17.8.0, `prettier` 3.9.6, and `@types/node` 22.20.0 → 24.13.3 to
    match the Node 24 the SPA is built on. All are build- or test-time packages
    except Mantine and the icon set; the shipped bundle changes only by
    Mantine's own 7.15 → 7.17 fixes. Prettier 3.9 reformats short union types
    onto one line, which is why three source files show whitespace-only edits.
  - **CI.** `github/codeql-action` re-pinned from the `v4.37.4` annotated *tag
    object* to the commit that tag dereferences to. Same release, same CodeQL
    bundle, same `security-extended` suite — a SHA-pin correctness fix, not a
    version bump.

## [0.3.0] - 2026-08-03

### Upgrade notes

- **Upgrading applies a database migration.** The container runs
  `alembic upgrade head` on start as it always has; on first start of 0.3.0 that
  applies `0009_oidc_link_flows`, which adds two nullable columns (`purpose`,
  `user_id`) to `oidc_login_flows` — the table holding in-flight OIDC handshakes.
  No other table changes and no existing data is rewritten. The table is
  transient (10-minute TTL) and excluded from backup bundles, so the migration is
  fast on a database of any size. Nothing to run by hand: pull the image and
  restart.

- **Downgrading to 0.2.0 after upgrading is not supported.** The 0.2.0 image's
  migration history ends at `0008`, so it cannot start against a database
  stamped `0009` — `alembic upgrade head` fails with an unknown revision rather
  than starting with a mismatched schema. The migration's only reversal is
  dropping the two columns it added. If you may need to go back, **take a backup
  bundle before upgrading** and restore that onto 0.2.0; see
  [Backup & restore](README.md#backup--restore).

- No configuration change is required and no environment variable was added,
  removed, or renamed.

### Added

- **Link your existing account to an OIDC identity** (Settings → Authentication →
  *Your linked identity*). Enabling OIDC never connected it to the account you
  were already signed in as: the first OIDC sign-in either created a **second,
  separate account** (auto-provision on) or dead-ended at "no account is linked
  to that identity" (auto-provision off). The only workaround was to determine
  your provider's opaque `sub` by hand and write it into the database — which
  Authentik's default hashed subject mode and Entra ID's pairwise subjects do not
  let you look up at all.

  Linking now runs the same authorization-code handshake *while you are signed
  in* and binds the identity from the verified ID token to your own account.
  **Nobody types or sees a subject** — there is no such field in the API or the
  UI, by design. A guarded self-unlink completes the lifecycle.

  Both actions require **fresh full re-authentication** — your current password,
  plus a current TOTP code when enrolled — because each one changes how your
  account can be signed into, and a stolen session alone must never be able to
  add a sign-in path. Linking also **widens the accepted MFA-delegation
  limitation** from OIDC-provisioned accounts to any linked account, including
  MFA-enrolled admins — an admin with TOTP enrolled who links gains a sign-in
  path on which their local TOTP challenge never runs, so their effective second
  factor becomes whatever the identity provider enforces. This is the feature's
  main trade-off. The UI warns before you link, `auth.oidc_identity_linked` and
  `_unlinked` make the path's creation and removal auditable, and the README
  security model documents the trade in full. Confirm your identity provider
  enforces a second factor before linking an admin account. (L2 / SEC-8 — see
  [`docs/ARCHIVE.md` §15](docs/ARCHIVE.md#15-finding-id-index-decoder-for-14s-citations))

  Scope is deliberately minimal: an admin cannot bind an identity to *another*
  user (that needs the other person to authenticate at the provider), and
  email-based auto-linking is not built and not configurable — it is a
  well-known account-takeover vector. See #114.

- **A stale link now announces itself instead of resurfacing as the duplicate-account
  bug.** If your provider re-issues your identifier — the account was deleted and
  recreated, or an Authentik operator changed the provider's subject mode, which
  re-keys every user at once — the stored link silently stops matching while the
  settings screen still reads "Linked". Scrye now detects that case at sign-in
  and **refuses with a specific error** ("your identity provider issued a
  different account identifier than the one linked here"), recording
  `auth.oidc_identity_stale` in the audit log, instead of quietly minting a
  duplicate account or emitting a generic failure. It never re-binds on a name or
  email match. The linked-identity card shows when the link was last used, and
  the README carries a re-link runbook.

### Fixed

- **Every uvicorn access log line raised a `TypeError` and printed a ~50-line
  traceback in place of the line.** The secret-redaction layer was a
  `logging.Filter` that rewrote each record in place — collapsing its message and
  arguments into one pre-rendered string and clearing `record.args`. uvicorn's
  access formatter reads `record.args` directly, unpacking it into
  `(client_addr, method, full_path, http_version, status_code)`, so it hit
  `cannot unpack non-iterable NoneType object` on **every request**. Scrye itself
  was never affected — `/healthz` returned 200 throughout, because Python's
  logging routes a formatting failure to `handleError()` and carries on — so the
  only symptom was log volume, and it was substantial: with the container
  healthcheck at 30 seconds, roughly **144,000 lines/day** into Docker's
  json-file driver. On a host without log rotation that fills a disk.

  Redaction now runs on each handler's **rendered output** instead of on the log
  record, so no formatter ever sees a record we altered. Coverage is unchanged in
  intent and slightly wider in fact: the access line's client address and request
  line are rebuilt from the arguments and never appeared in the record's message,
  so they are redacted now for the first time. Access lines were **not** exempted
  — their query strings can carry a token. Present since 2026-07-04, when the
  redaction filter was first attached to uvicorn's loggers; it affected v0.1.0 and
  v0.2.0. See `docs/ARCHIVE.md` § Deviations (2026-08-02) for the full analysis,
  including why no CI check could have caught it.

- **A secret in a URL query string no longer takes the rest of the log line with
  it when redacted.** Masking a query parameter used to consume everything after
  it — on an access line that meant the HTTP version and the **status code**,
  leaving a log that cannot show a spike in 500s or someone probing for 401s.
  Redaction now bounds a query value at the delimiters a query actually has
  (`&`, `#`, whitespace, and the quote the access format puts after the path)
  rather than running to end of line, so
  `"GET /api/scans?api_token=[REDACTED] HTTP/1.1" 500` keeps everything but the
  token. Every secret in a multi-parameter query is masked individually, and
  non-secret parameters survive.

  Free-form log text still redacts to end of line, because it has no delimiters
  to stop at and a secret there may legitimately contain spaces — the bounded
  rule applies only where a real URL or path has been identified, which is what
  lets both behaviours coexist.

### Security

- **`react-router-dom` bumped 7.18.1 → 7.18.2, closing GHSA-qwww-vcr4-c8h2** (HIGH) —
  an RSC-mode CSRF bypass in which a server action could execute before the
  request was rejected with a 400. The fix was **backported to the 7 line** in
  7.18.2; the react-router 8.3.0 major that the advisory names as its only patched
  version is not required. Verified in the published tarballs rather than from the
  advisory: 7.18.2's RSC server entry is identical to 8.3.0's — the origin check is
  isolated in its own `try`, the server action is gated behind it, and a rejected
  request is rewritten to `GET` — and that backport is the entire 7.18.1 → 7.18.2
  diff.

  Scrye was never exposed: the SPA is declarative-only (`<BrowserRouter>`, no
  data-mode router, no server actions, no `@react-router/*` package), so the
  vulnerable RSC entry point is not imported and never enters the bundle, and the
  runtime image copies only the built `dist/` output. **`npm audit` and Dependabot
  will keep reporting this at 7.18.2** — the advisory's affected range still reads
  `< 8.3.0` and has not been re-cut for the backport. That is a metadata artifact,
  not a code finding; the downgrade to 7.11.0 that `npm audit fix --force` proposes
  remains the wrong move. Tracked in #123, now closed.
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

- **CodeQL code scanning moved from GitHub's default setup to a committed
  workflow** (`.github/workflows/codeql.yml`). Nothing about the analysis
  changed — same `security-extended` suite, same three languages (`python`,
  `javascript-typescript`, `actions`), same `codeql-action` version, now
  SHA-pinned. What changed is when it runs: default setup's pull-request trigger
  targets the repository's **default branch**, so PRs into `dev` — where all
  day-to-day work is PR'd — got no CodeQL check at all, and findings only
  surfaced on `main` after a promotion had already landed. It now runs on every
  pull request and push for both `dev` and `main`, plus default setup's weekly
  scan (Mondays, 04:00 UTC) so a newly published query fires on its own instead
  of waiting for someone to touch a file in that language — that cron runs
  against the default branch, as all scheduled workflows do. Deliberately
  carries no `paths:` filters: a required check whose workflow never triggers
  blocks a PR forever. No change to a deployed Scrye.
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

[Unreleased]: https://github.com/tyler-rich/Scrye/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/tyler-rich/Scrye/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tyler-rich/Scrye/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tyler-rich/Scrye/releases/tag/v0.1.0
