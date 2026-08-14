import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist'] },
  {
    // `recommendedTypeChecked` (not plain `recommended`) so the rules that need
    // type information are active — chiefly `no-floating-promises` and
    // `no-misused-promises`, which catch a rejected promise nobody is waiting on
    // (P3-8). `projectService` resolves each file to its owning tsconfig
    // (`tsconfig.app.json` for `src/`, `tsconfig.node.json` for the Vite/Vitest
    // config), so tests are type-linted alongside app code.
    extends: [js.configs.recommended, ...tseslint.configs.recommendedTypeChecked],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      // The two classic hook rules plus the React Compiler rule set — under
      // eslint-plugin-react-hooks 7.x this is 16 rules, where 5.1.0 contributed
      // only `rules-of-hooks` and `exhaustive-deps`. Adopted deliberately; see
      // docs/upgrades/frontend-toolchain-86.md, Step 3.
      ...reactHooks.configs.recommended.rules,
      // The one rule from that set not at its preset severity ('error'). #176's
      // six genuine synchronous-setState sites are all refactored away; the 13
      // reports that remain are all the fetch-on-mount idiom, where every
      // setState runs after an await (12 loaders, plus ScanDetailPage's
      // `void loadFindings()`, which kept reporting after its synchronous flip
      // was removed). Those reports track what the compiler can see, not a
      // behavioural difference: `void load()` reports while the semantically
      // identical `void (async () => { await load(); })()` does not, and moving
      // `load` behind a custom hook silences every shape — so there is no fix
      // for them that is an actual improvement, only ways to hide them.
      //
      // 'warn' is a maintainer decision (2026-08-11, closing out #176) in
      // preference to 13 per-site disables or a data-fetching refactor: the
      // known reports stay visible in lint output without failing it (`npm run
      // lint` sets no --max-warnings). The cost is that a NEW report from this
      // rule also arrives as a warning — and a genuine synchronous
      // setState-in-effect looks exactly like these — so any change in this
      // rule's report count is worth reading in review, not scrolling past.
      // See docs/ARCHIVE.md §14, 2026-08-11 (#176 part 2).
      'react-hooks/set-state-in-effect': 'warn',
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
    },
  },
  {
    // Test files and shared test utilities are not part of the app's
    // Fast-Refresh graph, so the "only export components" rule doesn't apply —
    // test-utils legitimately mix a render wrapper with re-exported helpers.
    files: ['**/*.test.{ts,tsx}', 'src/test/**/*.{ts,tsx}'],
    rules: {
      'react-refresh/only-export-components': 'off',
    },
  },
);
