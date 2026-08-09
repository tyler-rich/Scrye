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
      // The one rule from that set held back. It reports 18 sites, and only 6
      // are the synchronous setState-in-effect the rule's rationale describes;
      // those 6 are tracked in #176 and must be refactored before this override
      // is removed. Two of them (ScanDetailPage's :scanId reset, L17/P2-2, and
      // ScansPage's compare reconcile, P3-2) are deliberate effects that each
      // closed a real bug — #176 says so, so they don't get "fixed" blind.
      //
      // The other 12 are the fetch-on-mount idiom, where every setState runs
      // after an await. They are not what this rule is for: with `load` defined
      // in the component body `void load()` reports while the semantically
      // identical `void (async () => { await load(); })()` does not, and moving
      // `load` behind a custom hook silences every shape — so the report tracks
      // what the compiler can see, not a behavioural difference. Deliberately
      // not in #176: there is no fix there that is an improvement.
      'react-hooks/set-state-in-effect': 'off',
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
