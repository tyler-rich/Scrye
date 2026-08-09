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
      // These two are exactly what `reactHooks.configs.recommended.rules`
      // contained under eslint-plugin-react-hooks 5.1.0, which this spread used
      // to pull in. Written out because 7.x's `configs.recommended` folds in the
      // React Compiler rule set on top of them, and adopting that is a separate
      // decision — see docs/upgrades/frontend-toolchain-86.md, Step 3.
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
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
