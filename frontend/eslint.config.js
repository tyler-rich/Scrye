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
      ...reactHooks.configs.recommended.rules,
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
