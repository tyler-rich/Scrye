/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// During development the SPA runs on the Vite dev server and proxies API calls
// to the FastAPI backend so the browser sees a single same-origin app.
const API_TARGET = process.env.SCRYE_DEV_API_TARGET ?? 'http://localhost:8089';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/healthz': API_TARGET,
      '/api': API_TARGET,
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
  test: {
    // Two test environments live side by side, split by file extension so each
    // suite runs under the lightest harness that fits:
    //   *.test.ts  → pure-helper tests (e.g. src/lib/), run under Node.
    //   *.test.tsx → component/page render tests, run under jsdom with React
    //                Testing Library (see src/test/).
    // The extension split keeps the existing lib/ helper tests untouched — they
    // never pay for the DOM harness — while giving page tests a real DOM.
    projects: [
      {
        extends: true,
        test: {
          name: 'node',
          environment: 'node',
          include: ['src/**/*.test.ts'],
        },
      },
      {
        extends: true,
        test: {
          name: 'jsdom',
          environment: 'jsdom',
          include: ['src/**/*.test.tsx'],
          setupFiles: ['./src/test/setup.ts'],
        },
      },
    ],
  },
});
