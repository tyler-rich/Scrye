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
});
