import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: "../dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      // lancer-api serves /v1/* (no /api prefix); strip /api when proxying so
      // the GUI's /api/v1/* calls reach /v1/* on the backend.
      "/api": {
        target: "http://127.0.0.1:9191",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
});
