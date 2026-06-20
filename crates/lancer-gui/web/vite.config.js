import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";

// Dev-only parity for the "Open Browser" button.
// In production the GUI server (lancer-gui) serves POST /api/browser/open itself,
// but the vite dev server proxies /api/* to lancer-api — which has no such route,
// so the button 404s under `npm run dev`. This plugin reproduces the launch
// (Chrome/Edge pre-configured to use Lancer's proxy) so the button works in dev.
function devBrowserOpen() {
  const ENV = process.env;
  const candidates = [
    ENV.LANCER_BROWSER, // explicit override, if set
    ENV.PROGRAMFILES && `${ENV.PROGRAMFILES}\\Google\\Chrome\\Application\\chrome.exe`,
    ENV["PROGRAMFILES(X86)"] && `${ENV["PROGRAMFILES(X86)"]}\\Google\\Chrome\\Application\\chrome.exe`,
    ENV.LOCALAPPDATA && `${ENV.LOCALAPPDATA}\\Google\\Chrome\\Application\\chrome.exe`,
    ENV.PROGRAMFILES && `${ENV.PROGRAMFILES}\\Microsoft\\Edge\\Application\\msedge.exe`,
    ENV["PROGRAMFILES(X86)"] && `${ENV["PROGRAMFILES(X86)"]}\\Microsoft\\Edge\\Application\\msedge.exe`,
  ].filter(Boolean);
  // Keep the throwaway browser profile off C:\ per the project's drive rule.
  const PROFILE = ENV.LANCER_BROWSER_PROFILE || "D:\\lancer-browser";

  return {
    name: "lancer-dev-browser-open",
    configureServer(server) {
      // Registered in configureServer => runs before vite's /api proxy middleware.
      server.middlewares.use("/api/browser/open", (req, res, next) => {
        if (req.method !== "POST") return next();
        const args = [
          "--proxy-server=127.0.0.1:8080",
          "--ignore-certificate-errors",
          `--user-data-dir=${PROFILE}`,
          "--no-first-run",
          "--no-default-browser-check",
        ];
        let ok = false;
        const bin = candidates.find((p) => {
          try { return existsSync(p); } catch { return false; }
        });
        try {
          const child = bin
            ? spawn(bin, args, { detached: true, stdio: "ignore" })
            : spawn("cmd", ["/C", "start", "", "chrome", ...args], { detached: true, stdio: "ignore" });
          child.on("error", () => {});
          child.unref();
          ok = true;
        } catch {
          ok = false;
        }
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ ok, via: bin || "cmd:start" }));
      });
    },
  };
}

export default defineConfig({
  plugins: [svelte(), devBrowserOpen()],
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
