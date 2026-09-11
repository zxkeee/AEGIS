import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// The console is embedded into the Go binary and served from the admin plane
// root. Relative asset paths keep it origin-agnostic; a single JS + CSS bundle
// keeps the CSP simple (script-src 'self', one file family). The names are
// deliberately NOT content-hashed: the built bundle is committed so `go build`
// works without Node, and hashed names would rewrite every filename on every
// build. The server revalidates with an ETag instead — see serveConsoleAsset.
export default defineConfig({
  plugins: [react()],
  base: "./",
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  build: {
    // Emit straight into the Go package so the console is embedded via go:embed
    // (which cannot reference paths outside its package dir). Committed so
    // `go build` works without Node.
    outDir: "../../internal/api/console_dist",
    emptyOutDir: true,
    cssCodeSplit: false,
    modulePreload: { polyfill: false },
    rollupOptions: {
      output: {
        entryFileNames: "assets/console.js",
        chunkFileNames: "assets/console-[name].js",
        assetFileNames: "assets/console.[ext]",
      },
    },
  },
  server: {
    // `npm run dev` proxies the admin API to a locally running gateway.
    proxy: {
      "/api": "http://127.0.0.1:8081",
      "/metrics": "http://127.0.0.1:8081",
    },
  },
});
