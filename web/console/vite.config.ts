import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// The console is embedded into the Go binary and served from the admin plane
// root. Relative asset paths keep it origin-agnostic; a single JS + CSS bundle
// keeps the CSP simple (script-src 'self', one file family).
//
// The ENTRY names (console.js, console.css) are deliberately constant: the built
// bundle is committed so `go build` works without Node, and a hash in the entry
// name would rewrite the filename the server hard-codes on every build. The
// server revalidates those with an ETag instead — see serveConsoleAsset.
//
// Every other asset IS content-hashed, for the opposite reason: see the note on
// assetFileNames below. Sequential names made a no-op rebuild rewrite 58 files.
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
        // The JS and CSS entries keep constant names (see the note above); every
        // OTHER asset — the fonts, ~56 of them — is named by a hash of its
        // CONTENT.
        //
        // "assets/console.[ext]" gave them sequential names (console9.woff,
        // console10.woff, …) assigned in build order, and that order is not
        // stable: a rebuild with no source change rewrote 58 files, shuffling
        // which bytes lived under which name. That made `git diff --exit-code`
        // useless as a check that the committed bundle matches the lockfile,
        // which in turn meant a dependency bump could change the console's
        // inputs while the embedded bundle silently stayed as it was.
        //
        // Content hashing makes an unchanged font keep its name, so a rebuild
        // is a no-op in git and a real change shows up as exactly the files
        // that changed.
        assetFileNames: (info) => {
          const name = info.names?.[0] ?? info.name ?? "";
          if (name.endsWith(".css")) return "assets/console.css";
          return "assets/[name]-[hash][extname]";
        },
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
