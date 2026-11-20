import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// `npm run dev:web` proxies the API to a local server (CENTRALD_DEV_SERVER,
// default https://127.0.0.1:7443). The dev proxy rewrites Origin so the
// server's same-origin guard accepts it.
const target = process.env.CENTRALD_DEV_SERVER ?? "https://127.0.0.1:7443";

export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
  server: {
    proxy: {
      "/api": {
        target,
        secure: false,
        ws: true,
        changeOrigin: true,
        headers: { origin: target },
      },
    },
  },
});
