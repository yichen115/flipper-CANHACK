import { defineConfig } from "vite";

export default defineConfig({
  root: "web",
  server: {
    proxy: {
      "/ws": { target: "http://127.0.0.1:8765", ws: true },
    },
  },
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    chunkSizeWarningLimit: 550,
    rollupOptions: {
      output: {
        manualChunks: {
          three: ["three"],
          lucide: ["lucide"],
        },
      },
    },
  },
});
