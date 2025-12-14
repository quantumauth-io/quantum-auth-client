import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/healthz": "http://127.0.0.1:6137",
      "/status": "http://127.0.0.1:6137",
      "/agent": "http://127.0.0.1:6137",
      "/pair": "http://127.0.0.1:6137",
    },
  },
});