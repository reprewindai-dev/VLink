import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: "dist/client" },
  base: "/vlink/connect/",
  // Only these two non-secret origins cross into the client bundle; every other VLINK_* value
  // (sealing keys, LockerPhycer URL, ...) stays server-side. Prefixes are matched by startsWith.
  envPrefix: ["VITE_", "VLINK_PUBLIC_ORIGIN", "VLINK_ACCOUNT_ORIGIN"],
});
