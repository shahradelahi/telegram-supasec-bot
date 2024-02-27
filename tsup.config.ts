import { defineConfig } from 'tsup';

export default defineConfig({
  clean: true,
  entry: ['server.ts'],
  format: ['esm'],
  //   banner: {
  //     js: `\
  // const require = (await import("node:module")).createRequire(import.meta.url);
  // const __filename = (await import("node:url")).fileURLToPath(import.meta.url);
  // const __dirname = (await import("node:path")).dirname(__filename);`
  //   },
  inject: ['cjs-shim.ts'],
  platform: 'node',
  target: 'esnext',
  outDir: 'dist'
});
