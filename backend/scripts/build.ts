/**
 * backend/scripts/build.ts
 *
 * WHY esbuild instead of tsc:
 * - tsconfig.json uses "moduleResolution": "Bundler" — correct for a bundler
 *   pipeline, but tsc is not a bundler. tsc only transpiles; it emits bare
 *   relative imports like `from './db'` unchanged. Node.js ESM (strict, Node
 *   20+) requires explicit .js extensions. The --experimental-specifier-
 *   resolution=node flag that previously papered this over was removed in
 *   Node 20. esbuild resolves and inlines all local src/ imports at build time,
 *   producing self-contained output. tsc --noEmit continues to enforce types in
 *   CI as a separate, independent step — esbuild intentionally does zero type
 *   checking. tsx remains unchanged for all local dev and seeding scripts.
 *
 * WHY sourcemaps (sourcemap: 'linked'):
 * - @sentry/node is initialised in server.ts. Without sourcemaps every Sentry
 *   stack trace shows bundled output line numbers, not TypeScript source lines.
 *   Production debugging is effectively blind without them.
 * - 'linked' emits a companion .js.map next to each .js and appends a
 *   `//# sourceMappingURL=` comment. Node.js and @sentry/node locate them
 *   automatically — no extra configuration. The .map files are copied into the
 *   production image alongside the .js files. This lets @sentry/node resolve
 *   TypeScript source context locally. The graduation path when a proper CI
 *   release pipeline exists is to additionally upload sourcemaps to Sentry via
 *   Sentry CLI and set a pinned SERVICE_VERSION — the groundwork is already
 *   here (server.ts already passes release: serviceVersion to Sentry.init).
 *
 * OUTPUT STRUCTURE:
 * - dist/index.js [+ .map]
 *     Fully bundled application server. All local src/ imports inlined.
 *     node_modules are kept external — they live in /repo/node_modules at
 *     runtime (installed by the prod-deps Docker stage).
 *
 * - dist/shared/db/migrate.js [+ .map]
 *     Fully bundled migration runner. Its local deps (db, config, logger) are
 *     inlined. Migration files are NOT inlined here (see next entry).
 *
 * - dist/shared/db/migrations/*.js [+ .map]
 *     Individual migration files compiled as separate modules. They MUST remain
 *     separate because migrate.ts discovers and imports them at runtime via
 *     dynamic import(pathToFileURL(fullPath)) by scanning the migrations
 *     directory on disk — they cannot be bundled into migrate.js.
 *
 * INVARIANTS:
 * - `packages: 'external'`  — never inline node_modules. bcrypt has native
 *   bindings; inlining would break it. prod-deps handles runtime deps.
 * - `format: 'esm'`         — matches "type": "module" in backend/package.json.
 * - `target: 'node20'`      — matches the container runtime (node:20-bookworm-slim).
 * - `bundle: true`          — the flag that actually resolves bare relative imports.
 * - `sourcemap: 'linked'`   — companion .map files, not inline, not hidden.
 */

import { build, type BuildOptions } from 'esbuild';
import { readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

const sharedConfig: BuildOptions = {
  platform: 'node',
  format: 'esm',
  target: 'node20',
  bundle: true,
  // WHY sourcemap: 'linked':
  // @sentry/node is initialised in server.ts. Without sourcemaps every Sentry
  // stack trace shows esbuild output line numbers — not TypeScript source lines.
  // 'linked' generates a companion .js.map file next to each .js file and
  // appends a `//# sourceMappingURL=` comment so Node.js and Sentry locate them
  // automatically. The .map files are copied into the production image and
  // @sentry/node resolves TypeScript source context locally without requiring a
  // Sentry CLI upload step (recommended graduation path once a CI release
  // pipeline is in place).
  sourcemap: 'linked',
  // Never inline node_modules. Production deps are installed separately into
  // /repo/node_modules by the prod-deps Docker stage and mounted at runtime.
  // bcrypt has native bindings — inlining would break it.
  packages: 'external',
};

// ── 1. Main application server ─────────────────────────────────────────────
await build({
  ...sharedConfig,
  entryPoints: [path.join(root, 'src/index.ts')],
  outfile: path.join(root, 'dist/index.js'),
});
console.log('✓ dist/index.js + .map');

// ── 2. Migration runner ────────────────────────────────────────────────────
// Bundled standalone so it can be invoked as `node dist/shared/db/migrate.js`
// before the server starts. Its local deps (db, config, logger) are inlined.
// The migration files it loads are NOT inlined — they're in the next step.
await build({
  ...sharedConfig,
  entryPoints: [path.join(root, 'src/shared/db/migrate.ts')],
  outfile: path.join(root, 'dist/shared/db/migrate.js'),
});
console.log('✓ dist/shared/db/migrate.js + .map');

// ── 3. Individual migration files ──────────────────────────────────────────
// migrate.ts scans dist/shared/db/migrations/ at runtime and imports each file
// via its absolute filesystem URL (pathToFileURL). They must exist as separate
// compiled modules on disk — they cannot be bundled into migrate.js.
const migrationsDir = path.join(root, 'src/shared/db/migrations');
const migrationFiles = (await readdir(migrationsDir))
  .filter((f) => f.endsWith('.ts'))
  .map((f) => path.join(migrationsDir, f));

await build({
  ...sharedConfig,
  entryPoints: migrationFiles,
  outdir: path.join(root, 'dist/shared/db/migrations'),
});
console.log(`✓ dist/shared/db/migrations/ (${migrationFiles.length} files + maps)`);

console.log('\nBuild complete.');
