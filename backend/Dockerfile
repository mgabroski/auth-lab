# backend/Dockerfile
#
# WHY:
# - Containerises the Fastify backend for the full Docker topology.
# - Uses the repo root Yarn workspace + lockfile as the single dependency truth.
# - Builds backend TypeScript once, then runs compiled JS in the final image.
# - Installs only backend production dependencies in the runtime image.
# - Runs migrations before starting the server.
#
# RULES:
# - Build context is the REPO ROOT (see infra/docker-compose.yml).
# - Backend listens on PORT (3001 in stack mode).
# - All secret env vars are injected by docker-compose — never hardcoded here.
# - The container does NOT expose ports to the host — only the proxy does.

FROM node:20-bookworm-slim AS base

RUN corepack enable

WORKDIR /repo

# ── Stage 1: install full backend-focused deps for build/type tooling ──────────
FROM base AS deps

COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn ./.yarn
COPY backend/package.json backend/package.json
COPY frontend/package.json frontend/package.json

RUN yarn workspaces focus @auth-lab/backend

# ── Stage 2: compile backend TypeScript ────────────────────────────────────────
FROM deps AS build

COPY backend ./backend

# WHY esbuild instead of tsc:
# tsconfig.json uses "moduleResolution": "Bundler" — correct, but means a real
# bundler must resolve local imports at build time. tsc only transpiles; it emits
# bare imports like `from './db'` unchanged. Node.js ESM (strict, Node 20+)
# requires explicit .js extensions, and --experimental-specifier-resolution=node
# which previously papered this over was removed in Node 20. esbuild resolves and
# inlines all local src/ imports, producing self-contained output. node_modules
# are kept external (packages:'external') — they are installed separately in the
# prod-deps stage. tsc --noEmit continues to enforce types in CI independently.
RUN ./node_modules/.bin/tsx backend/scripts/build.ts

# ── Stage 3: install production-only backend deps ──────────────────────────────
FROM base AS prod-deps

COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn ./.yarn
COPY backend/package.json backend/package.json
COPY frontend/package.json frontend/package.json

RUN yarn workspaces focus @auth-lab/backend --production

# ── Stage 4: runtime image ─────────────────────────────────────────────────────
FROM node:20-bookworm-slim AS runner

WORKDIR /repo/backend

# WHY non-root user:
# - Running as root in a container means a process escape grants root on the host.
# - CIS Docker Benchmark §4.1 requires containers to not run as root.
# - The frontend runner already follows this pattern (nextjs:nodejs, uid/gid 1001).
#   The backend must be consistent — same uid/gid prevents permission conflicts
#   if a shared volume is ever mounted across both containers.
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 backend --ingroup nodejs

RUN rm -rf /usr/local/lib/node_modules/npm \
    /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm \
    /usr/local/bin/npx \
    /usr/local/bin/corepack

COPY --from=prod-deps /repo/node_modules /repo/node_modules
COPY --from=prod-deps /repo/backend/package.json ./package.json
# WHY --chown: dist/ and its .map files must be readable by the backend user.
# node_modules remain root-owned (755/644 defaults) — readable by all users.
COPY --chown=backend:nodejs --from=build /repo/backend/dist ./dist

USER backend

ENV PORT=3001
ENV NODE_ENV=production

# WHY no flags: esbuild bundles all local src/ imports at build time. dist/migrate.js
# and dist/index.js are fully self-contained — Node.js ESM resolves them without
# --experimental-specifier-resolution=node (removed in Node 20).
# WHY migrate first: migrations run to completion before the server binds its port.
# The healthcheck only starts polling after the CMD process starts, so the server
# never receives traffic against a stale schema.
CMD ["sh", "-c", "node dist/shared/db/migrate.js && node dist/index.js"]