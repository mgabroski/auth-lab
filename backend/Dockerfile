# backend/Dockerfile
#
# WHY:
# - Containerises the Fastify backend for the full Docker topology.
# - Uses the repo root Yarn workspace + lockfile as the single dependency truth.
# - Installs only the backend-focused workspace dependency tree.
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

# ── Stage 1: install only backend-focused workspace deps ──────────────────────
FROM base AS deps

COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn ./.yarn
COPY backend/package.json backend/package.json
COPY frontend/package.json frontend/package.json

RUN yarn workspaces focus @auth-lab/backend

# ── Stage 2: runtime image ─────────────────────────────────────────────────────
FROM node:20-bookworm-slim AS runner

WORKDIR /repo

# npm/corepack are not needed at runtime because we execute tsx directly.
RUN rm -rf /usr/local/lib/node_modules/npm \
    /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm \
    /usr/local/bin/npx \
    /usr/local/bin/corepack

COPY --from=deps /repo/node_modules ./node_modules
COPY --from=deps /repo/backend/package.json backend/package.json
COPY backend ./backend

ENV PORT=3001
ENV NODE_ENV=development

CMD ["sh", "-c", "./node_modules/.bin/tsx backend/src/shared/db/migrate.ts && ./node_modules/.bin/tsx backend/src/index.ts"]