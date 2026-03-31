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

RUN ./node_modules/.bin/tsc -p backend/tsconfig.json

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

RUN rm -rf /usr/local/lib/node_modules/npm \
    /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm \
    /usr/local/bin/npx \
    /usr/local/bin/corepack

COPY --from=prod-deps /repo/node_modules /repo/node_modules
COPY --from=prod-deps /repo/backend/package.json ./package.json
COPY --from=build /repo/backend/dist ./dist

ENV PORT=3001
ENV NODE_ENV=production

CMD ["sh", "-c", "node --experimental-specifier-resolution=node dist/shared/db/migrate.js && node --experimental-specifier-resolution=node dist/index.js"]