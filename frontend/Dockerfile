# frontend/Dockerfile
#
# WHY:
# - Used ONLY in the full Docker topology stack (scripts/stack.sh).
# - Uses the repo root Yarn workspace + lockfile as the single dependency truth.
# - NOT used in host-run dev mode (yarn dev runs Next.js directly on the host).
#
# TOPOLOGY:
#   Browser → Caddy:3000 → frontend:3000 (/* and /_next/*)
#                        → backend:3001  (/api/*)
#
# RULES:
# - Build context is the REPO ROOT (see infra/docker-compose.yml).
# - Multi-stage build: deps → builder → runner.
# - output: 'standalone' in next.config.ts is REQUIRED for this image to work.
# - INTERNAL_API_URL is injected at container runtime (docker-compose.yml).
#   It is NOT baked in at build time — Next.js SSR reads it at request time.

FROM node:20-bookworm-slim AS base
RUN corepack enable

# ── Stage 1: install focused frontend workspace deps from the repo root ───────
FROM base AS deps
WORKDIR /repo

COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn ./.yarn
COPY frontend/package.json frontend/package.json
COPY backend/package.json backend/package.json
RUN yarn workspaces focus frontend

# ── Stage 2: build the Next.js app ────────────────────────────────────────────
FROM base AS builder
WORKDIR /repo

COPY --from=deps /repo ./
COPY frontend ./frontend

ENV NEXT_PUBLIC_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# WHY ARG + ENV here:
# next.config.ts validates INTERNAL_API_URL at startup, which includes during
# `next build` (Next.js sets NODE_ENV=production internally for the build process).
# The actual runtime value is injected by docker-compose.yml at container start.
# This build arg satisfies the startup check without baking a real URL into the image.
# The value used here is the Docker-internal backend service name — the same value
# that will be set at runtime via docker-compose environment.
ARG INTERNAL_API_URL=http://backend:3001
ENV INTERNAL_API_URL=${INTERNAL_API_URL}

WORKDIR /repo/frontend
RUN yarn build

# ── Stage 3: minimal production image ─────────────────────────────────────────
FROM node:20-bookworm-slim AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# npm/corepack are not needed in the standalone runtime image.
RUN rm -rf /usr/local/lib/node_modules/npm \
    /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm \
    /usr/local/bin/npx \
    /usr/local/bin/corepack

COPY --from=builder /repo/frontend/public ./public
COPY --from=builder --chown=nextjs:nodejs /repo/frontend/.next/standalone ./
# WHY frontend/.next/static not .next/static:
# outputFileTracingRoot points to the repo root, so Next.js standalone output
# mirrors the repo structure. server.js lands at /app/frontend/server.js and
# expects static files at /app/frontend/.next/static — not /app/.next/static.
COPY --from=builder --chown=nextjs:nodejs /repo/frontend/.next/static ./frontend/.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME=0.0.0.0

CMD ["node", "frontend/server.js"]