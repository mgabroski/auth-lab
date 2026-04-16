# cp/Dockerfile
#
# WHY:
# - Used ONLY in the full Docker topology stack (scripts/stack.sh).
# - Uses the repo root Yarn workspace + lockfile as the single dependency truth.
# - NOT used in host-run dev mode (yarn dev:cp runs Next.js directly on the host).
#
# TOPOLOGY:
#   Browser → Caddy/nginx → cp:3002      (/* and /_next/*)
#                      → backend:3001    (/api/*)
#
# RULES:
# - Build context is the REPO ROOT (see infra/docker-compose.yml).
# - Multi-stage build: deps → builder → runner.
# - output: 'standalone' in cp/next.config.ts is REQUIRED for this image to work.
# - INTERNAL_API_URL is required for SSR/server-side CP → backend calls.
# - The same Docker-internal backend URL is supplied at build time and runtime.

FROM node:24.14.1-alpine AS base
RUN corepack enable

# ── Stage 1: install workspace deps from the repo root lockfile ──────────────
FROM base AS deps
WORKDIR /repo

COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn ./.yarn
COPY cp/package.json cp/package.json
COPY backend/package.json backend/package.json
COPY frontend/package.json frontend/package.json
RUN yarn install --immutable

# ── Stage 2: build the Next.js CP app ────────────────────────────────────────
FROM base AS builder
WORKDIR /repo

COPY --from=deps /repo ./
COPY cp ./cp

ENV NEXT_TELEMETRY_DISABLED=1

# WHY ARG + ENV here:
# cp/next.config.ts validates INTERNAL_API_URL in non-development builds.
# The actual runtime value is still injected by docker-compose.yml, but the build
# must use the same internal backend URL so the startup contract stays truthful.
ARG INTERNAL_API_URL=http://backend:3001
ENV INTERNAL_API_URL=${INTERNAL_API_URL}

WORKDIR /repo/cp
RUN yarn build

# ── Stage 3: minimal production image ────────────────────────────────────────
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder --chown=nextjs:nodejs /repo/cp/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /repo/cp/.next/static ./cp/.next/static

USER nextjs

EXPOSE 3002

ENV PORT=3002
ENV HOSTNAME=0.0.0.0

CMD ["node", "cp/server.js"]