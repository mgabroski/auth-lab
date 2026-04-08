# cp/Dockerfile
#
# WHY:
# - Used ONLY in the full Docker topology stack (scripts/stack.sh).
# - Uses the repo root Yarn workspace + lockfile as the single dependency truth.
# - NOT used in host-run dev mode (yarn dev:cp runs Next.js directly on the host).
#
# TOPOLOGY:
#   Caddy:3000 (cp.lvh.me:3000) → cp:3002 (/*)
#
# RULES:
# - Build context is the REPO ROOT (see infra/docker-compose.yml).
# - Multi-stage build: deps → builder → runner.
# - output: 'standalone' in cp/next.config.ts is REQUIRED for this image to work.
# - CP has no INTERNAL_API_URL dependency in Phase 1 (no backend calls yet).
#   This will change when Phase 2 backend APIs are wired.

FROM node:20-alpine AS base
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