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

FROM node:20-alpine AS base
RUN corepack enable

# ── Stage 1: install workspace deps from the repo root lockfile ──────────────
FROM base AS deps
WORKDIR /repo

COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn ./.yarn
COPY frontend/package.json frontend/package.json
COPY backend/package.json backend/package.json
RUN yarn install --immutable

# ── Stage 2: build the Next.js app ───────────────────────────────────────────
FROM base AS builder
WORKDIR /repo

COPY --from=deps /repo ./
COPY frontend ./frontend

ENV NEXT_PUBLIC_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

WORKDIR /repo/frontend
RUN yarn build

# ── Stage 3: minimal production image ────────────────────────────────────────
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /repo/frontend/public ./public
COPY --from=builder --chown=nextjs:nodejs /repo/frontend/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /repo/frontend/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME=0.0.0.0

CMD ["node", "server.js"]