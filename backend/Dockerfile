# backend/Dockerfile
#
# WHY:
# - Containerises the Fastify backend for the full Docker topology.
# - Uses the repo root Yarn workspace + lockfile as the single dependency truth.
# - Runs migrations before starting the server.
#
# RULES:
# - Build context is the REPO ROOT (see infra/docker-compose.yml).
# - Backend listens on PORT (3001 in stack mode).
# - All secret env vars are injected by docker-compose — never hardcoded here.
# - The container does NOT expose ports to the host — only the proxy does.

FROM node:20-alpine

RUN apk add --no-cache wget && corepack enable

WORKDIR /repo

# Install dependencies from the repo-root workspace/lockfile so container builds
# use the same package-manager truth as local development.
COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn ./.yarn
COPY backend/package.json backend/package.json
COPY frontend/package.json frontend/package.json
RUN yarn install --immutable

# Copy only the backend source needed at runtime.
COPY backend ./backend

ENV PORT=3001
ENV NODE_ENV=development

CMD ["sh", "-c", "yarn workspace @auth-lab/backend db:migrate && yarn workspace @auth-lab/backend start:container"]