# infra/oidc-server/Dockerfile
#
# WHY:
# - The local OIDC server is a pure Node.js script with zero npm dependencies.
# - node:20-alpine is the smallest official image that ships Node 20.
# - No build step, no package install — just copy the single script and run it.
# - Only used in CI Docker stack (docker-compose-ci.yml). Never deployed to production.

FROM node:20-alpine

WORKDIR /app

COPY server.mjs ./

# Run as non-root
USER node

EXPOSE 9998

CMD ["node", "server.mjs"]
