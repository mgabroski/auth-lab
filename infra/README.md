# infra/

Infrastructure configuration for Hubins Auth-Lab.

This folder defines the local and reference deployment topology for the current foundation phase.

Read this together with:

- `README.md`
- `docs/current-foundation-status.md`
- `ARCHITECTURE.md`
- `docs/decision-log.md`

---

## Purpose of this folder

This folder exists to support two different but complementary needs:

1. **daily local development** where backend/frontend run on the host and only infra is containerized
2. **full topology validation** where the app runs behind the intended local proxy shape

Neither mode replaces the other.
They prove different things.

---

## Local modes

There are intentionally two local modes.

## Mode 1 — host-run (daily development)

Command from repo root:

```bash
yarn dev
```

### What actually runs

- Postgres in Docker
- Redis in Docker
- Mailpit in Docker
- local OIDC helper in Docker
- backend on the host (`localhost:3001`)
- frontend on the host

### Canonical browser URL

Use:

```text
http://goodwill-ca.lvh.me:3000
```

Do **not** use plain `localhost:3000` when testing tenant-aware behavior.

### What host-run mode proves

- backend ↔ Postgres / Redis local wiring
- Mailpit local email capture
- SSR direct-backend communication through `INTERNAL_API_URL`
- browser same-origin `/api/*` usage through the local Next Route Handler proxy
- tenant-aware browser behavior when using the correct tenant host
- local OIDC availability for auth-related local proof

### What host-run mode does not prove

- real Caddy proxy behavior
- real `/api` prefix stripping through the public proxy layer
- real `X-Forwarded-*` handling through Caddy
- full cookie/proxy behavior for the public stack shape
- final topology conformance

Host-run mode is the daily work mode, not the final topology-proof mode.

---

## Mode 2 — full Docker topology

You have two entry paths depending on what you need.

### A. Standard full topology

```bash
yarn stack
```

This uses `infra/docker-compose.yml`.

### B. Full topology plus local OIDC helper

```bash
yarn dev:stack
```

This uses:

- `infra/docker-compose.yml`
- `infra/docker-compose-ci-oidc.yml`

Use `yarn dev:stack` when you want the full Docker topology and also need the local OIDC helper available in that stack.

### Public full-stack entrypoint

```text
http://goodwill-ca.lvh.me:3000
```

### What full-stack mode proves

- Caddy proxy behavior
- `/api/*` routing through the proxy
- `/api` prefix stripping
- public-origin browser behavior through the proxy layer
- host-derived tenant routing through the public stack shape
- forwarded-header behavior through the proxy path
- proxy conformance checks against the real local topology

### What full-stack mode still does not prove

The local full stack is still HTTP-only.
It does **not** fully prove:

- production HTTPS behavior
- real `__Host-` cookie prefix enforcement by browsers
- final production TLS termination behavior

That is expected.
The local stack is for topology proof, not for pretending local HTTP equals production HTTPS.

---

## Recommended validation flow

### Daily feature loop

```bash
yarn dev
```

### Repo-level checks before push / merge

```bash
yarn verify
```

### Topology-sensitive changes

```bash
yarn stack
yarn stack:test
```

Or, if your test path depends on the local OIDC helper inside the full stack:

```bash
yarn dev:stack
yarn stack:test
```

Use all three levels appropriately:

- `yarn dev` for normal iteration
- `yarn verify` for format/lint/typecheck/test proof
- `yarn stack:test` for topology-sensitive proof

Important truth note:

`yarn verify` currently runs:

- format check
- lint
- typecheck
- tests

It does **not** run a frontend production build.
If you want build proof, run it separately.

---

## Topology-sensitive changes that require full-stack proof

Run full-stack proof before merging changes that affect:

- `infra/`
- proxy config
- request context / tenant resolution
- session/cookie behavior
- SSR forwarded-header behavior
- SSO callback/start assumptions
- browser vs SSR communication assumptions
- public-origin path handling under `/api/*`

If the change touches one of those areas, host-run mode alone is not enough.

---

## Commands in practice

### Start host-run mode

```bash
yarn dev
```

### Start full Docker topology

```bash
yarn stack
```

### Start full Docker topology plus local OIDC helper

```bash
yarn dev:stack
```

### Run proxy conformance tests

```bash
yarn stack:test
```

### Stop Docker-backed local modes

```bash
yarn stop
```

### Check local topology status

```bash
yarn status
```

### Reset local Docker volumes

```bash
yarn reset-db
```

---

## Files in this folder

| File                         | Purpose                                                    |
| ---------------------------- | ---------------------------------------------------------- |
| `docker-compose.yml`         | full Docker stack: proxy + frontend + backend + core infra |
| `docker-compose-infra.yml`   | infra-only stack for host-run mode                         |
| `docker-compose-ci-oidc.yml` | local OIDC helper overlay used by `yarn dev:stack`         |
| `caddy/Caddyfile`            | local reverse-proxy topology                               |
| `nginx/nginx.conf`           | production/reference reverse-proxy config                  |

---

## Canonical local URLs

### Host-run mode

| Surface         | URL                                           |
| --------------- | --------------------------------------------- |
| Public app      | `http://goodwill-ca.lvh.me:3000`              |
| Backend health  | `http://localhost:3001/health`                |
| Mailpit UI      | `http://localhost:8025`                       |
| Local OIDC JWKS | `http://localhost:9998/.well-known/jwks.json` |

### Full-stack mode

| Surface                  | URL                                         |
| ------------------------ | ------------------------------------------- |
| Public app               | `http://goodwill-ca.lvh.me:3000`            |
| Backend health via proxy | `http://goodwill-ca.lvh.me:3000/api/health` |

`lvh.me` resolves to `127.0.0.1`, so no `/etc/hosts` edits are needed.

---

## Local development credentials

### Postgres (dev only)

| Key      | Value      |
| -------- | ---------- |
| Database | `auth_lab` |
| User     | `auth_lab` |
| Password | `auth_lab` |

These are local-development credentials only.
Never reuse them in production.

---

## Practical truth rules

- Host-run mode is the fastest daily loop, but it is not final topology proof.
- Full-stack mode is required for proxy-sensitive changes.
- `yarn verify` is a repo verification gate, not a deployment simulation.
- `yarn verify` does not currently perform a frontend production build.
- `lvh.me` is the canonical tenant-aware browser host in both local modes.
- If you test tenant behavior on plain `localhost`, you are testing the wrong host contract.

These distinctions are intentional.
They keep local development fast while still preserving a real topology-proof path.
