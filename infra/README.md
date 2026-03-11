# infra/

Infrastructure configuration for Hubins Auth-Lab.

This folder defines the local and reference deployment topology for the current foundation phase.

Read this together with:

- `README.md`
- `docs/current-foundation-status.md`
- `ARCHITECTURE.md`
- `docs/decision-log.md`

---

## Two dev modes

There are intentionally two modes.
Neither is wrong.
They serve different purposes.

## Mode 1 — Host-run (daily development)

**Command from repo root:**

```bash
yarn dev
```

### What runs

- Postgres + Redis in Docker (`docker-compose-infra.yml`)
- Backend on the host (`localhost:3001`)
- Frontend on the host (`goodwill-ca.localhost:3000`)

### Use this for

- day-to-day feature development
- quick backend/frontend iteration
- normal local debugging

### Important browser URL

Use:

```text
http://goodwill-ca.localhost:3000
```

Do **not** use plain `localhost:3000` when testing tenant-aware behavior.

### What host-run mode does prove

- backend ↔ Postgres / Redis local wiring
- SSR direct-backend communication through `INTERNAL_API_URL`
- browser same-origin `/api/*` usage through the local Next Route Handler proxy
- tenant-aware browser behavior when using the correct subdomain host

### What host-run mode does **not** prove

- Caddy proxy behavior
- forwarded-header behavior through the real public proxy layer
- public proxy cookie handling behavior
- full topology conformance

Host-run mode is the daily work mode, not the final topology-proof mode.

---

## Mode 2 — Full Docker stack (topology validation)

**Command from repo root:**

```bash
yarn stack
```

### What runs

- Caddy proxy
- Next.js frontend
- Fastify backend
- Postgres
- Redis

Everything runs in Docker behind the intended local proxy shape.

### Public entrypoint

```text
http://goodwill-ca.lvh.me:3000
```

### Use this before merging changes that affect

- `infra/`
- proxy config
- request context / host resolution
- session/cookie behavior
- SSO callback/start assumptions
- browser vs SSR communication assumptions

### Run topology validation

```bash
yarn stack:test
```

This executes the proxy conformance suite against the live stack.

---

## Recommended validation flow

### Daily feature loop

```bash
yarn dev
```

### Repo-level checks before merge

```bash
yarn verify
```

### Topology-sensitive changes

```bash
yarn stack
yarn stack:test
```

Use all three levels appropriately:

- `yarn dev` for normal iteration
- `yarn verify` for repo-level formatting/lint/type/build/test checks
- `yarn stack:test` for topology-sensitive proof

---

## Files in this folder

| File                       | Purpose                                        |
| -------------------------- | ---------------------------------------------- |
| `docker-compose.yml`       | Full stack: proxy + frontend + backend + infra |
| `docker-compose-infra.yml` | Infra-only stack for host-run mode             |
| `caddy/Caddyfile`          | Local reverse proxy topology                   |
| `nginx/nginx.conf`         | Production/reference reverse proxy config      |

---

## Local dev ports (host-run mode)

| Service                 | URL                                 |
| ----------------------- | ----------------------------------- |
| Frontend (tenant-aware) | `http://goodwill-ca.localhost:3000` |
| Backend (Fastify)       | `http://localhost:3001`             |
| Postgres                | `localhost:5432`                    |
| Redis                   | `localhost:6379`                    |

---

## Proxy/public ports (full Docker stack mode)

| Entry point              | URL                                         |
| ------------------------ | ------------------------------------------- |
| Full application         | `http://goodwill-ca.lvh.me:3000`            |
| Backend health via proxy | `http://goodwill-ca.lvh.me:3000/api/health` |

`lvh.me` resolves to `127.0.0.1`, so no `/etc/hosts` edits are needed.

---

## Postgres credentials (dev only)

| Key      | Value      |
| -------- | ---------- |
| Database | `auth_lab` |
| User     | `auth_lab` |
| Password | `auth_lab` |

These are local-development credentials only.
Never reuse them in production.
