# infra/

## Why this folder exists

This folder contains **local development infrastructure only**.

We run **Postgres + Redis** in Docker so every developer has the same dependencies.
The backend runs on the host machine (fast hot reload) and connects to these services.

## How to use

Use the scripts from repo root (single source of truth):

- Start infra: `./scripts/dev.sh`
- Stop infra: `./scripts/stop.sh`
- Reset infra data (danger): `./scripts/reset-db.sh`

> We intentionally avoid running the backend in Docker during dev to prevent slow rebuild cycles.

## Default ports

- Postgres: `localhost:5432`
- Redis: `localhost:6379`

## Default credentials (DEV ONLY)

Postgres:

- DB: `auth_lab`
- User: `auth_lab`
- Password: `auth_lab`

These are safe for local development and will be replaced by real secrets in production.
