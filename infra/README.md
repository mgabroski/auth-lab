# Infra Surface Reference

This folder contains local infrastructure and topology support for the Hubins repo.

It is an infra surface reference.
It is not the repo entrypoint.

Start at the repo root first:

1. `../README.md`
2. `../docs/current-foundation-status.md`
3. `../ARCHITECTURE.md`
4. `../docs/quality-bar.md`
5. `../docs/decision-log.md`
6. `../docs/security-model.md`

For AI/review routing, use:

- `../AGENTS.md`

---

## What This Folder Owns

This folder owns repo infrastructure assets that support local execution, stack topology, and environment-backed validation.

That includes:

- Docker Compose stack definitions
- proxy configuration
- local service topology
- local support services such as database, cache, mail capture, and identity-provider helpers when present
- stack lifecycle helpers referenced by repo scripts
- topology-sensitive test support

Use `../docs/current-foundation-status.md` before describing any infra behavior as fully shipped or production-complete.

---

## What This Folder Does Not Own

This folder does **not** own:

- repo-wide architecture law
- backend business logic
- frontend route behavior
- API contract truth
- product scope truth
- security policy truth by itself

Those are defined in higher-truth repo and backend/frontend authority docs.

---

## Read For Infra Work

### Core repo truth

- `../ARCHITECTURE.md`
- `../docs/decision-log.md`
- `../docs/security-model.md`
- `../docs/current-foundation-status.md`

### Operational and execution docs

- `../docs/developer-guide.md`
- `../docs/ops/runbooks.md`
- `../docs/ops/observability.md`
- `../docs/ops/release-engineering.md`

### Review expectations

- `../code_review.md`

### Area-specific code and config

Read the actual files under this folder that the task changes, such as:

- Docker Compose files
- proxy config
- local env templates
- support-service config
- stack scripts referenced by repo commands

---

## Infra Operating Rules

### 1. Preserve the topology contract

Infra changes must not casually break:

- single public-origin local behavior
- browser same-origin `/api/*` assumptions
- SSR/backend internal call assumptions
- host-derived tenant behavior
- forwarded-header expectations
- session/cookie behavior through the proxy path

### 2. Dev infra must support truthful validation

Local infra exists to make important behavior real enough to test.

Do not simplify local stack behavior in ways that make auth, session, proxy, cookie, SSR, or tenant behavior misleading.

### 3. Do not confuse local support with production truth

Some local services exist only to support development and validation.

Do not describe local convenience behavior as production behavior unless a higher-truth doc says so.

### 4. Keep infra changes coupled to support docs

If infra changes alter startup, reset, stack behavior, proxy behavior, support-service usage, or operator expectations, update the matching docs in the same change.

### 5. Keep secrets and env handling disciplined

Do not casually add, rename, or repurpose environment variables without checking:

- repo docs
- env templates
- developer guidance
- affected scripts
- CI or stack expectations

### 6. Keep topology-sensitive proof honest

A config that boots is not automatically a correct config.
Infra work must be judged by whether the intended behavior still holds.

---

## Folder Map

### Stack definitions

Use the Compose and related stack files here for:

- service wiring
- networks
- ports
- dependencies
- local support services

### Proxy configuration

Use proxy config here for:

- public-origin routing
- `/api/*` forwarding
- asset routing
- header forwarding
- host preservation
- local topology behavior

### Env templates and support config

Use env examples and support-service config here only as infra support assets.

They are not the only source of truth for behavior.

### Infra-adjacent scripts or helpers

If this folder contains helper files for stack lifecycle or local support services, keep them aligned with repo scripts and support docs.

---

## Local Development Role

Normal repo development usually starts from the repo root:

```bash
yarn dev
```

Topology-sensitive validation may use:

```bash
yarn stack
yarn stack:test
```

Stopping or resetting the stack may use repo-root commands such as:

```bash
yarn stop
yarn status
yarn reset-db
```

Use `../docs/developer-guide.md` for the authoritative developer workflow rather than expanding this file into a setup manual.

---

## Infra Truth Order

When infra-local materials seem to disagree, use this order:

1. active locked product/module source-of-truth docs
2. repo-level shipped-truth and architecture docs
3. security and trust-boundary docs
4. ops and developer docs
5. actual infra config and stack files
6. local reference docs like this one

If a lower source conflicts with a higher one, the lower source must be corrected or ignored.

---

## What This File Should Be

This file should stay small.

Its job is to:

- explain what the infra folder owns
- point readers to the right higher-truth docs
- prevent this folder from becoming a second repo entrypoint
- keep infra readers oriented without adding duplicate process text

It should not become:

- a duplicate of root `README.md`
- a long setup guide
- a second architecture document
- a substitute for `docs/developer-guide.md`
- a substitute for `docs/ops/*.md`
