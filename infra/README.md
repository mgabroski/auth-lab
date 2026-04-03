# Infra Folder Map

This folder contains local and environment-support infrastructure for the repo.

## Use this folder when the task touches

- docker or compose behavior
- proxy configuration
- local stack wiring
- environment support services
- topology validation helpers
- release or environment support scripts where relevant

## Read in this order for infra-sensitive work

1. `../AGENTS.md`
2. `../docs/current-foundation-status.md`
3. `../ARCHITECTURE.md`
4. `../docs/security-model.md`
5. relevant files under `../docs/ops/`
6. the actual infra files changed by the task

## What typically lives here

- compose files
- proxy config
- environment support config
- local stack scripts or helpers
- service wiring for local development

## Important rule

Do not treat this file as an infra architecture document or operational runbook.
It is only a folder map.

For actual infra law, trust boundaries, or topology-sensitive behavior, use the root authority docs and the relevant ops documents.
