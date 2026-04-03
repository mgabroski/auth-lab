# Backend Docs Map

This folder is a backend reference surface.

It is not a repo entrypoint.
It is not a second source of truth for the whole repository.

Read root authority first:

1. `../../README.md`
2. `../../docs/current-foundation-status.md`
3. `../../ARCHITECTURE.md`
4. `../../docs/quality-bar.md`
5. `../../docs/decision-log.md`
6. `../../docs/security-model.md`

Then use this folder for backend-specific law, contracts, and references.

---

## What This Folder Contains

### Backend law

- `engineering-rules.md`
- `module-skeleton.md`

Use these for backend structure, ownership, layering, and implementation rules.

### Backend contracts

- `api/auth.md`
- `api/invites.md`
- `api/admin.md`

Use these when backend behavior, request/response semantics, or frontend/backend coupling matters.

### Backend module reference

- `modules/auth-user-provisioning.md`

Use this for the current backend module’s scoped behavior and implementation framing.

### Backend ADRs

- `adr/README.md`
- `adr/*.md`

Use these when a backend or boundary decision matters historically or architecturally.

### Backend prompt assets

- `prompts/*.md`

These are execution aids.
They are not stronger than backend law or repo law.

---

## How To Read Backend Docs

### For implementation

Read in this order:

1. `../../AGENTS.md`
2. `../AGENTS.md`
3. `engineering-rules.md`
4. `module-skeleton.md`
5. relevant `api/*.md`
6. relevant ADRs or module reference docs

### For review

Read in this order:

1. `../../AGENTS.md`
2. `../AGENTS.md`
3. `../../code_review.md`
4. relevant backend law and API docs
5. changed backend code and tests

### For architecture-sensitive backend work

Also read:

- `../../ARCHITECTURE.md`
- `../../docs/decision-log.md`
- `../../docs/security-model.md`

---

## Backend Truth Order

When backend documents appear to conflict, use this order:

1. active locked product/module source-of-truth docs
2. repo-level shipped-truth and architecture docs
3. backend law docs
4. backend API docs
5. ADRs and module reference docs
6. backend prompt docs

If a lower document disagrees with a higher one, the lower document must be updated or ignored.

---

## What This Folder Should Not Become

Do not turn this file into:

- a second root router
- a restatement of all repo law
- a process essay
- a duplicate of `backend/AGENTS.md`

Its job is simple:

- show what exists here
- route backend readers quickly
- stay smaller than the docs it points to
