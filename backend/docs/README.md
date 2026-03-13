# Backend Docs Map

This folder contains the backend implementation law, module structure law, API contract docs, module-specific backend docs, ADR guidance, and LLM execution prompts.

It is the backend documentation hub.
It is **not** the top authority for the whole repository.

The backend docs must always be read inside the wider repo authority chain:

1. `README.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/decision-log.md`
5. `backend/docs/README.md`
6. `backend/docs/engineering-rules.md`
7. `backend/docs/module-skeleton.md`

If this folder ever implies something broader than the current shipped repo truth, the repo-level documents win.

---

## What this folder is for

Use this folder to answer backend questions like:

- What is the backend implementation law?
- What structure must a module follow?
- What does the auth API contract look like?
- What does the current Auth + User Provisioning backend module actually cover?
- How should an LLM-assisted implementation session be run?
- How should a backend review session be run?
- How should architectural decisions be recorded?

This folder is intentionally practical.
It exists to reduce drift between backend code, backend rules, and backend-assisted implementation workflows.

---

## Read documents in this order

| #   | File                                              | What it is                                                      | Who should read it                            |
| --- | ------------------------------------------------- | --------------------------------------------------------------- | --------------------------------------------- |
| 1   | `README.md` _(repo root)_                         | Repo entrypoint and current scope framing                       | Everyone                                      |
| 2   | `docs/current-foundation-status.md` _(repo root)_ | Exact current shipped truth for this repo version               | Everyone                                      |
| 3   | `ARCHITECTURE.md` _(repo root)_                   | Broader system direction and locked architecture law            | Everyone                                      |
| 4   | `docs/decision-log.md` _(repo root)_              | Non-obvious architecture decisions and consequences             | Everyone making architectural changes         |
| 5   | `backend/docs/README.md`                          | Backend docs entrypoint and backend doc hierarchy               | Backend contributors                          |
| 6   | `backend/docs/engineering-rules.md`               | Backend implementation law                                      | Every backend engineer on every PR            |
| 7   | `backend/docs/module-skeleton.md`                 | Canonical backend module structure and file responsibilities    | Anyone adding or reshaping a backend module   |
| 8   | `backend/docs/api/auth.md`                        | Current auth API contract for bootstrap + auth endpoints        | Engineers touching auth API behavior          |
| 9   | `backend/docs/api/invites.md`                     | Current invite-acceptance API contract                          | Engineers touching invite acceptance          |
| 10  | `backend/docs/api/admin.md`                       | Current admin invite + audit API contract                       | Engineers touching admin provisioning         |
| 11  | `backend/docs/modules/auth-user-provisioning.md`  | Business/configuration behavior for the current backend module  | Engineers, PMs, QA                            |
| 12  | `backend/docs/adr/README.md`                      | How ADRs are written and when one is required                   | Engineers changing architecture or boundaries |
| 13  | `backend/docs/prompts/module-generation.md`       | Prompt for generating a new backend module from a business spec | Tech lead / PM / LLM session owner            |
| 14  | `backend/docs/prompts/implement.md`               | Prompt for implementation sessions                              | Engineer + LLM                                |
| 15  | `backend/docs/prompts/review.md`                  | Prompt for adversarial backend review sessions                  | Engineer + LLM                                |

---

## Source-of-truth hierarchy for backend questions

When backend docs appear to conflict, resolve them in this order:

```text
README.md
  ↓
docs/current-foundation-status.md
  ↓
ARCHITECTURE.md
  ↓
docs/decision-log.md
  ↓
backend/docs/engineering-rules.md
  ↓
backend/docs/module-skeleton.md
  ↓
backend/docs/api/*.md and backend/docs/modules/*.md
  ↓
backend/docs/prompts/*.md
  ↓
backend/docs/adr/*.md
```

### How to interpret that hierarchy

- `README.md` sets repo entry framing and points readers to the correct scope documents.
- `docs/current-foundation-status.md` decides what is actually implemented now.
- `ARCHITECTURE.md` decides broader system shape and locked architecture rules.
- `docs/decision-log.md` explains non-obvious decisions already taken.
- `engineering-rules.md` defines how backend code must be written.
- `module-skeleton.md` defines how backend modules must be shaped.
- API/module docs describe the current behavior of specific surfaces.
- Prompt docs are derived execution artifacts and must reflect the rules above.
- ADRs explain why a decision exists; they do not silently override repo law.

If a lower document disagrees with a higher one, the lower document must be updated.

---

## The backend docs split

This backend doc set intentionally has five categories.

### 1. Law docs

These define how backend work must be done.

- `engineering-rules.md`
- `module-skeleton.md`

### 2. Contract docs

These define concrete backend surfaces consumed or depended on by other parts of the system.

- `api/auth.md`
- `api/invites.md`
- `api/admin.md`

### 3. Module docs

These explain the behavior and scope of an implemented backend module.

- `modules/auth-user-provisioning.md`

### 4. Prompt docs

These are execution artifacts for LLM-assisted work.

- `prompts/module-generation.md`
- `prompts/implement.md`
- `prompts/review.md`

### 5. Decision docs

These explain architecture decisions that should not drift silently.

- `adr/*.md`

This split matters because not every document has the same job.
A prompt file is not the same thing as engineering law.
A module doc is not the same thing as architecture law.

---

## Prompt files are derived artifacts

The files in `backend/docs/prompts/` are not source authority.
They are **derived execution artifacts**.

That means:

- they must reflect the current repo law
- they must not invent structure that the repo does not use
- they must not overclaim what the backend currently implements
- they must be updated whenever the law they depend on changes

If `engineering-rules.md` or `module-skeleton.md` changes and the prompts are not updated, that is a documentation bug.

### Prompt responsibilities

| File                           | Loaded when                                | Purpose                                                                                 |
| ------------------------------ | ------------------------------------------ | --------------------------------------------------------------------------------------- |
| `prompts/module-generation.md` | Starting a new module from a business spec | Converts a business spec into a repo-aligned module generation plan                     |
| `prompts/implement.md`         | Running an implementation session          | Forces the implementation to follow the repo’s structure, laws, and output expectations |
| `prompts/review.md`            | Running a review session                   | Forces review against architecture, law, topology, boundaries, and docs                 |

---

## ADRs

`backend/docs/adr/` exists to record backend-significant decisions that should not drift silently.

Use an ADR when:

- a backend architectural boundary changes
- a shared primitive is added or changed in a way other modules will depend on
- a topology-sensitive backend assumption changes
- a cross-module contract becomes important enough that “tribal memory” is unsafe
- a backend law is intentionally overridden or revised in a meaningful way

ADR files are not required for every PR.
They are required for decisions that affect future design or future module work.

See `backend/docs/adr/README.md` for the ADR format and naming rules.

---

## What this folder must never do

These backend docs must not:

- pretend planned backend structure is already implemented when it is not
- contradict repo-level current-foundation truth
- silently drift away from the actual backend structure
- treat prompt files as higher authority than law docs
- hide missing implementation behind polished wording

A backend doc that sounds strong but is not true is a defect.

---

## Update rules

Update this folder when:

### Update `engineering-rules.md` when:

- backend implementation law changes
- boundary rules change
- transaction ownership rules change
- request/session/tenant backend rules change

### Update `module-skeleton.md` when:

- canonical backend module structure changes
- new mandatory backend layer types are introduced
- shared-vs-module responsibility changes

### Update `api/auth.md` when:

- an auth endpoint changes
- an auth response contract changes
- bootstrap endpoint behavior changes
- frontend auth bootstrap expectations change

### Update `modules/auth-user-provisioning.md` when:

- backend Auth + User Provisioning behavior changes
- tenant-config behavior changes
- a documented business/config rule becomes real, changes, or is removed

### Update prompt docs when:

- backend law changes
- backend structure law changes
- review expectations change
- repo topology assumptions change in ways backend sessions must honor

### Add or update an ADR when:

- a decision is important enough that future contributors should not rediscover it from scratch

---

## Current backend truth

At the current repo phase, the backend is already the more complete side of the system.

That means these docs should assume:

- backend topology assumptions are real
- backend tenant/session behavior is real
- Auth + User Provisioning backend behavior is real

But they must also stay honest that:

- the frontend auth/provisioning surface is now real for the current module scope
- the broader Hubins product is not fully implemented yet
- some repo-wide quality gates and later hardening work are still being tightened

The backend docs should help future work build correctly on the current foundation and current shipped auth/provisioning slice — not hide what is already real or what is still future work.
