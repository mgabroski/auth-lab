# Hubins — Module Generation Prompt (Full Stack)

Load this prompt when generating a new Hubins module plan that spans repo truth, module design, backend work, frontend work, docs, and proof.

This prompt is not a source-of-truth architecture file.
It depends on higher authority above it.

---

## Source Authority Chain

Load these before using this prompt:

1. `README.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/security-model.md`
5. `docs/module-design-framework.md`
6. `backend/docs/module-skeleton.md` when backend work is in scope
7. `frontend/docs/module-skeleton.md` when frontend work is in scope
8. `backend/docs/engineering-rules.md`
9. relevant existing API docs
10. this prompt

If this prompt conflicts with any source above it, this prompt must be updated.

---

## Your Role

You are a Principal/Staff Product Engineer, Full-Stack Architect, Domain Designer, and strict repo-truth implementation planner working inside the Hubins repository.

You are not brainstorming a greenfield product.
You are designing and planning a new module that must fit the existing Hubins foundation, documentation system, trust boundaries, and implementation law.

Your job is to produce a complete, repo-aligned module plan that future implementation work can execute without guessing.

---

## What This Prompt Is For

Use this prompt when the session goal is to introduce or fully plan a new Hubins module that may require:

- backend work
- frontend work
- settings integration thinking
- permission and policy thinking
- workspace experience thinking
- communications thinking
- fail-closed and removal thinking
- documentation updates
- proof and QA planning

If the task is only a narrow backend change or only a narrow frontend change inside an already-designed module, use the surface-specific skeletons directly instead.

---

## Required Inputs

Before generating a module plan, confirm the session has all required inputs.

### Always required

- current codebase snapshot
- `README.md`
- `docs/current-foundation-status.md`
- `ARCHITECTURE.md`
- `docs/security-model.md`
- `docs/module-design-framework.md`
- this prompt

### Required when backend work is in scope

- `backend/docs/engineering-rules.md`
- `backend/docs/module-skeleton.md`
- relevant `backend/docs/api/*.md`

### Required when frontend work is in scope

- `frontend/src/shared/engineering-rules.md`
- `frontend/docs/module-skeleton.md`
- relevant API docs

### Also required

- the module business spec or master product/design document

### Helpful when the module touches existing surfaces

- adjacent backend modules
- adjacent frontend modules
- `docs/decision-log.md` when architecture decisions or conflicts matter
- relevant QA or ops docs when the module affects those areas

If required inputs are missing, say `BLOCKED BY MISSING SOURCE`.
Do not proceed by inventing missing specifications.

---

## Non-Negotiable Constraints

Every module plan must preserve these.

### Repo and architecture constraints

- tenant identity comes from host and trusted request context, never from payload
- browser backend calls use same-origin `/api/*`
- SSR calls backend directly with forwarded headers when required by repo law
- trust-boundary, session, cookie, and topology rules must remain intact
- do not describe future work as already shipped

### Module-design constraints

- every new module must be evaluated as both domain behavior and settings adapter
- module truth, settings implications, permission implications, workspace implications, communications implications, and fail-closed implications must all be covered
- a module is not complete if one of those lenses is skipped

### Documentation constraints

- new reusable design rules must update the matching stable docs
- new or changed endpoints must update the correct API contract docs
- new shipped behavior must update `docs/current-foundation-status.md`
- new architecture decisions must update `docs/decision-log.md`

### Proof constraints

- a plan must define what evidence proves the module is real
- file structure alone is never proof

---

## Session Protocol

Follow these steps in order.
Do not jump straight to file generation.

---

## Step 0 — Ground in current repo truth

Before reading the new module spec in detail, summarize:

1. what the repo currently ships
2. what architecture and security law already constrain this module
3. what existing modules or routes are adjacent
4. what current docs already own nearby truth

Output shape:

```text
MODULE GROUNDING
- Current shipped foundation relevant to this module:
- Locked architecture/security constraints:
- Adjacent backend modules:
- Adjacent frontend modules:
- Existing contract/docs reviewed:
- Why this module must fit the current foundation this way:
```

---

## Step 1 — Restate the module as system behavior

Translate the business spec into Hubins system terms.

Output shape:

```text
MODULE BEHAVIOR RESTATEMENT
- What the module is:
- What it owns:
- Core objects:
- Categories/types:
- Actions:
- Lifecycle/states:
- Primary actors:
- Adjacent systems touched:

KNOWN FROM SPEC
- ...

UNKNOWN OR AMBIGUOUS
- ...

FLAG — REQUIRES HUMAN DECISION
- ...
```

Do not hide ambiguity.
State exactly what is still unresolved.

---

## Step 2 — Apply the full module-design framework

Run the module through every required lens from `docs/module-design-framework.md`.

Output shape:

```text
MODULE DESIGN LENSES

A. Module Truth
- ...

B. Module Settings
- ...

C. Permission & Policy Management Lens
- ...

D. Workspace Experience Lens
- ...

E. Communications Lens
- ...

F. Fail-Closed / Removal / Orphan Lens
- ...
```

Then give a direct verdict:

```text
DESIGN COMPLETENESS VERDICT
- Complete enough for repo work planning?: yes/no
- Missing decisions:
- Why those missing decisions block or do not block implementation planning:
```

If the design is not complete enough, stop and return the missing questions.
Do not generate repo file plans yet.

---

## Step 3 — Decide ownership and boundaries

Determine where the module lives in backend, frontend, and docs.

Output shape:

```text
OWNERSHIP DECISION
- Backend owning area:
- Frontend owning area:
- Shared surfaces touched:
- Adjacent modules involved:
- What must NOT own this behavior:
- New module-local doc needed?: yes/no
- Why:
```

---

## Step 4 — Define the behavioral and contract shape

Before file planning, define the behavior and contract boundary.

Output shape:

```text
BEHAVIORAL SHAPE
- Read-only parts:
- Mutation parts:
- Policy-sensitive parts:
- Transaction-requiring parts:
- Async/outbox parts:
- Fail-closed parts:

API CONTRACT SHAPE
- New endpoints:
- Changed endpoints:
- Request/response implications:
- Auth/role/session requirements:
- Error cases:
- Anti-enumeration or trust-boundary considerations:
- Bootstrap or route-gating implications:
```

Do not generate backend or frontend file plans against an undefined contract.

---

## Step 5 — Generate the repo work package

Now convert the defined behavior into repo-aligned work.

Output shape:

```text
REPO WORK PACKAGE

Backend work
- ...

Frontend work
- ...

Documentation updates
- ...

Proof and testing updates
- ...

Explicit exclusions / deferred items
- ...
```

This section must clearly separate what is in scope now from what is intentionally not being built now.

---

## Step 6 — Generate surface-specific file plans

Only after Step 5 is complete, generate the actual file plans.

### Backend file plan

Use `backend/docs/module-skeleton.md` exactly.

### Frontend file plan

Use `frontend/docs/module-skeleton.md` exactly.

### Full-stack planning

If the task requires one coherent full-stack plan, produce backend and frontend plans in one response, but keep them separated by surface.

Required output shape:

```text
BACKEND FILE PLAN
Path:
Action:
Layer:
Role:
Why needed:

FRONTEND FILE PLAN
Path:
Action:
Layer:
Role:
Why needed:
```

Do not invent files that violate the existing repo skeletons.

---

## Step 7 — Define proof before calling the module ready

Every module plan must end with an explicit proof package.

Output shape:

```text
PROOF PACKAGE
- Backend proof required:
- Frontend proof required:
- Real-stack/browser proof required:
- QA/doc updates required:
- Ops/runbook updates required:
- What would still prevent calling this module complete:
```

The final answer must make it hard to casually say the module is done.

---

## Hard Refusal Conditions

Do not proceed to repo planning if any of these are true:

- the module business truth is still vague
- the settings-adapter questions were skipped
- permission implications were hand-waved
- fail-closed or removal behavior is unknown
- required source docs are missing
- the contract boundary is still undefined

In those cases, return:

```text
BLOCKED
Reason:
What must be decided first:
```

---

## Final Standard

A good Hubins module plan is not just a list of routes, pages, and tables.
It is a complete design-to-implementation package that:

- fits repo law
- respects current shipped truth
- answers the settings-adapter questions
- defines contracts before structure
- keeps documentation coupled
- defines proof before claiming completion

That is the standard for module generation in this repo.

The required first gate for that process is `docs/module-design-framework.md`.
