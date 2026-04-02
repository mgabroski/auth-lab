# Hubins Auth-Lab — Contributor Onboarding

**Status:** Stage 6 canonical onboarding entrypoint  
**Scope:** Current repository only  
**Audience:** New engineers, returning contributors, and repo-aware LLM sessions  
**Owner Role:** Lead Architect or Designated Quality Owner  
**Last Updated:** 2026-04-02

---

## Purpose

This is the durable onboarding entrypoint for this repository.

It exists to give a new contributor one clear answer to five questions:

- what this repo actually is
- what is implemented now versus what is still broader architecture direction
- which documents are authoritative
- what order to read them in
- how to start contributing without breaking repo law

This file is intentionally **not**:

- a replacement for `README.md`
- a replacement for `docs/developer-guide.md`
- a replacement for backend or frontend engineering-law docs
- a design essay
- a second source of truth for contracts already owned elsewhere

Use this file to get oriented quickly, then move to the correct authoritative docs for the area you are touching.

---

## What This Repo Really Is

Hubins Auth-Lab is the foundation repository for the wider Hubins platform.

Today, the repo already implements a real, shipped foundation slice:

- multi-tenant topology and request model
- same-origin browser API contract under `/api/*`
- SSR direct-to-backend contract with forwarded request identity
- host-derived tenant resolution
- backend-owned auth/session/bootstrap truth
- Auth + User Provisioning backend behavior
- Auth + User Provisioning frontend routes and screens
- local full-stack proof with proxy, Postgres, Redis, Mailpit, and Playwright
- repo-law, security, operability, and release-discipline baseline documents and CI enforcement

This repo is **not yet** the full Hubins product.

Do not treat broader architecture direction as current shipped scope.
If you are unsure what is real today, `docs/current-foundation-status.md` wins.

---

## The Five Repo Laws You Must Understand First

Before touching code, understand these load-bearing laws.

### 1. Browser traffic is same-origin

Browser code talks to the backend through relative `/api/*` paths.

Do not hardcode browser calls to backend origins.

### 2. SSR is different from browser execution

SSR/server-side frontend code may call the backend directly through `INTERNAL_API_URL`, but only while forwarding the required request identity headers.

Do not treat browser and SSR fetch behavior as interchangeable.

### 3. Tenant identity is host-derived

Tenant identity comes from the request host/subdomain.

It must never come from payload, local storage, query params, or ad hoc client headers.

### 4. Backend truth is authoritative

The backend owns:

- session truth
- membership truth
- auth continuation truth
- tenant bootstrap truth

The frontend may reflect that truth, but it must not invent a competing state model.

### 5. Repo law and docs are part of the system

If you change architecture, contracts, trust boundaries, runbooks, or contributor law, update the matching docs in the same change.

This repo does not allow silent documentation drift.

---

## Read In This Order

This is the canonical reading order for a new contributor.

### First — orient to shipped truth

1. `README.md`  
   Start here for repo purpose and high-level scope.

2. `docs/current-foundation-status.md`  
   Read this next to separate real implemented scope from broader platform direction.

### Second — load the architectural law

3. `ARCHITECTURE.md`  
   Read this for the long-lived system shape and boundary rules.

4. `docs/decision-log.md`  
   Read this for non-obvious decisions you should not rediscover from scratch.

5. `docs/security-model.md`  
   Read this before touching auth, sessions, cookies, tokens, SSO, tenant isolation, or sensitive data handling.

### Third — route by area

#### If you are changing backend code

6. `backend/docs/README.md`
7. `backend/docs/engineering-rules.md`
8. `backend/docs/module-skeleton.md`
9. the relevant `backend/docs/api/*.md` contract docs
10. the relevant backend module doc if one exists

#### If you are changing frontend code

6. `frontend/README.md`
7. `frontend/src/shared/engineering-rules.md`
8. `frontend/docs/module-skeleton.md`
9. the relevant backend API contract docs that drive the frontend behavior

#### If you are changing topology, trust boundaries, or auth/bootstrap behavior

Read both backend and frontend law docs, plus:

- `docs/ops/runbooks.md`
- `docs/ops/observability.md`
- `docs/ops/release-engineering.md`

#### If you are doing review or AI-assisted work

After the law docs above, load:

- `AGENTS.md`
- `code_review.md`
- `docs/prompts/usage-guide.md`
- `docs/prompts/catalog.md`

### Fourth — load local execution truth only after you understand the law

11. `docs/developer-guide.md`

Use the developer guide for setup, reset, test execution, and local environment truth.
It is not the first architecture document.

---

## What Is Authoritative vs Reference-Only

### Primary authority for current work

Use these as the main truth chain:

1. `README.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/decision-log.md`
5. `docs/security-model.md`

### Area authority

Then use the area-specific law docs:

- backend: `backend/docs/engineering-rules.md`, `backend/docs/module-skeleton.md`, `backend/docs/api/*.md`
- frontend: `frontend/src/shared/engineering-rules.md`, `frontend/docs/module-skeleton.md`
- ops/release: `docs/ops/*.md`

### Reference and support material

These are useful, but they should not be the first place you derive repo truth from:

- `CONTRIBUTING.md`
- `AGENTS.md`
- `docs/prompts/*.md`
- `docs/qa/*.md`
- `docs/implementation-session-charter.md`
- `docs/ai/repo-ai-adoption-roadmap.md`
- `code_review.md`

If a support document appears to conflict with a higher-law document, the support document must be corrected.

---

## Architecture Walkthrough For New Contributors

This is the shortest accurate walkthrough of how the repo works.

### 1. One public origin

From the browser’s perspective, the system is one public origin.
The browser does not directly know or care that frontend and backend are separate services.

### 2. Proxy routing is load-bearing

The public entry routes:

- `/api/*` to the backend
- `/_next/*` to the frontend
- everything else to the frontend

This is not implementation trivia. It is part of the architecture contract.

### 3. Browser and SSR follow different backend paths

Browser:

- uses same-origin `/api/*`
- cookies are handled by the browser

SSR/server-side frontend code:

- uses `INTERNAL_API_URL`
- must forward `Host`, `Cookie`, and `X-Forwarded-*`

### 4. Tenant resolution happens before business logic

The backend resolves the tenant from the request host.
Everything else depends on that being correct.

### 5. Session and tenant must agree

A session for one tenant must not be accepted for another tenant.
This repo intentionally fails closed on tenant/session mismatch.

### 6. SSO state is not the session cookie

The repo has a two-cookie contract:

- session cookie for authenticated session identity
- short-lived SSO state cookie for OAuth callback validation

Do not merge these concepts.

### 7. The current shipped product slice is Auth + User Provisioning

The implemented slice includes:

- login/logout
- signup/verification/reset-password
- invite lifecycle
- MFA setup/verify/recovery
- Google and Microsoft SSO flows
- admin invite management
- workspace setup banner and `/admin/settings` acknowledgement surface

### 8. The repo is already governance-heavy on purpose

This repo does not rely on memory alone.
Quality bar, repo guard, API-doc coupling, prompt catalog coupling, CI, runbooks, QA docs, and security docs are already part of the system.

---

## Safe Contribution Path

When you pick up work, use this order.

### Step 1 — Classify the change

Ask:

- is this backend, frontend, topology, docs, or release/ops work?
- is it architecture-sensitive?
- does it introduce or substantially expand a major module?

If it is ambiguous, treat it as higher-risk until proven otherwise.

### Step 2 — Load only the docs that govern that change

Do not read every document in the repo.
Load the authoritative documents for the area you are changing.

### Step 3 — Identify the truth-coupled docs before editing code

Before touching code, identify which docs must move with it.
Typical examples:

- API change → matching `backend/docs/api/*.md`
- auth/bootstrap or trust-boundary change → `docs/decision-log.md`, `docs/security-model.md`, possibly ops docs
- shipped-scope change → `docs/current-foundation-status.md`
- release/migration contract change → `docs/ops/release-engineering.md`

### Step 4 — Make the smallest truthful change

Prefer narrow, explicit, reversible changes.
Do not use a small task as an excuse to reorganize unrelated code or docs.

### Step 5 — Run the right proof for the risk level

Examples:

- code-style or doc-only change → lighter checks may be enough
- backend/frontend behavior change → unit/integration/E2E checks as appropriate
- topology/auth/session/proxy change → higher-confidence stack proof is required

### Step 6 — Report what was actually verified

Do not imply runtime proof if you only reviewed code.
Say what you ran.

---

## Module Onboarding Checklist

Use this checklist before starting a new major module or substantially expanding one.

### 1. Scope and boundary check

- [ ] Confirm whether the work is a major module under `docs/quality-bar.md`
- [ ] Identify the bounded context and what it owns
- [ ] Identify what it must not own
- [ ] Confirm whether any existing module already owns this behavior

### 2. Authority check

- [ ] Read `README.md`
- [ ] Read `docs/current-foundation-status.md`
- [ ] Read `ARCHITECTURE.md`
- [ ] Read `docs/decision-log.md`
- [ ] Read the relevant backend/frontend engineering-law docs

### 3. Contract check

- [ ] Identify which API/contract docs must be added or updated
- [ ] Confirm whether frontend behavior depends on a backend contract change
- [ ] Confirm whether QA-visible flows or messages will change

### 4. Decision and trust-boundary check

- [ ] Decide whether the change needs a `docs/decision-log.md` entry
- [ ] Decide whether the change needs a backend ADR
- [ ] Re-check `docs/security-model.md` if cookies, sessions, tokens, SSO, tenant isolation, or secrets are involved

### 5. Proof check

- [ ] Define the primary happy-path proof
- [ ] Define unit coverage for branch-heavy logic and policies
- [ ] Define contract/integration coverage for risky boundaries
- [ ] Define negative-path coverage for the most important failure and permission conditions

### 6. Operability and release check

- [ ] Identify required metrics/logging/correlation updates
- [ ] Identify required runbook impact
- [ ] Identify migration safety impact if schema/data shape changes
- [ ] Identify release-lane impact in `docs/ops/release-engineering.md`

### 7. Track A / signoff check

- [ ] Use the PR Module Quality Gate
- [ ] Gather evidence for the mandatory gates
- [ ] Do not treat a checked box as signoff by itself
- [ ] Record any allowed defer in `docs/quality-exceptions.md`

### 8. Shipped-truth check

- [ ] Update `docs/current-foundation-status.md` if shipped scope materially changed
- [ ] Update onboarding/relevant entry docs if the repo reading path or law changed

---

## Quick Rule For Using The Decision Log

Use `docs/decision-log.md` when the decision is:

- architectural
- cross-cutting
- non-obvious
- likely to matter again later

Do **not** use it for:

- routine refactors
- local naming choices
- one-off bug fixes
- behavior already fully explained by existing repo law

Backend-local architectural decisions that do not belong in the repo-wide decision log should go through `backend/docs/adr/README.md`.

A separate detailed decision-log usage guide should remain small and procedural.
This onboarding doc only gives the routing rule.

---

## Ongoing Knowledge Transfer And Refresh Rule

This repository uses a small repeatable Stage 6 knowledge-transfer mechanism.
It should stay lightweight and durable, not turn into a parallel process system.

### 1. Canonical written walkthrough

This file is the canonical written onboarding and architecture-entry document for contributors.

It is the first knowledge-transfer surface.
It must stay current enough that a new engineer or new LLM session can orient correctly without tribal knowledge.

### 2. Periodic architecture refresh

A lightweight architecture refresh must happen whenever one of these occurs:

- a major repo law changes
- the contributor reading order changes
- the shipped foundation surface changes materially
- a new major module becomes real current-scope work
- contributor confusion is recurring enough that this file or linked docs are no longer sufficient

The refresh does **not** require a heavy ceremony.
It may take one of two forms:

- a short architecture Q&A session
- a recorded walkthrough or written walkthrough refresh

The important rule is not the format.
The important rule is that design intent is actively retransmitted when the repo changes in ways new contributors must understand.

### 3. Minimum cadence while the repo is evolving

If active architecture and module work is continuing, contributor guidance should be re-checked at least once per quarter even if no single law change obviously triggered it.

This is a lightweight truth check, not a rewrite cycle.

### 4. Output of a refresh

A refresh is only complete when the result is reflected in the authoritative docs as needed.

Typical outputs may include updates to:

- `docs/onboarding.md`
- `README.md`
- `CONTRIBUTING.md`
- `docs/current-foundation-status.md`
- `docs/decision-log.md`
- relevant engineering-rules or ops docs

A meeting, recording, or conversation by itself does not count if the contributor truth remains stale afterward.

### 5. Owner responsibility

The Lead Architect or Designated Quality Owner owns this onboarding surface.

Contributors introducing major law, reading-order, or current-scope changes are responsible for proposing the matching doc updates in the same change.
The owner role is responsible for ensuring the onboarding truth stays coherent.

---

## Common Ways New Contributors Get Lost

### 1. Treating the broader Hubins vision as if it were already implemented

Fix: read `docs/current-foundation-status.md` early.

### 2. Reading prompts before reading repo law

Fix: prompts are execution aids, not top authority.

### 3. Treating browser and SSR backend access as the same thing

Fix: they are different execution contexts with different rules.

### 4. Mistaking support docs for source of truth

Fix: use the truth chain in this file.

### 5. Adding duplicate docs instead of tightening the right one

Fix: if a higher-authority doc already owns the truth, update it there.

---

## What Not To Do

Do not:

- add a second overview doc that competes with this one
- restate API contracts here
- restate module skeleton details here
- invent a frontend-only auth or tenant model
- derive tenant from request payload or local state
- hardcode direct backend browser origins
- treat a prompt, chat summary, or support note as stronger than repo law

---

## Maintenance Rule

This onboarding document must be updated whenever any of the following change materially:

- repo reading order
- repo truth hierarchy
- topology law
- auth/bootstrap law
- tenant/session law
- the current shipped module surface in a way that changes how new contributors should orient themselves
- the contributor knowledge-transfer or refresh process defined in this file

If one of those changes happens and this file is not updated, onboarding truth is stale.
That is a documentation defect, not a cosmetic issue.
