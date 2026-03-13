# Decision Log

This file records non-obvious architectural decisions that should not silently drift.

Each entry explains:

- what was decided
- why it was decided
- what alternatives were rejected
- what consequences follow from that decision

Format:
`## ADR-NNN — Title`

---

## ADR-001 — Next.js App Router over Vite SPA

**Date:** 2026-03  
**Status:** Accepted

### Context

We needed to choose a frontend framework for the auth UI foundation. The two candidates were:

- Next.js App Router
- Vite React SPA

### Decision

Use **Next.js App Router**.

### Why

- Sessions use `HttpOnly` cookies. There is no browser-managed auth token in `localStorage`.
- The first render often needs server-side knowledge of session state.
- Tenant identity is derived from host/subdomain, which SSR can read reliably before hydration.
- SSR can call `GET /auth/me` and `GET /auth/config` using the server-side request context.
- This supports a cleaner auth/bootstrap flow than forcing the browser to discover everything after hydration.

### Rejected alternative

**Vite SPA**

A SPA can work, but for this topology it would push too much session/bootstrap logic into client-side loading states and route flicker. That is the wrong tradeoff for an auth-heavy, tenant-aware frontend foundation.

---

## ADR-002 — Two dev modes: host-run for daily work, full stack for topology validation

**Date:** 2026-03  
**Status:** Accepted

### Context

We needed to decide whether local development should standardize on:

- host-run development
- or full Docker stack only

### Decision

Use **both**, intentionally.

### Why

#### Host-run mode

Best for daily engineering work:

- faster feedback loop
- backend hot reload
- frontend hot reload
- easier debugging

#### Full stack mode

Required for validating topology behavior that host-run mode does not prove:

- reverse proxy behavior
- forwarded header behavior
- cookie handling through proxy
- same-origin routing
- subdomain tenant resolution through the public entrypoint

### Consequence

A change can be “good enough for host-run” and still be unsafe for topology.
That is why topology-affecting changes must be validated in the full stack too.

---

## ADR-003 — SSO redirect URI embedded in encrypted state

**Date:** 2026-03  
**Status:** Accepted

### Context

A single global redirect base URL is too weak for tenant-aware SSO in a subdomain-driven system.

### Decision

Construct the tenant-aware redirect URI at SSO start and embed it in the encrypted SSO state.

### Why

- callback processing uses the exact URI chosen for that flow
- avoids brittle global re-derivation
- supports tenant-aware redirect behavior
- keeps the redirect target protected inside the encrypted state payload

### Rejected alternative

**Global `SSO_REDIRECT_BASE_URL` re-derivation at callback time**

That centralizes the callback origin too aggressively and becomes fragile in a multi-tenant topology.

---

## ADR-004 — SSO state cookie CSRF binding

**Date:** 2026-03  
**Status:** Accepted

### Context

OAuth `state` protects against CSRF, but state alone is stronger when also bound to the browser with a short-lived cookie.

### Decision

Set a short-lived `sso-state` cookie and require it to match the callback `state` query parameter.

### Why

- adds browser-bound CSRF protection
- keeps the SSO flow harder to replay incorrectly
- cookie is short-lived and contains only encrypted state
- aligns with a defense-in-depth approach for SSO entrypoints

### Cookie posture

- `HttpOnly`
- `SameSite=Lax`
- short TTL
- cleared on callback completion

### Why not `SameSite=Strict`

The OAuth provider redirects back to our callback URL as a top-level cross-site navigation. `Strict` would block the cookie in that flow and make validation fail.

---

## ADR-005 — Caddy manages `X-Forwarded-For` chain by default

**Date:** 2026-03  
**Status:** Accepted

### Context

A manual `header_up X-Forwarded-For {remote_host}` override looked harmless, but it actually collapses the forwarded chain.

### Decision

Do not manually override `X-Forwarded-For` in Caddy. Rely on Caddy's normal reverse proxy behavior.

### Why

- preserves the client IP chain correctly
- avoids flattening all requests into a single proxy-shaped identity
- keeps rate limiting and audit behavior meaningful behind the proxy

### Rejected alternative

**Manual header override**

It is too easy to accidentally destroy the chain that the backend expects when `trustProxy` is enabled.

---

## ADR-006 — Topology-first foundation before broader module expansion

**Date:** 2026-03  
**Status:** Accepted

### Context

Hubins is a broader platform, but this repository phase needed a strong foundation before expanding into more modules or richer UI flows.

There was a risk of treating broader product docs as if they implied current implementation completeness.

### Decision

Treat this repo phase explicitly as:

**Topology + FE/BE wiring + Auth/User Provisioning foundation first**

### Why

Because the following are load-bearing and must be correct before broader expansion:

- same-origin FE/BE contract
- SSR backend access contract
- tenant routing and isolation
- session/cookie behavior
- proxy trust assumptions
- backend module/bootstrap discipline
- truthful repo/documentation authority

### Consequence

The repo is allowed to describe the broader Hubins platform direction, but it must always keep current shipped scope explicit through:

- `README.md`
- `docs/current-foundation-status.md`
- this decision log

### Rejected alternative

**Pretend the wider platform architecture equals current repo completeness**

That creates false confidence and causes drift in both implementation and planning.

---

## ADR-007 — Browser uses same-origin `/api/*`, SSR uses direct backend access

**Date:** 2026-03  
**Status:** Accepted

### Context

We needed one clear FE/BE communication rule that works with:

- tenant subdomains
- proxy routing
- session cookies
- SSR bootstrap flows

### Decision

Split communication paths by execution environment:

#### Browser

Use relative same-origin `/api/*` through the proxy.

#### SSR / server-side frontend code

Call backend directly through `INTERNAL_API_URL` and explicitly forward:

- `Host`
- `Cookie`
- `X-Forwarded-For`
- `X-Forwarded-Proto`
- `X-Forwarded-Host`

### Why

This keeps browser behavior aligned with the public topology while allowing SSR to bootstrap session-aware state directly and efficiently.

### Rejected alternatives

#### Browser directly calling backend origin

Rejected because it weakens topology discipline and complicates cookie / origin handling.

#### SSR also calling through public `/api/*`

Rejected because SSR already has direct backend reachability and should preserve the original request context explicitly.

---

## ADR-008 — Tenant identity is derived from routing, not client-selected state

**Date:** 2026-03  
**Status:** Accepted

### Context

Multi-tenant systems often drift into client-selected tenant IDs passed in payloads or app state. That weakens isolation and complicates trust assumptions.

### Decision

Derive tenant identity from the request host/subdomain.

### Why

- aligns tenant identity with routing
- avoids client-controlled tenant switching in payloads
- simplifies reasoning about request ownership
- pairs naturally with same-origin browser behavior and SSR host forwarding

### Consequence

Frontend code must not invent its own tenant source of truth.
Tenant-aware behavior must follow the current host.

### Rejected alternatives

- tenant ID in request body
- tenant selection in query string
- tenant stored as client-auth state independent of host

## ADR-009 — Documentation home is scope-split, not single-folder-only

**Date:** 2026-03  
**Status:** Accepted

### Context

The repository now has three kinds of active documentation:

- repo-wide truth and architecture documents
- backend law / contract documents
- frontend scope documents that intentionally live close to the frontend surface

Without an explicit rule, future work can create drift by duplicating truth across new folders or by moving backend/frontend docs away from the code they describe.

### Decision

Use a **scope-split documentation home**:

- repo-wide truth lives at repo root and under `/docs`
- backend law/contracts live under `backend/docs/`
- frontend implementation guidance stays close to the frontend surface (`frontend/README.md` and `frontend/src/shared/engineering-rules.md`)

### Why

- keeps repo-wide truth easy to find
- keeps backend contracts and law close to backend code
- keeps frontend guidance close to the frontend implementation surface
- avoids inventing a second parallel home for the same truth

### Consequences

When updating docs:

- change repo-wide status/architecture/decision documents in root `/docs`
- change backend-specific law/contracts in `backend/docs/`
- change frontend-specific guidance where the frontend already keeps it

A new document should not be added until its scope is clear.
If the same fact would need to live in two homes, one of those homes is wrong.
