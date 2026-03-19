# ADR 0003 — Workspace setup state and workspace-setup banner UX

## Status

Accepted (Phase 9)

## Context

After admin onboarding is complete and a workspace is still unconfigured, the auth
module needs to surface workspace configuration. The initial design proposed a
per-membership `FIRST_TIME_SETUP` nextAction that would redirect one admin to
`/admin/settings` exactly once from the auth flow.

That design has two concrete correctness problems:

**Problem 1 — Wrong ownership.** Whether a workspace has been configured is a
fact about the workspace (tenant), not about any individual user's login history.
Using per-membership state to represent workspace state is a domain model error.

**Problem 2 — Race condition.** If five admin invites are sent simultaneously
and all five complete onboarding before any of them visits the settings page, all
five get redirected on first login. Two admins completing onboarding within
milliseconds of each other both read `NULL`, both get redirected, and both trigger
the ack. The "only the first admin sees it" guarantee cannot be made with
per-membership state without a distributed lock.

## Decision

### 1 — Workspace setup state belongs to the tenant, not to individual users

Add `setup_completed_at TIMESTAMPTZ NULL` to the `tenants` table (migration
`0013`). This is the authoritative record of whether workspace configuration has
been acknowledged by any admin.

### 2 — All admins always land on `/admin` — no redirect from the auth flow

The `nextAction` contract is not extended with `FIRST_TIME_SETUP`. The
continuation chain (`MFA_SETUP_REQUIRED` → `MFA_REQUIRED` → `NONE`) is
unchanged. The auth module's routing responsibility ends at landing the admin
on `/admin`.

### 3 — A non-blocking banner on `/admin` surfaces the setup call to action

When `config.tenant.setupCompleted === false`, the admin dashboard shows a
persistent but non-blocking banner:

```
⚙  Workspace setup incomplete
Configure SSO, invite policy, and MFA requirements before inviting your team.
[Open workspace settings →]
```

The banner links to `/admin/settings`. Any admin can dismiss it by visiting
settings. Once any admin visits `/admin/settings`, `setup_completed_at` is
written and the banner disappears for all admins immediately on their next
page load.

### 4 — `setupCompleted` is exposed in `ConfigResponse`

`GET /auth/config` already runs on every SSR bootstrap. Adding
`setupCompleted: boolean` to the existing `ConfigResponse.tenant` shape
means zero extra backend calls are needed — the admin dashboard already has
this value when it renders.

`setupCompleted` is derived as `setup_completed_at IS NOT NULL` by the
backend at read time and is the only field the frontend needs to check.

### 5 — `POST /auth/workspace-setup-ack` marks the workspace as set up

Called by `/admin/settings` SSR on load when `!config.tenant.setupCompleted`.
Requires an authenticated ADMIN session with email verified and MFA verified.
Idempotent: `UPDATE tenants SET setup_completed_at = now() WHERE id = ? AND setup_completed_at IS NULL`.

The ack is tenant-scoped, not user-scoped. One admin visiting settings clears
the banner for all admins.

### 6 — Role-aware `NONE` routing is fixed as part of this phase

`getPathForNextAction('NONE', role)` now accepts `role: MembershipRole`:

- `NONE + ADMIN` → `/admin`
- `NONE + MEMBER` → `/app`

This was a pre-existing bug independent of workspace setup. It is corrected
here because it was discovered during Phase 9 scope and is required for correct
admin landing behaviour.

## Rejected alternatives

### Per-membership `FIRST_TIME_SETUP` nextAction

Rejected. Places workspace state on individual memberships (wrong ownership),
introduces a race condition when multiple admins register simultaneously, and
pollutes the auth continuation contract with a concern that belongs to the
tenant layer. See Context above.

### Blocking first-visit wizard (Slack/Notion style)

Rejected for this phase. A blocking wizard requires coordination state
("is another admin currently setting up?") and a waiting UI for other admins.
Complexity is disproportionate to the current setup surface, which is a
placeholder. This can be added later when real settings content justifies it.

### No setup concept at all

Rejected. The tenant bootstrap flow creates a workspace with no configuration.
Admins need a signal that configuration is expected before they invite more users.
The banner is minimal but provides that signal without blocking anything.

## Consequences

- Migration `0013_tenants_setup_completed_at.ts` adds `setup_completed_at TIMESTAMPTZ NULL` to `tenants`.
- `database.types.ts` gains `setup_completed_at: Timestamp | null` on `Tenants`.
- `Tenant` domain type gains `setupCompletedAt: Date | null`.
- `tenant.queries.ts` maps `setup_completed_at` in `rowToTenant`.
- `auth.types.ts` `ConfigResponse` gains `setupCompleted: boolean`. No change to `AuthNextAction`.
- `get-auth-config.ts` derives `setupCompleted = setup_completed_at IS NOT NULL`.
- `workspace-setup-ack-flow.ts` writes tenant-scoped `setup_completed_at`.
- `POST /auth/workspace-setup-ack` is a new ADMIN-auth-gated endpoint.
- `contracts.ts` (frontend) `ConfigResponse.tenant` gains `setupCompleted: boolean`.
- `/admin/page.tsx` renders a `WorkspaceSetupBanner` when `!config.tenant.setupCompleted`.
- `/admin/settings/page.tsx` is a new real SSR-gated admin route that calls the ack on load.
- `getPathForNextAction` requires `role: MembershipRole` — all callers updated.
- `getPostAuthRedirectPath` requires `role: MembershipRole` — all callers updated.
- All `AuthNextAction` types, route states, and test specs remain clean: no `FIRST_TIME_SETUP`.
