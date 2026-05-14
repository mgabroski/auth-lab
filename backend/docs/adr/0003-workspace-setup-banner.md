# ADR 0003 — Workspace setup state and workspace-setup banner UX

## Status

Accepted as historical auth-phase scaffold. Superseded for current Settings setup truth by the Settings-native bootstrap and readiness-gate closure.

Current implementation note: this ADR explains why the repo originally added tenant-scoped workspace setup acknowledgement during auth closure. The active Settings implementation no longer uses auth as a Settings writer. `/admin` now reads Settings-native bootstrap truth, and auth no longer exposes a workspace-setup acknowledgement mutation.

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
`0013`) for the original auth-phase scaffold. That column is now a retired compatibility/backfill artifact, not the authoritative Settings setup record.

### 2 — All admins always land on `/admin` — no redirect from the auth flow

The `nextAction` contract is not extended with `FIRST_TIME_SETUP`. The
continuation chain (`MFA_SETUP_REQUIRED` → `MFA_REQUIRED` → `NONE`) is
unchanged. The auth module's routing responsibility ends at landing the admin
on `/admin`.

### 3 — A non-blocking banner on `/admin` surfaces the setup call to action

During the auth-phase scaffold, when `config.tenant.setupCompleted === false`, the admin dashboard showed a
persistent but non-blocking banner:

```
⚙  Workspace setup incomplete
Configure SSO, invite policy, and MFA requirements before inviting your team.
[Open workspace settings →]
```

The current Settings implementation keeps the same non-blocking user experience, but the banner is now driven by `GET /settings/bootstrap` and Settings-owned persisted setup state. Visiting `/admin/settings` no longer writes auth-owned setup acknowledgement state.

### 4 — `setupCompleted` is exposed in `ConfigResponse`

`GET /auth/config` originally exposed `setupCompleted: boolean` during the auth-phase scaffold.

In the current Settings implementation, `setupCompleted` remains only as a compatibility field derived from `setup_completed_at IS NOT NULL`. It is not used by `/admin` or `/admin/settings` for Settings setup truth.

### 5 — Historical scaffold acknowledgement endpoint is retired

The auth-phase scaffold used an authenticated tenant-scoped acknowledgement endpoint to write `setup_completed_at`. That endpoint is no longer part of the active API surface.

Current behavior: Settings setup progress is changed only by Settings-owned mutations such as Access acknowledgement, Account card saves, Personal full replacement save, and CP-driven cascade handling. The retired auth acknowledgement route must not act as a competing Settings writer.

### 6 — Role-aware `NONE` routing is fixed

`getPathForNextAction('NONE', role)` now accepts `role: MembershipRole`:

- `NONE + ADMIN` → `/admin`
- `NONE + AGENT` → `/app`
- `NONE + USER` → `/app`
- legacy `MEMBER` normalizes to `USER` before route selection

This was a pre-existing bug independent of workspace setup. It is corrected
here because it was discovered during workspace setup closure and is required for correct
admin landing behaviour.

## Rejected alternatives

### Per-membership `FIRST_TIME_SETUP` nextAction

Rejected. Places workspace state on individual memberships (wrong ownership),
introduces a race condition when multiple admins register simultaneously, and
pollutes the auth continuation contract with a concern that belongs to the
tenant layer. See Context above.

### Blocking first-visit wizard (Slack/Notion style)

Rejected for this shipped model. A blocking wizard requires coordination state
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
- The historical auth acknowledgement flow has been retired from the active API surface.
- `setupCompleted` remains in auth config only as compatibility metadata, not as current Settings truth.
- `contracts.ts` (frontend) `ConfigResponse.tenant` gains `setupCompleted: boolean`.
- `/admin/page.tsx` renders `WorkspaceSetupBanner` from `GET /settings/bootstrap`.
- `/admin/settings/page.tsx` is a real SSR-gated admin route that reads `GET /settings/overview`; it does not call an auth acknowledgement endpoint.
- `getPathForNextAction` requires `role: MembershipRole` — all callers updated.
- `getPostAuthRedirectPath` requires `role: MembershipRole` — all callers updated.
- All `AuthNextAction` types, route states, and test specs remain clean: no `FIRST_TIME_SETUP`.
