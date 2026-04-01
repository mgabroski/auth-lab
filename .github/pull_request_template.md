# Pull Request Summary

## What changed

Describe the change in plain language.

## Why this change exists

Describe the problem, goal, or risk this PR addresses.

## Scope notes

State what is intentionally in scope and what is intentionally out of scope.

---

# Linked Update Context

## Governing docs reviewed

List the repo-level or area-level docs you reviewed for this PR.

Examples:

- `docs/quality-bar.md`
- `docs/current-foundation-status.md`
- `docs/ops/release-engineering.md`
- `docs/ops/runbooks.md`
- `AGENTS.md`
- `backend/AGENTS.md`
- `frontend/AGENTS.md`
- `code_review.md`
- `ARCHITECTURE.md`
- `docs/decision-log.md`
- `docs/security-model.md`
- `docs/security/threat-model.md`
- relevant API docs
- relevant QA/runbook docs

## Required doc updates included in this PR

List every documentation file updated in this PR because the code or governance truth changed.

If none were required, say:

`None required.`

## Linked update context for protected law/governance files

If this PR changes any protected law or governance file, explain:

1. why the file changed
2. what downstream docs or guardrails were reviewed or updated
3. whether the change affects repo law, review behavior, prompt law, or quality-gate behavior

If this PR does not change protected law/governance files, say:

`Not applicable.`

---

# Validation

## What I ran

List the actual commands, tests, or checks you ran.

## What I did not run

List important checks not run yet, if any.

## Risk notes

Call out any migration, rollout, auth, tenant, topology, or operational risk that reviewers should pay extra attention to.

If none, say:

`No special risk notes.`

---

# Module Quality Gate

Complete this section for any PR that introduces or substantially expands a major module.

If not applicable, check the first box and leave a short reason.

## Applicability

- [ ] Not applicable — this PR does not introduce or substantially expand a major module
- [ ] Applicable — this PR introduces or substantially expands a major module

If not applicable, reason:

<!-- Add one sentence. Example: "Small change inside an existing module; no new route/API surface, schema impact, or major boundary expansion." -->

## Mandatory gates

When applicable, confirm the status of each mandatory gate from `docs/quality-bar.md`.

- [ ] Architecture fit and boundary review completed or explicitly linked
- [ ] Required API or contract documentation updated or explicitly linked
- [ ] Minimum test coverage at the right levels exists or is explicitly linked
- [ ] Failure-mode and security review proportional to risk completed or explicitly linked
- [ ] Observability touchpoints reviewed and updated if needed
- [ ] Runbook and ops impact reviewed and updated if needed
- [ ] Migration safety reviewed if schema or data-shape changes are involved
- [ ] Track A signoff requested from Lead Architect or Designated Quality Owner

## Evidence / links

When applicable, link the concrete evidence for the checked items above.

Examples:

- architecture review notes
- API doc update
- test files or CI runs
- security or topology review
- runbook update
- migration notes
- signoff comment or review link

If not applicable, say:

`Not applicable.`

## Deferred quality targets

List any explicitly deferred quality targets allowed by `docs/quality-bar.md`, including:

- deferred item
- reason
- owner
- target date

If none, say:

`None.`

---

# Release / Change Management

## Release lane

Check exactly one lane from `docs/ops/release-engineering.md`.

- [ ] Lane A — standard code/doc change
- [ ] Lane B — topology / auth / security-sensitive change
- [ ] Lane C — migration-bearing change
- [ ] Lane D — hotfix

## Migration safety

If this PR includes a migration or schema/data-shape change, fill all applicable items.
If not applicable, say:

`Not applicable.`

Required when applicable:

- migration class: Class 1 / Class 2 / Class 3
- can old code still run safely after this migration?
- can new code still run safely before this migration?
- rollback path
- post-migration verification steps

## Rollback expectation

State the rollback expectation for this change.

Examples:

- `None — docs/test-only change.`
- `Redeploy previous app code only; migration is backward-compatible.`
- `Follow-up revert migration required.`
- `Manual DB recovery step required; see notes.`

## Post-change verification

List the exact checks that must be performed after the change is applied in the target environment.

If none, say:

`None.`

## Deployment / release notes

State whether this PR has any deployment, migration, rollback, or release coordination needs.

If none, say:

`None.`

## Changelog impact

State whether this PR should produce a changelog or release-note entry.

If none, say:

`None.`

---

# Reviewer Focus

## What reviewers should focus on most

Call out the two or three highest-value review areas for this PR.

Examples:

- auth/session behavior
- tenant isolation
- API contract changes
- migration safety
- SSR/browser boundary changes
- docs/runtime drift
- module boundary fit
