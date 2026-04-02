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
- relevant QA or runbook docs

## Required doc updates included in this PR

List every documentation file updated in this PR because the code or governance truth changed.

If none were required, say:

`None required.`

## Linked update context for protected law/governance files

If this PR changes any protected law or governance file, explain:

1. why the file changed
2. what downstream docs or guardrails were reviewed or updated
3. whether the change affects repo law, review behavior, prompt law, or quality-gate behavior

If this PR does not change protected law or governance files, say:

`Not applicable.`

## Drift / exception notes

List any known drift, temporary mismatch, or reviewer-visible exception introduced or resolved by this PR.

If none, say:

`None.`

If this PR introduces or updates a quality exception record, point to:

- `docs/quality-exceptions.md`

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

## ADR / architecture-law linkage

Fill this section when the PR changes or materially pressures any of the following:

- topology assumptions
- tenant-isolation rules
- auth/session trust boundaries
- security-foundation rules
- repo law or engineering law
- other lasting architectural decisions already governed by ADRs or the decision log

Choose exactly one:

- [ ] ADR updated in this PR
- [ ] New ADR added in this PR
- [ ] Decision log updated in this PR
- [ ] No ADR or decision-log update required

If the last option is checked, explain why no ADR or decision-log update is required.

If not applicable, say:

`Not applicable.`

## Track A signoff evidence

When applicable, provide the exact signoff evidence for the required owner review.

Examples:

- approving review from Lead Architect
- approving review from Designated Quality Owner
- linked review thread with explicit signoff language
- linked comment confirming signoff conditions are satisfied

If signoff is still pending, say:

`Pending owner signoff.`

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

## Quality exception record

Fill this section if this PR introduces, updates, or closes any deferred quality target, refused signoff record, or explicit time-bounded exception.

Required fields when applicable:

- record type: deferred quality target / refused signoff / explicit exception / closure
- record location in `docs/quality-exceptions.md`
- owner
- target resolution date
- reviewer-visible impact

If not applicable, say:

`Not applicable.`

## Refusal / escalation notes

Fill this section only if Track A signoff was refused or merge is proceeding with a documented, time-bounded exception path.

Required when applicable:

- unmet gate
- reason it is unmet
- required remediation
- named owner
- target resolution timeline
- linked record in `docs/quality-exceptions.md`

If not applicable, say:

`Not applicable.`

---

# Release / Change Management

## Release lane

Check exactly one lane from `docs/ops/release-engineering.md`.

- [ ] Lane A — standard code/doc change
- [ ] Lane B — topology / auth / security-sensitive change
- [ ] Lane C — migration-bearing change
- [ ] Lane D — hotfix

## Migration safety

If this PR includes a migration or schema or data-shape change, fill all applicable items.
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

State whether this PR has any deployment, migration, rollback, release coordination, or operator-action needs.

If none, say:

`None.`

## Changelog impact

Choose exactly one disposition and then add the explanation underneath it.

- [ ] `CHANGELOG.md updated in this PR`
- [ ] `No changelog entry required`

Required guidance:

- If `CHANGELOG.md updated in this PR` is checked, summarize what the entry covers.
- If `No changelog entry required` is checked, explain why.
- If this PR is Lane B, Lane C, or Lane D and no changelog entry is required, the reason must be explicit and reviewer-visible.

## Hotfix details

Fill this section only if `Lane D — hotfix` is checked.

If not applicable, say:

`Not applicable.`

Required when applicable:

- one-line incident summary
- blast-radius statement
- exact fix scope
- immediate post-deploy verification owner or owner-ready handoff
- reason this could not wait for the normal change lane

---

# Reviewer Focus

## What reviewers should focus on most

Call out the two or three highest-value review areas for this PR.

Examples:

- auth or session behavior
- tenant isolation
- API contract changes
- migration safety
- SSR or browser boundary changes
- docs or runtime drift
- module boundary fit
