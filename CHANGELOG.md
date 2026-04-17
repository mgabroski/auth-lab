# Changelog

All notable release-relevant changes to this repository should be recorded in this file.

This changelog is intentionally human-written.
It exists to capture changes that matter to:

- users
- operators
- reviewers
- release owners
- incident responders

This file does **not** need to list every internal refactor.
It should focus on changes that materially affect:

- runtime behavior
- auth or tenant-isolation behavior
- topology or proxy behavior
- migrations or rollback expectations
- security posture
- operational handling
- release coordination

The format is based on Keep a Changelog principles, adapted to the current repo reality.

---

## [Unreleased]

### Added

- Added `docs/ops/release-engineering.md` as the repo’s release-engineering contract covering release lanes, applicable merge gates, migration safety, rollback expectations, post-change verification, incident severity, hotfix handling, changelog discipline, and explicit external GitHub-control dependencies.
- Added `CHANGELOG.md` as the repo’s human-written release-relevant history surface.

### Changed

- Updated `docs/current-foundation-status.md` to reflect the current repo truth more precisely, including that Stage 5 practical closure is now completed to the strongest honest repo-visible depth, while external GitHub branch-protection and required-review behavior remain explicit external dependencies.
- Updated `README.md` to match the real current command, host, stack, and verification behavior.
- Updated `infra/README.md` to clarify host-run versus full-topology local modes and the correct proof path for topology-sensitive changes.
- Updated `docs/developer-guide.md` to match current setup, env, seed/bootstrap, test, and Playwright behavior.
- Updated `.github/pull_request_template.md` to require clearer release-lane, rollback, migration-safety, post-change verification, hotfix, and changelog-disposition notes.
- Updated `scripts/repo-guard.mjs` to enforce stronger Stage 5 release-management truth, including hotfix-detail requirements and changelog-disposition consistency with actual `CHANGELOG.md` changes.
- Updated `.github/workflows/repo-guard.yml` so standalone changes to `CHANGELOG.md` and `.github/CODEOWNERS` cannot bypass repo guard enforcement.
- Updated `.github/workflows/backend-tests.yml` so root dependency-surface changes such as root `package.json`, `yarn.lock`, and repo Yarn config still trigger backend CI.
- Updated `.github/workflows/frontend.yml` so root dependency-surface changes such as root `package.json`, `yarn.lock`, and repo Yarn config still trigger frontend CI and Playwright auth smoke coverage.
- Updated `.github/CODEOWNERS` to expand ownership metadata across major repo areas using valid CODEOWNERS glob patterns.
- Updated `README.md`, `docs/qa/qa-execution-pack.md`, `docs/ops/runbooks.md`, `docs/security-model.md`, and `docs/decision-log.md` so the shipped CP surface, QA execution path, bounded-risk note, and operational recovery guidance now match the real current implementation.
- Updated stale CP/backend module comments so they describe the current shipped CP surface rather than earlier phase-only placeholders.
- Updated `docs/prompts/catalog.md` to remove ghost references to prompt files that are not part of the approved prompt inventory.

### Fixed

- Fixed the CP integrations validation path to use an integration-scoped validation error instead of incorrectly reusing the personal-validation error factory.
- Renamed the CP server-side account loader facade away from `mock-data.ts` so the file name matches its real runtime role.

---

## Release entry template

Use this template when adding a new release-relevant entry.

```md
## [YYYY-MM-DD]

### Added

- ...

### Changed

- ...

### Fixed

- ...

### Removed

- ...
```

---

## Changelog writing rules

- Prefer clear operational language over marketing language.
- Record the effect of the change, not just the file touched.
- Mention migrations when they exist.
- Mention rollback or operator impact when relevant.
- Mention tenant-isolation, auth, proxy, or security implications when relevant.
- Do not claim automation or environment behavior that the repo does not actually have.
- Group trivial related changes into one meaningful entry instead of many tiny noisy bullets.
