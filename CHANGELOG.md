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

- Added `docs/ops/release-engineering.md` as the repo’s release-engineering baseline covering release lanes, merge gates, migration safety, rollback expectations, post-change verification, incident severity, hotfix handling, and ownership metadata expectations.
- Added `CHANGELOG.md` as the repo’s human-written release-relevant history surface.

### Changed

- Updated `docs/current-foundation-status.md` to reflect the current repo truth more precisely, including the distinction between completed foundations, baseline-complete areas, partial enforcement layers, and the in-repo release-engineering baseline.
- Updated `README.md` to match the real current command, host, stack, and verification behavior.
- Updated `infra/README.md` to clarify host-run versus full-topology local modes and the correct proof path for topology-sensitive changes.
- Updated `docs/developer-guide.md` to match current setup, env, seed/bootstrap, test, and Playwright behavior.
- Updated `.github/pull_request_template.md` to require clearer release, rollback, migration-safety, and post-change verification notes.
- Updated `scripts/repo-guard.mjs` to enforce the current PR release-management structure and migration-bearing PR expectations.
- Updated `.github/CODEOWNERS` to expand ownership metadata across major repo areas using valid CODEOWNERS glob patterns.

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
