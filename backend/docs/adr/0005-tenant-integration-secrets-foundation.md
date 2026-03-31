# ADR 0005 — Tenant Integration Secrets Foundation

## Status

Accepted

## Date

2026-03-31

## Owners

Lead Architect / Designated Quality Owner

---

## Context

The wider Hubins design already identified a real blocker:
secret-bearing tenant integrations must not be implemented by storing credentials in plain tenant config JSON.

That blocker is valid for this repository too.
The auth/provisioning repo already contains strong security handling for platform-owned secret material:

- MFA secret encryption key
- MFA recovery-code HMAC key
- SSO state encryption key
- outbox encryption keys
- SMTP and OAuth credentials

However, the repository does **not** yet have a reusable foundation for tenant-configured integration secrets such as:

- per-tenant OAuth client secrets
- HRIS API keys
- Stripe secrets
- service-account private material
- provider refresh tokens or access credentials

Without an explicit foundation, future implementation pressure creates a predictable failure mode:
engineers start storing secret-bearing tenant values in a convenient JSON blob because the product/config model already exists.
That would be a security regression and a design trap.

This ADR exists to lock the foundation before those integrations are implemented.

---

## Decision

The repository adopts the following secrets-management foundation for tenant-configured integrations.

## 1. Tenant integration secrets must not be stored in plain config JSON

Security-sensitive tenant integration values must never be stored directly in `config_json`, DTO payload echoes, exports, logs, audit payloads, or admin page bootstrap responses.

Examples of prohibited direct storage in plain config JSON include:

- API keys
- client secrets
- webhook signing secrets
- provider refresh tokens
- service-account private keys
- SMTP credentials for tenant-owned providers

Non-secret operational values may still live in normal config storage, for example:

- provider enabled/disabled flags
- account IDs or tenant IDs that are not confidential
- mapping rules
- sync cadence configuration
- last successful sync timestamp
- non-secret redirect/base URLs

## 2. Secret-bearing config is split into two layers

Every tenant integration configuration is split into:

### Layer A — operational config

Safe, non-secret values stored in normal tenant configuration records.

### Layer B — secret material

Secret values stored through a dedicated secret-management abstraction and referenced indirectly from normal config.

This means normal config may store metadata such as:

- secret reference ID
- secret version
- provider key identifier
- last rotation timestamp
- validation status

But it must not store the raw secret value itself.

## 3. The foundation is abstraction-first, vendor-neutral

This ADR does **not** lock the repo to a specific secret backend vendor.
That is intentional.

Stage 4 needs a durable security foundation, not premature vendor commitment.

The repository therefore standardizes the abstraction and behavioral contract first.
A later implementation ADR may map this abstraction to a concrete backend such as:

- cloud secret manager
- vault service
- encrypted database-backed secret store
- platform-specific key-management system

Vendor choice is deferred.
The safety contract is not.

## 4. Secret operations must fail closed

If secret retrieval, version resolution, decryption, or provider-binding validation fails, the dependent integration must fail closed.

That means:

- no partial enablement
- no silent fallback to insecure/default values
- no “best effort” provider calls with missing secret material
- no fake Connected/Ready status in the UI when the secret layer is broken

The system may show a blocked or invalid configuration state, but it must not proceed as though the secret were available.

## 5. Secret reads are purposeful and minimal

The platform should retrieve secret material only for operations that actually require it, such as:

- testing a provider connection
- refreshing a provider token
- signing a request
- calling an upstream API

Secrets must not be fetched just to populate settings pages or overview payloads.
Admin UI surfaces may display status metadata, but not raw secret values.

## 6. Secret writes are replace/rotate operations, not normal config echoes

Secret values should be written through explicit set/replace/rotate operations.
They must not round-trip through generic update DTOs that later appear in:

- page bootstrap payloads
- audit diffs
- debug logs
- export jobs

The system may support secret replacement and rotation metadata, but secret material itself remains write-only from the perspective of normal admin flows.

## 7. Audit and observability must describe the action, not the secret

The platform may audit and log events such as:

- integration secret created
- integration secret rotated
- integration secret deleted
- provider credential validation succeeded/failed

But logs and audit payloads must never contain the raw secret value.

Allowed metadata examples:

- integration key
- tenant ID
- actor ID
- secret version label
- timestamp
- validation outcome

Disallowed examples:

- API key content
- refresh token content
- private key PEM content
- SMTP password

## 8. Secret lifecycle status must be modeled separately from business config status

An integration may be:

- allowed by CP/platform rules
- configured at the operational level
- blocked because secret material is missing or invalid

That separation is important.
A system must not collapse these into one vague “configured” boolean.

## 9. Rotation must be part of the foundation, not an afterthought

The abstraction must support secret versioning/rotation semantics, even if the first concrete implementation is simple.

At minimum, the design must allow:

- replacing current secret material safely
- tracking a current version identifier
- invalidating superseded secret material
- re-validating the dependent integration after rotation

## 10. Until this foundation exists in runtime code, secret-bearing tenant integrations remain blocked

This ADR is not permission to ship tenant-configured secret-bearing integrations immediately.

It is the prerequisite foundation decision.
Until the runtime abstraction and storage path exist, integrations that require tenant-managed secrets remain intentionally blocked/deferred.

---

## Consequences

### Positive

- prevents the most likely future security shortcut: plain secrets in config JSON
- keeps current product/config design compatible with a secure implementation path
- allows UI, DTO, and settings work to distinguish secret metadata from secret material
- makes later provider work safer and easier to review

### Costs / tradeoffs

- adds an abstraction layer before some integrations can ship
- requires status modeling that distinguishes “allowed,” “configured,” and “blocked by secrets”
- delays secret-bearing tenant integrations until the implementation brick is real

### Practical consequence for current repo scope

For the current repository baseline:

- Google/Microsoft SSO used by the platform itself may continue using platform-owned credentials already handled through env/config
- tenant-configured secret-bearing integrations remain deferred until this abstraction is implemented

---

## Required implementation properties

When the runtime implementation lands, it must satisfy all of the following:

1. raw secret values are never stored in normal config JSON
2. raw secret values are never returned by normal read APIs
3. secret retrieval failures fail closed
4. integration readiness distinguishes secret-state problems from business-config completeness
5. secret mutation is explicit and auditable
6. rotation metadata is supported
7. tests cover missing secret, invalid secret, rotated secret, and blocked-state behavior

---

## Alternatives considered

## A. Store tenant integration secrets directly in encrypted config JSON

Rejected.
Even if encrypted at rest, this still encourages broad exposure through generic config reads, diffs, exports, and logs unless every surrounding surface is redesigned around that choice.
It creates a fragile and easy-to-misuse model.

## B. Reuse existing app encryption helpers and store ciphertext in normal tables

Rejected as the default foundation.
Those helpers solve cryptographic transformation, not full secret lifecycle separation.
They do not by themselves provide the correct operational model for write-only secrets, reference indirection, status handling, and rotation discipline.

## C. Choose a vendor-specific secret backend now

Deferred.
Vendor lock is not required to establish the security contract.
The repo first needs the correct abstraction and fail-closed semantics.

---

## Operational notes

- settings/admin UIs may show secret presence, validation status, and last-rotated metadata
- settings/admin UIs must not display stored secret values back to the operator after save
- deleting or invalidating a tenant integration secret must place the dependent integration into a blocked/non-ready state immediately
- export or diagnostic tooling must treat secret references and secret values as different sensitivity classes

---

## Follow-up work

This ADR requires later implementation work, including:

- concrete secret-store interface in backend code
- storage/reference model for tenant integration secrets
- readiness/status handling for integrations that depend on secret presence/validity
- tests for secret absence, invalidity, replacement, and rotation
- eventual concrete backend selection ADR if needed

---

## Links

- `docs/security/threat-model.md`
- `docs/security-model.md`
- `docs/ops/runbooks.md`
- broader Settings / Integrations design material that marked this foundation as blocked until explicitly solved
