# backend/docs/adr/0002-outbox-payload-encryption-key-rotation.md

## Status

Accepted

## Context

Auth-Lab stores email-delivery side effects in Postgres (`outbox_messages`). These rows contain:

- encrypted tokens (password reset, invite accept, email verification)
- encrypted recipient email (`toEmailEnc`)

This table is durable and will exist for the lifetime of the service. Even if application code is correct,
operational reality requires:

- secrets rotation (scheduled rotations, incident rotations)
- safe multi-key decryption during a transition window
- explicit behavior when an old key is removed

## Decision

Outbox encrypted fields are versioned and self-describing:

- Every encrypted field is stored as: `<version>:<ciphertext>`
  - Example: `v1:AbCdEf...`
- A single default encryption version is locked in config:
  - `OUTBOX_ENC_DEFAULT_VERSION` (default: `v1`)
- Keys are provided per version:
  - `OUTBOX_ENC_KEY_V1` (required)
  - `OUTBOX_ENC_KEY_V2` (optional)
  - `OUTBOX_ENC_KEY_V3` (optional)
  - (extendable to `V4+`)

Encryption uses the default version. Decryption uses the version prefix from the stored ciphertext.

## Key Rotation Procedure

1. Add a new key:
   - Set `OUTBOX_ENC_KEY_V2` in the environment.
   - Keep `OUTBOX_ENC_DEFAULT_VERSION=v1`.
   - Deploy.
   - Result: system can decrypt both `v1` and `v2`, but still encrypts as `v1`.

2. Flip default encryption:
   - Set `OUTBOX_ENC_DEFAULT_VERSION=v2`.
   - Deploy.
   - Result: new outbox rows encrypt as `v2`, old rows remain decryptable via `v1`.

3. Drain the old-key window (optional but recommended):
   - Wait until all `v1` rows are processed (or expire) under your operational policy.

4. Remove old key:
   - Remove `OUTBOX_ENC_KEY_V1` from the environment.
   - Deploy.
   - Result: any remaining `v1:` outbox rows will fail decryption and will be dead-lettered
     with an explicit `decrypt_failed` error. This is intentional: missing key is a hard failure.

## Consequences

- The outbox table never stores raw email or raw tokens.
- Operator error is explicit:
  - missing version prefix => worker hard-fails that row (dead-letter)
  - unknown version => worker hard-fails that row (dead-letter)
  - missing key => worker hard-fails that row (dead-letter)
- Rotation does not require DB migrations or backfills.
- This design makes the “correct” operational playbook obvious and repeatable.

## Alternatives Considered

1. Single key without versioning
   - Rejected: forces DB backfill or breaks old rows on rotation.

2. Storing key-version in a separate column
   - Rejected: adds schema coupling and makes encrypted fields less self-contained.

3. Making outbox “PII-bearing” instead of encrypting email
   - Rejected: increases permanent operational overhead; encryption is simpler and safer.
