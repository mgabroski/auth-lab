# CONTRIBUTING.md

---

## Before you write a single line

Read these four documents in order. All of them. Not just the sections that seem relevant.

1. `ARCHITECTURE.md` — the platform architecture law and bounded context definitions
2. `backend/docs/README.md` — the docs map for backend engineering
3. `backend/docs/engineering-rules.md` — the implementation law every PR is checked against
4. `backend/docs/module-skeleton.md` — the canonical structure every module must follow

If you are generating a new module with an LLM, also read:

- `backend/docs/prompts/module-generation.md` — the spec template and generation workflow
- `backend/docs/prompts/implement.md` — the implementation session protocol
- `backend/docs/prompts/review.md` — the adversarial review protocol

---

## The standards that are never optional

These apply to every PR, every module, every file, every commit.

**Module boundaries.** Every module's internal layers (`dal/`, `queries/`, `policies/`, `flows/`) are private. Other modules import only from `index.ts`. If you need something from another module and it is not exported, export it — do not reach in.

**Transaction ownership.** Only flow files open `db.transaction()`. Services do not. Repos do not. If a service method owns rate limiting, a transaction, and audit writing, it is a flow that has not been extracted yet.

**Two-phase audit.** Success audits commit inside the transaction atomically with the data. Failure audits are written in the `catch` block using the bare `auditRepo` — never `.withDb(trx)`. Both must exist for every mutation flow.

**Tenant isolation.** Every query on tenant-owned data includes a `tenant_id` WHERE clause. Cross-tenant access returns 404, not 403. Tenant identity comes from the URL subdomain — never from the request body or headers.

**No raw PII in logs or audit metadata.** Hash first. `email → emailKey`, `ip → ipKey`, `token → tokenHash`. This is not optional for GDPR compliance.

**Outbox for all side effects.** Email sending and any external API call triggered by a mutation must go through the DB outbox. The outbox row is enqueued inside the same transaction as the triggering mutation.

---

## Before opening a PR

Run all three of these. All three must pass with zero errors or failures:

```bash
cd backend
yarn lint
yarn typecheck
yarn test
```

Then verify the PR fitness checklist in `backend/docs/engineering-rules.md` section 15. Work through every applicable item for your changed files. Do not mark a PR ready if you have not done this check.

---

## Adding a new module

1. Fill in the MODULE SPEC TEMPLATE in `backend/docs/prompts/module-generation.md` (Part 2). Every `[FILL]` field must have a precise answer before any code is written. Vague business rules produce wrong behavior.
2. Open an implementation session with `backend/docs/prompts/implement.md` as the LLM system prompt.
3. The LLM produces the full module. Engineering reviews and merges — not rewrites.
4. After merge, the engineering review is the gate. Not CI alone.

---

## Adding a new endpoint to an existing module

1. Add the route to `<module>.routes.ts` — one line.
2. Add the handler method to `<module>.controller.ts` — Zod parse + service call + reply.
3. Add a facade method to `<module>.service.ts` — one line.
4. Add a flow file to `flows/<use-case>/execute-<use-case>-flow.ts`.
5. Add any new repo methods, query functions, or policies needed by the flow.
6. Add the audit helper to `<module>.audit.ts` and add the action string to `KnownAuditAction` in `src/shared/audit/audit.types.ts`.
7. Add tests: E2E (happy path + DB assertion + audit assertion + business rule failures), DAL, unit for each policy branch.

---

## Adding a new audit event

1. Write the typed helper in `<module>.audit.ts`:

```typescript
export function auditMyAction(
  writer: AuditWriter,
  data: { fieldA: string; fieldB: string },
): Promise<void> {
  return writer.append('mymodule.myaction', {
    fieldA: data.fieldA,
    fieldB: data.fieldB,
  });
}
```

2. Add the action string to `KnownAuditAction` in `src/shared/audit/audit.types.ts`.

3. Call the helper from the flow — never call `writer.append()` directly in a flow file.

---

## Adding a new migration

```bash
cd backend
yarn db:make <description>       # scaffolds NNNN_<description>.ts
# fill in up() and down()
yarn db:migrate                   # apply
yarn db:types                     # regenerate database.types.ts
```

Commit the migration file and the regenerated `database.types.ts` in the same PR. Never edit a migration that has been applied to any environment.

---

## When documentation must be updated

Update docs when you change:

| What changed                                                     | Which docs to update                                                    |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Architecture shape, bounded context definitions, or module split | `ARCHITECTURE.md`                                                       |
| An engineering rule, layer responsibility, or prohibited pattern | `backend/docs/engineering-rules.md` + relevant prompt files             |
| The canonical module folder structure or file responsibility     | `backend/docs/module-skeleton.md` + `backend/docs/prompts/implement.md` |
| A module's public surface (`index.ts` exports)                   | File header + any consuming module's comments                           |
| A significant technical decision that should not drift silently  | Add an ADR to `backend/docs/adr/`                                       |

When `engineering-rules.md` changes, also update `backend/docs/prompts/implement.md` and `backend/docs/prompts/review.md` to reflect the change. The three files are coupled — a rule that is in the rules file but not in the prompts will not be enforced in LLM-generated code.

---

## ADRs

Significant decisions that would otherwise drift silently belong in `backend/docs/adr/`. An ADR is required when:

- An architectural boundary rule is being overridden (even temporarily)
- A locked decision from `ARCHITECTURE.md` is being changed
- A cross-module contract in `modules/_shared/` is being introduced or broken
- A new infra primitive is being added to `shared/`

Format: `backend/docs/adr/NNNN-<short-title>.md`. Use the template in `backend/docs/adr/README.md` (create it if it does not exist). Status field must be one of: `PROPOSED | ACCEPTED | SUPERSEDED | DEPRECATED`.

---

## What a good PR looks like

- **Small.** Does one thing. The PR title describes that one thing.
- **Reversible.** Can be reverted in a single commit if needed.
- **Tested.** Every mutation endpoint has an E2E test. Every policy has unit tests. Every repo write has a DAL test.
- **Aligned.** Passes the PR fitness checklist in `engineering-rules.md` section 15.
- **Documented.** If it changes an architectural boundary or cross-module contract, an ADR or doc update is included.

A PR that passes `yarn lint && yarn typecheck && yarn test` but violates a [HARD] rule in `engineering-rules.md` is not ready to merge. Tests verify behavior — they do not verify architecture.

---

## Known legacy violations

`backend/docs/engineering-rules.md` may contain a small set of documented legacy violations during active cleanup. Do not add new violations. Do not treat an existing documented exception as precedent for new code.
