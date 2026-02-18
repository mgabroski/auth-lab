# Refactor Safety Rules (Auth-Lab)

This repo is refactored in **small, test-gated batches** to preserve behavior and reduce risk.

## Non-negotiable rules

1. **One batch = one intent**
   - Examples:
     - “move queries into queries/ folder”
     - “extract one policy + add unit tests”
     - “extract login flow into flows/”
   - Never mix “move files” + “logic changes” in the same batch.

2. **Move-only batches must be behavior-identical**
   - Allowed: file moves, renames, import path updates.
   - Not allowed: logic changes, signature changes, different error codes, different log/audit payloads.

3. **Every batch has a test gate**
   - At minimum: run the relevant tests for the touched area.
   - At phase gates: run the full suite.

4. **Rollback must be trivial**
   - If a batch causes unexpected behavior or breaks tests:
     - revert the commit
     - re-apply with smaller scope

5. **No boundary violations**
   - Transactions only in service/use-cases.
   - DAL stays dumb SQL.
   - Policies are pure.

## Standard workflow per batch

1. Create a branch: `refactor/<phase>-<step>-<short-name>`
2. Make the smallest change that fulfills the step.
3. Run the tests for the impacted area.
4. Commit with clear message: `refactor(phase-x): <step> <what>`
5. If clean, merge; if not, revert and shrink.

## Test commands (fill with your repo scripts)

- Unit/DAL tests:
  - `yarn test test/dal`
- E2E tests:
  - `yarn test test/e2e`
- Full suite:
  - `yarn test`

> If your scripts differ, update this doc once and treat it as the source of truth.
