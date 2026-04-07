# Prompt Catalog

Use this file only to choose the right prompt.

This is a router.
It is not a substitute for architecture, security, contract, or module-design truth.

---

## Read This First

Before selecting any prompt, load the repo truth in the normal order:

1. `docs/current-foundation-status.md`
2. `ARCHITECTURE.md`
3. `docs/security-model.md`

Then choose the prompt that matches the task.

If the task is about introducing, analyzing, or fully designing a new module, you must load `docs/module-design-framework.md` before selecting a module planning prompt.

---

## Prompt Routing

### 1. Implement

Use when the design is already clear and the task is to add or change implementation inside the existing repo rules.

Load:

- `docs/prompts/implement.md`

Use for:

- normal backend implementation work
- normal frontend implementation work
- incremental feature work inside an already-designed area

Do not use this as a substitute for unfinished product or module design.

---

### 2. Review

Use when the task is to review code, detect drift, challenge assumptions, or audit correctness.

Load:

- `docs/prompts/review.md`

Use for:

- adversarial review
- implementation audit
- architecture drift checks
- contract or behavior review

---

### 3. Refactor

Use when behavior should stay the same but the internal structure must improve.

Load:

- `docs/prompts/refactor.md`

Use for:

- cleanup without behavior expansion
- code movement or restructuring
- safer internal simplification

---

### 4. Module Generation — Full Stack

Use when the task is to produce one integrated planning artifact for a brand-new module or a major new bounded context.

Load in this order:

1. `docs/module-design-framework.md`
2. `backend/docs/module-skeleton.md` when backend work is in scope
3. `frontend/docs/module-skeleton.md` when frontend work is in scope
4. `docs/prompts/module-generation-fullstack.md`

Use for:

- full module planning
- backend + frontend + docs + proof planning in one session
- forcing design completeness before file planning

Do not use this prompt to skip module-design work.
If the module-design framework still shows major unknowns, stop and resolve those first.

---

## Fast Decision Table

### I already know the module and just need implementation help

Use:

- `implement.md`

### I need to challenge or audit something

Use:

- `review.md`

### I need to restructure code without changing behavior

Use:

- `refactor.md`

### I need to introduce or fully plan a new module

Use:

- `module-generation-fullstack.md`

But only after loading:

- `docs/module-design-framework.md`

---

## Hard Rules

- Do not use a prompt as a replacement for repo truth.
- Do not use `module-generation-fullstack.md` before the module-design framework is loaded.
- Do not treat prompt docs as higher authority than architecture, security, or shipped-truth docs.
- If a prompt conflicts with repo law, update the prompt.

---

## Final Position

This catalog chooses prompts.
It does not decide the product, architecture, or module design.

The new required gate for future-module work is `docs/module-design-framework.md`.
Prompt choice happens after that.
