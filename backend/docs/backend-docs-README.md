# backend/docs/README.md

# Backend Docs Map

This folder contains the backend engineering rules, module skeleton, ADRs, and LLM execution prompts. It is the backend documentation hub. Authority over any question is resolved by the hierarchy below — `ARCHITECTURE.md` at the root is the highest authority, not this folder.

---

## Read documents in this order

| #   | File                                        | What it is                                                                                           | Who reads it                                                         |
| --- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| 1   | `ARCHITECTURE.md` _(repo root)_             | Platform architecture law. Bounded contexts, module split, dependency rules, core domain definition. | Everyone. Day one.                                                   |
| 2   | `backend/docs/engineering-rules.md`         | The implementation law. 82 numbered rules. Every PR is checked against this.                         | Every engineer on every PR.                                          |
| 3   | `backend/docs/module-skeleton.md`           | The canonical folder structure and file responsibility contract every module must follow exactly.    | Any engineer adding a module or endpoint.                            |
| 4   | `backend/docs/prompts/module-generation.md` | Turnkey prompt for generating a new module from a business spec. Contains the MODULE SPEC TEMPLATE.  | PM or tech lead writing the spec. LLM in the implementation session. |
| 5   | `backend/docs/prompts/implement.md`         | LLM implementation session protocol. Loaded as system context for every new module session.          | LLM. Engineer verifying the session followed the protocol.           |
| 6   | `backend/docs/prompts/review.md`            | Adversarial LLM review protocol. Loaded when reviewing a completed module or brick.                  | LLM. Engineer running the review session.                            |
| 7   | `backend/docs/adr/`                         | Locked decisions in ADR format. One file per significant decision that should not drift silently.    | Anyone investigating why something was built the way it was.         |

---

## Source of truth hierarchy

When documents conflict, this hierarchy resolves it:

```
ARCHITECTURE.md               ← highest authority — platform shape and laws
    ↓
backend/docs/engineering-rules.md  ← implementation law — how code is written
    ↓
backend/docs/module-skeleton.md    ← structural law — how modules are shaped
    ↓
backend/docs/prompts/*.md          ← derived — must reflect the rules above
    ↓
backend/docs/adr/*.md              ← decision records — explain the decision, context, and consequences
```

**If any document conflicts with `engineering-rules.md` on an implementation question, `engineering-rules.md` wins.**

If `engineering-rules.md` conflicts with `ARCHITECTURE.md` on an architectural question, `ARCHITECTURE.md` wins and `engineering-rules.md` must be updated.

---

## Prompt files — LLM execution artifacts

The files in `backend/docs/prompts/` are **not** general reading material or wiki docs. They are LLM execution artifacts — loaded as system context into an LLM session the same way a config file is loaded into a server. Humans use them by loading them, not by reading them for background.

A change to `engineering-rules.md` that is not reflected in `implement.md` and `review.md` is a bug: generated code will silently violate the new rule.

| File                   | Loaded when                  | Purpose                                                                                                                 |
| ---------------------- | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `module-generation.md` | Starting a new module        | Contains Part 1 (invariant system context), Part 2 (MODULE SPEC TEMPLATE to fill in), and Part 3 (output format rules). |
| `implement.md`         | Every implementation session | Governs the 6-step session protocol: read → spec restatement → plan → full code → commit → wait.                        |
| `review.md`            | Every code review session    | Adversarial review with P0–P3 severity taxonomy, per-layer contract checks, and structured output format.               |

---

## ADRs

`backend/docs/adr/` contains architectural decision records for decisions that would otherwise drift silently. An ADR is required when:

- An architectural boundary rule is overridden (even temporarily)
- A locked decision from `ARCHITECTURE.md` is changed
- A cross-module contract in `modules/_shared/` is introduced or changed
- A new infra primitive is added to `shared/`

ADR filename format: `NNNN-<short-title>.md`. Status must be one of: `PROPOSED | ACCEPTED | SUPERSEDED | DEPRECATED`.

---

## Tier classification

These docs use the three-tier model from `doc-system-design.md`:

| File                           | Tier               | Update trigger                                                 |
| ------------------------------ | ------------------ | -------------------------------------------------------------- |
| `ARCHITECTURE.md`              | 1 — Global Stable  | Architecture shape or bounded context changes                  |
| `engineering-rules.md`         | 1 — Global Stable  | Architecture changes, or deliberate implementation law changes |
| `module-skeleton.md`           | 1 — Global Stable  | Architecture changes, or deliberate structural law changes     |
| `prompts/implement.md`         | 1 — Global Stable  | `engineering-rules.md` or `module-skeleton.md` changes         |
| `prompts/review.md`            | 1 — Global Stable  | `engineering-rules.md` changes                                 |
| `prompts/module-generation.md` | 1 — Global Stable  | `engineering-rules.md` or `module-skeleton.md` changes         |
| `adr/*.md`                     | 2 — Global Growing | New decision or status change                                  |

Tier 1 documents are written once and updated deliberately — not per-module, not per-PR. If you feel the need to edit a Tier 1 document for a specific module, the module likely has the wrong design, not the document.
