# Hubins — New Module Introduction Framework

## 1. Purpose of This Framework

This framework defines the mandatory thinking cycle Hubins must use every time a new module is introduced.

Its purpose is to prevent shallow module design, prevent settings drift, and prevent the team from declaring a module “done” before the full Hubins model has been evaluated.

This framework exists because a new Hubins module is never only a business/domain module. It must also be evaluated as a tenant-facing settings adapter.

That means every new module must be analyzed through six connected lenses:

1. Module Truth
2. Module Settings
3. Permission & Policy Management
4. Workspace Experience
5. Communications
6. Fail-Closed / Removal / Orphan Behavior

This framework is reusable, project-level, and intentionally strict. It is designed for both human readers and LLM readers.

---

## 2. How This Framework Fits the Existing Hubins Model

This framework does not introduce a new philosophy. It applies the already locked Hubins philosophy to all future modules.

The existing Hubins model is already locked around these principles:

- CP grants the allowed universe.
- Hubins tenant admins configure within that universe.
- Policies later control access.
- Communications is a first-class tenant domain.
- Workspace Experience is a first-class tenant domain.
- Policies are not CP-owned.
- Required-removal changes can trigger Needs Review.
- Optional removals orphan quietly and fail closed where needed.

This framework converts those locked truths into a repeatable design method.

It also fits the documentation system already locked in the project:

- stable global documents should stay stable
- growing domain outputs should stay domain-owned
- documentation should not duplicate code or create ad hoc sprawl
- reusable guidance should be clear enough for future LLM sessions to apply without reinterpretation

This framework is therefore a Tier 1 style reusable source: a stable project-level law for future module-introduction work.

---

## 3. Core Principle: Every New Module Is Also a Settings Adapter

A new Hubins module must always be designed twice at the same time:

1. as a domain module
2. as a settings adapter

The domain view answers:

- what the module is
- what it owns
- what objects it manages
- what states and actions exist
- what business outcomes it supports

The settings-adapter view answers:

- what CP is allowed to grant for this module
- what tenant admins can shape later
- what policy targets the module creates
- what workspace surfaces appear or disappear
- what communications moments the module creates
- what breaks, hides, or becomes orphaned when parts of the module are removed or become unavailable

A module is not fully designed until both views are complete and consistent.

---

## 4. The Full Module Design Cycle

Every new module must pass through this exact cycle, in this order.

### Step 1 — Scope the module as a bounded product/domain surface

Define the module’s name, purpose, and business boundary.

Confirm:

- what belongs inside the module
- what does not belong inside the module
- what neighboring domains it touches
- what pre-existing locked domains it must not reopen

### Step 2 — Define Module Truth

Describe the module as a system of owned objects, owned states, owned actions, and owned business rules.

Confirm:

- core entities/objects
- object relationships
- lifecycle states
- actions/transitions
- status vocabulary
- variants, categories, types, or families
- role-specific workflows if they are intrinsic to the module

### Step 3 — Define the CP grant surface

Before tenant configuration is discussed, define what CP would grant for this module.

Confirm:

- whether the module itself is CP-gated or baseline
- whether the module has sub-capabilities, families, categories, or feature flags
- whether CP grants only the module boundary or also grants internal catalog items
- what is product-owned and never CP-configurable

### Step 4 — Define Module Settings

Describe what tenant admins can configure once the module is available to the tenant.

Confirm:

- tenant-editable structure
- required vs optional decisions
- default generation behavior
- review/acknowledgement behavior
- what saves at section level vs artifact level
- what is management-only vs setup-blocking

### Step 5 — Pass the Permission & Policy Management lens

Describe how the module becomes a policy target.

Confirm:

- whole-module permissions
- sub-surface permissions
- action permissions
- target scopes
- grouping behavior
- whether field/item-level special cases exist
- whether hidden, excluded, inactive, archived, or orphaned targets remain policy-visible for remediation

### Step 6 — Pass the Workspace Experience lens

Describe how the module manifests in runtime experience.

Confirm:

- navigation entry presence/absence
- cards, menus, buttons, views, and tasks
- role- or responsibility-specific work surfaces
- how hidden/excluded/not-in-use states affect runtime experience
- what the default runtime experience is before tenant customization

### Step 7 — Pass the Communications lens

Describe what communication moments the module introduces.

Confirm:

- business events that matter enough to communicate
- candidate recipients
- whether templates are needed
- whether rules are tenant-configurable or product-defined
- what belongs to Communications and what does not

### Step 8 — Pass the Fail-Closed / Removal / Orphan lens

Describe how the module behaves when granted surfaces shrink, dependencies disappear, targets are removed, or the module becomes partially invalid.

Confirm:

- what fails closed immediately
- what disappears from UI immediately
- what becomes orphaned and retained for remediation
- what triggers Needs Review
- what quietly decays because it was optional
- what runtime behavior must stop rather than guess

### Step 9 — Produce the standard module design artifact

The artifact must use the standard output shape defined later in this framework.

### Step 10 — Run the completion check

The module may be called fully designed only if every required question is answered, every lens is covered, boundaries are explicit, and no major ownership ambiguity remains.

---

## 5. Module Truth

Module Truth is the base layer. It is the part of the module that remains true even before settings, permissions, workspace UX, or communications are added.

Every module truth definition must answer all of the following.

### 5.1 Module identity

- What is this module?
- Why does it exist in Hubins?
- What business problem does it solve?
- What is its durable product meaning?

### 5.2 Ownership boundary

- What does this module own directly?
- What does it not own?
- What neighboring module owns adjacent concerns?
- What must never be pulled into this module just because it is related?

### 5.3 Core objects

- What are the primary objects/records/artifacts in this module?
- What supporting objects exist?
- What relationships exist between those objects?
- Which objects are first-class and which are derived or supporting?

### 5.4 Categories and internal structure

- Does the module contain families, types, categories, templates, definitions, instances, runs, or versions?
- Are there parent/child relationships?
- Are there blueprint-vs-instance distinctions?

### 5.5 Actions

- What actions can happen inside the module?
- Which actions are human-triggered?
- Which actions are system-triggered?
- Which actions create downstream effects in other domains?

### 5.6 Lifecycle and statuses

- What statuses exist?
- What does each status mean?
- What transitions are valid?
- What transitions are forbidden?
- Are there review, publish, archive, suspend, revoke, complete, cancel, or expired states?

### 5.7 Runtime truths

- What makes an object usable vs unusable?
- What makes an object active vs inactive?
- What runtime checks must happen before module actions are allowed?

### 5.8 Module Truth output rule

If the module truth section does not let a reader explain the module’s objects, state model, and business boundary in plain language, the module is not ready to move forward.

---

## 6. Module Settings

Module Settings defines how the tenant shapes the module after CP has defined the allowed universe.

This section must never blur product-owned truth, CP-owned truth, and tenant-owned configuration.

### 6.1 Ownership split

For every configurable part of the module, classify ownership explicitly:

- CP-owned
- tenant-owned
- product-owned
- policy-owned
- runtime/platform-owned

### 6.2 Tenant configuration surface

Answer:

- What can tenant admins configure?
- What are they reviewing vs actively editing?
- What is read-only in the first release?
- What is hidden when not allowed?
- What can be excluded even if allowed?

### 6.3 Required vs optional

Answer:

- What is required for setup completion?
- What is optional and non-blocking?
- What is management-only and should not block completion?
- What must be explicitly acknowledged rather than fully configured?

### 6.4 Defaults and generation

Answer:

- What defaults appear automatically when the module is first enabled?
- What sections/cards/views are generated by product defaults?
- What does the tenant refine versus invent from scratch?

### 6.5 Save model

Answer:

- What saves at section level?
- What saves at artifact level?
- Is there a review/acknowledge action?
- What changes only take effect after explicit save?

### 6.6 Setup-state relationship

Answer:

- Does this module block setup completion?
- Does only part of it block setup completion?
- Does it only affect management mode?
- What exactly changes the module to Not Started / In Progress / Complete / Needs Review?

### 6.7 Hidden vs excluded vs deferred

These terms must stay distinct:

- Hidden = not allowed, not shown
- Excluded = allowed but intentionally not in use
- Deferred = product-known but intentionally not buildable/configurable yet

### 6.8 Module Settings output rule

If the tenant surface still feels like “we will decide later how the tenant uses this,” then module settings thinking is not complete.

---

## 7. Permission & Policy Management Lens

Every new module must be evaluated as a future policy surface, even if policy UI for that module ships later.

### 7.1 Whole-module permissions

Answer:

- Does the module support module-level access grants?
- Is there a difference between view, use, manage, configure, approve, publish, or administer?

### 7.2 Middle-layer targets

Answer:

- Are there module sub-surfaces that deserve their own policy targets?
- Examples: definitions, instances, tasks, templates, categories, sections, queues, calendars, libraries, workflows

### 7.3 Action model

Answer:

- Which actions are sensitive enough to deserve explicit permission targets?
- Are there destructive actions?
- Are there approval actions?
- Are there state-transition actions?

### 7.4 Special-case targets

Answer:

- Do field-level, item-level, or subtype-level targets matter?
- If yes, are they first-class policy targets or exceptions only?
- If not, explicitly say they are not part of v1 policy design for this module.

### 7.5 Scope model

Answer:

- What scopes matter: tenant-wide, workspace-specific, object-specific, role-specific, responsibility-specific?
- Does the module produce targets that can be grouped meaningfully?

### 7.6 Assignment model

Answer:

- How would group/policy/assignment logic apply to this module?
- What types of groups would realistically need access?
- What does deny/absence of grant mean for the module?

### 7.7 Policy failure behavior

Answer:

- If a policy target disappears, what happens immediately?
- Does access fail closed?
- Does the target disappear from normal UI?
- Is the orphan retained for remediation?

### 7.8 Permission lens output rule

If the team cannot explain what a future policy would point at inside this module, then permission thinking is incomplete.

---

## 8. Workspace Experience Lens

Every module must be evaluated for what runtime experience it creates.

### 8.1 Navigation presence

Answer:

- Does the module appear in navigation?
- When does it appear?
- When is it hidden?
- Is it baseline or only visible when configured/in use?

### 8.2 Runtime surfaces

Answer:

- What pages, cards, menus, buttons, tables, detail views, dashboards, or panels does this module create?
- Which are admin-facing?
- Which are member-facing?
- Which are operator/reviewer/manager-facing?

### 8.3 Responsibility-specific experience

Answer:

- Does the module create distinct work surfaces for distinct responsibilities?
- Are those differences real product needs or just permission differences?

### 8.4 Default runtime organization

Answer:

- What is shown by default before tenant customization?
- What does Hubins pre-organize automatically?
- What can the tenant later rearrange through Workspace Experience rather than module-local settings?

### 8.5 Hidden / excluded / unavailable behavior

Answer:

- If a capability is not allowed, what disappears?
- If a capability is allowed but excluded, what disappears?
- If a capability exists but is operationally blocked, what runtime messaging appears?

### 8.6 Workspace Experience output rule

If the module has domain logic but no clearly described runtime surfaces, the design is incomplete.

---

## 9. Communications Lens

Every module must be evaluated for communication moments, but communication logic must remain separated from module truth.

### 9.1 Event inventory

Answer:

- What meaningful events happen in this module?
- Which events deserve notification consideration?
- Which events are merely internal and should not communicate?

### 9.2 Recipients

Answer:

- Who may need to know?
- Actor
- subject person
- reviewer
- manager
- admin
- external contact
- support or platform role

### 9.3 Communication type

Answer:

- Is the communication email-like content, an in-product alert, or future multi-channel?
- Does the module only produce communication moments, while Communications owns the sending configuration?

### 9.4 Product-owned vs tenant-configurable

Answer:

- Which module events are product-defined and always exist?
- Which can later be tenant-configurable through Notification Rules?
- Which templates, if any, would belong in Communications > Email Templates rather than inside the module?

### 9.5 Boundary discipline

The module must not absorb:

- SMTP/provider configuration
- generic notification routing logic
- template library ownership
- communications UI that belongs to the Communications domain

### 9.6 Communications output rule

If the module creates important business moments but the design has no communication inventory, the design is incomplete.

---

## 10. Fail-Closed / Removal / Orphan Lens

This lens is mandatory. It prevents optimistic designs that work only while everything exists.

### 10.1 Dependency failure

Answer:

- What happens if a required dependency is removed or becomes invalid?
- What stops immediately?
- What must fail closed rather than partially continue?

### 10.2 CP allowance shrinkage

Answer:

- What happens if CP removes a required module boundary, capability, family, field, or integration dependency?
- What becomes Needs Review?
- What simply disappears because it was optional?

### 10.3 Tenant removal or exclusion

Answer:

- What happens if a tenant later excludes something that had been in use?
- What happens to runtime surfaces?
- What happens to stored configuration or policy references?

### 10.4 Orphan retention

Answer:

- What becomes orphaned but retained for remediation or audit?
- What is retained only as system history?
- What is safe to hard-remove immediately?

### 10.5 UI disappearance rules

Answer:

- What should vanish from normal UI immediately?
- What should remain visible only as a warning or remediation object?
- What should show Blocked vs Hidden vs Needs Review?

### 10.6 Runtime enforcement rule

When the system is uncertain because a required dependency or target disappeared, the default must be fail closed, not guess-and-continue.

### 10.7 Removal lens output rule

If the module design only describes success paths and not removal paths, it is not complete.

---

## 11. Required Questions Every New Module Must Answer

A module is not allowed to pass design review unless all of the following questions have explicit answers.

### 11.1 Core module truth

- What is the module?
- Why does Hubins need it?
- What does it own?
- What does it explicitly not own?
- What are its first-class objects?
- What categories/types/families exist?
- What actions exist?
- What state model exists?
- What makes something usable, blocked, expired, suspended, active, archived, or complete?

### 11.2 Module settings

- Is the module baseline or CP-gated?
- What exactly does CP grant for this module?
- What exactly can tenant admins configure later?
- What is product-owned and not tenant-configurable?
- What is required for module completion?
- What is optional?
- What is default-generated?
- What is hidden, excluded, or deferred?
- What is setup-blocking vs management-only?

### 11.3 Permission & policy

- What module-level permissions exist?
- What sub-targets exist?
- What action permissions exist?
- What scopes matter?
- What future group/policy assignments would point at?
- Are there special item/field-level cases?
- How do removed targets affect policy behavior?

### 11.4 Workspace experience

- Where does the module appear in runtime UX?
- What navigation entries appear?
- What cards, pages, buttons, and task surfaces appear?
- What role-specific experience differences are real?
- What is the default product-organized runtime experience?
- What disappears when the module or a sub-capability is unavailable?

### 11.5 Communications

- What module events matter enough to communicate?
- Who are the candidate recipients?
- What should be product-defined?
- What may later become tenant-configurable through Communications?
- What absolutely does not belong inside the module because it belongs to Communications?

### 11.6 Fail-closed / orphan behavior

- What happens when required targets disappear?
- What becomes orphaned?
- What fails closed immediately?
- What triggers Needs Review?
- What disappears quietly because it was optional?
- What remains only for remediation/audit?

### 11.7 Design completeness

- What parts of the module are intentionally out of scope for the first release?
- What anti-drift boundaries are permanent?
- What unresolved questions still block calling the module fully designed?
- What proof would later be required before the module is called implemented and ready?

---

## 12. Required Output Shape for Every Future Module Design Artifact

Every future module design artifact must use this output shape.

### 12.1 Required sections in every module design artifact

1. Module Purpose
2. Ownership Boundary
3. Core Objects
4. Categories / Types / Families
5. Actions and State Model
6. CP Grant Surface
7. Tenant Module Settings Surface
8. Setup / Completion Rules
9. Permission & Policy Targets
10. Workspace Experience Impact
11. Communications Impact
12. Fail-Closed / Removal / Orphan Rules
13. Explicit Exclusions
14. Anti-Drift Rules
15. Open Questions / Final Closure Verdict

### 12.2 Standard writing rule

Each section must answer durable questions, not provide vague prose.

### 12.3 Standard exclusion rule

Every module artifact must contain an explicit exclusions section so future readers know what was intentionally left out rather than forgotten.

### 12.4 Standard closure rule

Every module artifact must end with a verdict in one of these forms:

- Fully designed
- Partially designed — blocked by named unresolved items
- Not ready for module closure

“Looks good” is not an allowed closure verdict.

---

## 13. How To Know Module Thinking Is Complete

Module thinking is complete only when all of the following are true.

### 13.1 All six lenses are covered

The artifact covers:

- Module Truth
- Module Settings
- Permission & Policy Management
- Workspace Experience
- Communications
- Fail-Closed / Removal / Orphan Behavior

### 13.2 Ownership is explicit

There is no unresolved confusion between:

- CP-owned
- tenant-owned
- product-owned
- policy-owned
- runtime/platform-owned

### 13.3 Boundaries are explicit

The artifact states what belongs in the module and what must stay outside it.

### 13.4 Removal behavior is explicit

The artifact explains what happens when required pieces disappear, not only when everything is healthy.

### 13.5 Runtime surfaces are explicit

The artifact describes what real users will see and do, not only backend/domain structure.

### 13.6 Policy targets are explicit

The artifact explains what future policies would point at inside the module.

### 13.7 Communications moments are explicit

The artifact explains which events matter and which do not.

### 13.8 Release boundaries are explicit

The artifact clearly distinguishes:

- first-release truth
- later-release placeholders
- permanent exclusions

### 13.9 No hidden assumptions remain

A new reader should not need prior chat history to understand what the module is, how it fits Hubins, and what remains open.

### 13.10 Strict closure test

A module cannot be called fully designed if any one of these remains true:

- major ownership ambiguity remains
- one of the six lenses is missing
- removal/orphan behavior is not described
- runtime surfaces are undefined
- policy targets are undefined
- communications impact is undefined
- completion criteria are hand-wavy
- exclusions are missing

---

## 14. LLM Readability / Documentation Rules

This framework is meant to be used directly in future LLM chats, so readability rules are mandatory.

### 14.1 Stable headings

Use stable headings and stable section names. Do not rename major sections casually.

### 14.2 Stable terminology

Use one term consistently for one concept.

Do not rotate between synonyms when the concept is the same.

Examples:

- use “module settings,” not alternate between settings/config/setup profile/editor surface
- use “hidden” only for not allowed and not shown
- use “excluded” only for allowed but intentionally not in use
- use “deferred” only for product-known but intentionally not shipped/configurable yet

### 14.3 No buried law

If a rule is important, state it directly. Do not hide it in narrative paragraphs.

### 14.4 Checklist-friendly writing

Prefer question lists, bullet lists, and explicit decision statements over long wandering prose.

### 14.5 Boundary-friendly writing

Every section should make ownership and boundaries obvious.

### 14.6 No accidental implementation drift

Do not turn design artifacts into code specs, endpoint catalogs, or implementation plans unless that is the explicit next phase.

### 14.7 No duplicate truth

Do not restate stable global law in multiple places unless a short reminder is necessary.

Reference durable law instead of cloning it.

### 14.8 Make omission obvious

If something is intentionally not covered, say so explicitly.

### 14.9 LLM input discipline

When this framework is attached in future module-design chats, it should be paired with the current master source-of-truth document for the target domain. Older conflicting notes must not override the latest locked master truth.

---

## 15. Boundary / Anti-Drift Rules

1. Do not design a module only as backend/domain logic. It must also pass the settings-adapter lenses.
2. Do not let Communications logic get absorbed into the module just because the module emits events.
3. Do not let Workspace Experience logic get absorbed into the module just because the module appears in runtime UI.
4. Do not treat policy as a late afterthought. Every module must be evaluated as a future policy surface.
5. Do not treat fail-closed behavior as an implementation detail. It is part of design truth.
6. Do not reopen locked CP / tenant / policy ownership rules.
7. Do not invent CP ownership over domains already locked as tenant-baseline domains.
8. Do not call a module “done” because its core objects were described while settings, policy, workspace, communications, or removal thinking is still missing.
9. Do not create a module artifact that lacks explicit exclusions and anti-drift rules.
10. Do not create ad hoc module design formats. Use the required output shape.
11. Do not write module artifacts that assume prior chat memory. The artifact must stand on its own.
12. Do not confuse hidden, excluded, blocked, deferred, orphaned, and removed. These are different states and must stay different.
13. Do not let optional removal behave like required removal. Required changes may trigger Needs Review; optional changes should not force fake review cycles.
14. Do not let uncertain runtime states guess. Required dependency uncertainty must fail closed.
15. Do not let future module work contradict the current highest-priority master truth.

---

## 16. Final Reusable Framework Document

# Hubins — Standard Framework for Introducing a New Module

## Purpose

Use this framework every time Hubins introduces a new module.

A new module is never only a domain module. It must also be designed as a settings adapter.

The module is not fully designed until all six lenses below are complete.

## Locked Hubins Model This Framework Assumes

- CP grants the allowed universe.
- Tenant admins configure within that universe.
- Policies later control access.
- Workspace Experience is a first-class tenant domain.
- Communications is a first-class tenant domain.
- Policy is not CP-owned.
- Required-removal changes may trigger Needs Review.
- Optional removals orphan quietly and fail closed where needed.

## The Six Mandatory Lenses

### 1. Module Truth

Answer:

- what the module is
- what it owns
- what it does not own
- what objects it manages
- what categories/types/families it contains
- what actions exist
- what lifecycle/states exist

### 2. Module Settings

Answer:

- what CP grants for this module
- what tenant admins can configure later
- what is required vs optional
- what defaults are product-generated
- what is hidden vs excluded vs deferred
- what is setup-blocking vs management-only

### 3. Permission & Policy Management

Answer:

- what whole-module permissions exist
- what middle-layer targets exist
- what action permissions exist
- what scopes matter
- whether field/item-level exceptions matter
- how future group/policy assignment would point at this module

### 4. Workspace Experience

Answer:

- whether the module appears in navigation
- what pages/cards/buttons/work queues it creates
- what responsibility-specific work surfaces exist
- what default runtime experience appears before customization
- what disappears when the module or a capability is unavailable

### 5. Communications

Answer:

- what business events matter enough to communicate
- who the relevant recipients are
- what is product-defined vs tenant-configurable later
- what belongs to Communications rather than inside the module

### 6. Fail-Closed / Removal / Orphan Behavior

Answer:

- what fails closed immediately
- what becomes orphaned
- what disappears from UI
- what triggers Needs Review
- what optional removals leave alone
- what must be retained for remediation or audit

## Required Questions Before a Module Can Be Called Fully Designed

- What is the module’s durable product meaning?
- What does it own and not own?
- What are its first-class objects and statuses?
- What exactly does CP grant for it?
- What exactly can tenant admins configure?
- What is product-owned, policy-owned, and runtime-owned?
- What permissions and policy targets does it create?
- What runtime work surfaces does it create?
- What communication moments does it create?
- What happens when required targets or dependencies disappear?
- What happens when optional targets are removed?
- What is first-release scope vs later-release scope?
- What is explicitly excluded?

## Required Output Shape for Future Module Design Artifacts

Every future module design artifact must contain:

1. Module Purpose
2. Ownership Boundary
3. Core Objects
4. Categories / Types / Families
5. Actions and State Model
6. CP Grant Surface
7. Tenant Module Settings Surface
8. Setup / Completion Rules
9. Permission & Policy Targets
10. Workspace Experience Impact
11. Communications Impact
12. Fail-Closed / Removal / Orphan Rules
13. Explicit Exclusions
14. Anti-Drift Rules
15. Final Closure Verdict

## Completion Rule

A module is not fully designed unless:

- all six lenses are covered
- ownership is explicit
- boundaries are explicit
- runtime surfaces are explicit
- policy targets are explicit
- communications moments are explicit
- removal/orphan behavior is explicit
- exclusions are explicit
- no major ambiguity remains

## LLM Readability Rules

- Use stable headings.
- Use stable terminology.
- Keep hidden / excluded / deferred / blocked / orphaned distinct.
- Use direct rules, not buried narrative.
- Make omissions explicit.
- Do not assume prior chat memory.
- Do not duplicate other source-of-truth documents unnecessarily.

## Anti-Drift Rules

- Do not design only the business layer.
- Do not skip the settings-adapter lenses.
- Do not absorb Communications into the module.
- Do not absorb Workspace Experience into the module.
- Do not delay policy thinking until later.
- Do not skip fail-closed behavior.
- Do not call a module “done” while major questions remain open.

## Final Standard

Hubins may say a new module is fully designed only when the module has been described as:

- a domain module
- a settings adapter
- a future policy surface
- a runtime experience surface
- a communications event source
- a fail-closed system

If any one of those views is missing, the module is not done.
