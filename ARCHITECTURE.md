# INSYNCTIVE

## Target System Architecture

\_Final Plan · Principal Architect Review

## 1. Executive Recommendation

> **Build Insynctive as a disciplined modular monolith today. Extract selectively and deliberately when specific modules have proven, measurable extraction triggers — not before.**
>
> This is not a conservative hedge. It is the correct engineering decision for the current team, scale, and domain maturity. Premature distribution is the single most destructive architectural mistake a small-to-medium SaaS team can make.

| Decision                   | Recommendation                                                                  |
| -------------------------- | ------------------------------------------------------------------------------- |
| Architecture               | Disciplined modular monolith with intentional, explicit async boundaries        |
| Primary stack              | Node.js + TypeScript + PostgreSQL + Redis + S3 — no changes warranted           |
| Async foundation           | DB outbox pattern for all side-effecting operations                             |
| Multi-tenancy              | Shared schema, row-level isolation — tenant_id enforced at typed DAL layer      |
| Business core              | Workflow Runtime Engine — process/checklist execution is the center of gravity  |
| Microservices now?         | No — team and operational maturity do not justify the complexity tax            |
| First extraction candidate | Document Processing pipeline — when signing/generation volume demands isolation |

---

## 2. What Kind of System Insynctive Really Is

Insynctive is a structured process execution platform for multi-tenant organizations. Every other capability — authentication, documents, communications, benefits, imports — is a support system for that core. This reading must be internalized before any module design decision is made.

| Tier               | Contains                                                      | Role                                                                  |
| ------------------ | ------------------------------------------------------------- | --------------------------------------------------------------------- |
| Core Domain        | Workflow templates, process execution, tasks, checklists      | The reason the platform exists. Maximum investment here.              |
| Supporting Domains | Documents, communications, benefits, rates, audit, reports    | Enable and record core domain activity. Important but derivative.     |
| Generic Subdomains | Auth, identity, provisioning, tenant management, integrations | Must work correctly but are not differentiating. Use proven patterns. |

### 2.1 Canonical Domain Vocabulary

> **These definitions are binding. Every engineer, PM, and document must use these terms consistently. Casual mixing of "task completed," "step completed," "checklist done," and "process finished" will rot the design even if the module split is correct.**

| Term                | Canonical meaning                                                                                                                                                                                                  | What it is NOT                                                                                                                            |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Workflow Template   | The design-time blueprint that defines a process structure. Contains step definitions, branching rules, required documents, task templates, and triggers. Authored by admins. Versioned. Rarely changed.           | Not a running object. It has no state. It describes possible behavior.                                                                    |
| Process Instance    | A single live execution of a Workflow Template for a specific Participant, initiated at a point in time. Has its own lifecycle state machine (CREATED → IN_PROGRESS → COMPLETED / CANCELLED / ARCHIVED).           | Not the template. Two process instances of the same template are entirely independent runtime objects.                                    |
| Step                | A runtime stage in a Process Instance — a child entity of the instance with its own state (PENDING → ACTIVE → COMPLETED / SKIPPED / BLOCKED). A step may produce Tasks, Document Requests, or downstream triggers. | Not a Task. A step is the runtime point of orchestration. Tasks are the actionable work that steps produce.                               |
| Task                | A discrete unit of actionable work assigned to a Person, Role, or System. Owned by Task Management. Has assignee, due date, completion state, comments. Created when a Step activates.                             | Not a Step. A Task is the human-facing work item. The Step is the orchestration checkpoint.                                               |
| Checklist           | A user-facing view of a Process Instance — a flat or grouped presentation of Steps and their associated Tasks for a given Participant. The Checklist is a UI/UX concept backed by a Process Instance.              | Not a separate data entity. A Checklist IS a Process Instance rendered in checklist form.                                                 |
| Document Request    | A directive produced by a Step requiring a specific document to be uploaded, generated, or signed. Owned by Document Management. Has its own lifecycle (REQUESTED → FULFILLED / REJECTED).                         | Not a document. A Document Request is the requirement. A Document is the artifact that fulfills it.                                       |
| Participant         | A business actor in a Process Instance — may be an employee, external user, customer, or dependent. Holds a role within the process (e.g., primary subject, reviewer, approver).                                   | Not a User. A Participant is a business role in a workflow context. One User may be Participant in many Process Instances simultaneously. |
| Enrollment          | A Participant's association with a Benefits plan as a result of a process outcome. Owned by Benefits & Rates. Created by process events, not by direct user action.                                                | Not a Membership. Membership is access to a Tenant. Enrollment is participation in a Benefits plan.                                       |
| Member / Membership | The access record connecting a User identity to a Tenant. Holds role (ADMIN/MEMBER) and access status (INVITED/ACTIVE/SUSPENDED).                                                                                  | Not a Participant or an Enrollment. Membership is about platform access, not business workflow roles.                                     |

### 2.2 Domain Entity Separation: Auth Principal vs Business Person

> **This is one of the highest-risk design gaps in multi-tenant SaaS platforms. If you allow "User" to mean both auth identity and business person model simultaneously, it becomes your God object within 12 months.**

Insynctive must maintain a hard architectural boundary between two distinct concepts that happen to share an email address:

| Concept                      | Owned by                   | What it contains                                                                                                                               | Key invariant                                                                                                |
| ---------------------------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Auth Principal               | Identity & Access          | Credentials (password hash, SSO identities), session records, MFA secrets, memberships, invite tokens, rate limit state.                       | One principal per email globally. Credentials are never exposed outside this context.                        |
| Person / Participant Profile | People / Directory context | Legal name, employment status, external identifiers (ADP ID, HR ID), business roles, contact details, language prefs, dependent relationships. | One profile per business actor. May exist without auth credentials (HRIS-imported person not yet onboarded). |

**Why this boundary is critical for Insynctive specifically:**

- HRIS import creates Person records without creating Auth Principals. An ADP-imported employee exists as a Person before they have ever logged in.
- A Dependent (family member in benefits) may be a Person in a process but will never have an Auth Principal.
- External participants (customers, counterparties) may have a limited Auth Principal but a rich Person profile for workflow purposes.
- Reporting and audit need Person identity (legal name, employee ID) — not auth identity (session ID, credential type).

**Implementation rule:** the People / Directory module holds business person records. The Identity & Access module holds credentials. They are linked by a nullable `user_id` foreign key on the person record — not by merging the two concepts into a single User table.

---

## 3. Proposed Bounded Contexts / Modules

Each bounded context is a module with its own folder, internal types, DAL, and defined public interface. No module imports another module's internal DAL. Cross-module communication uses defined service interfaces (synchronous) or the outbox (async). No module directly queries another module's tables — not even with a JOIN.

| Context             | Lives here                                                                                          | Role                                                                                                          | Priority  |
| ------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | --------- |
| Identity & Access   | auth, users, memberships, MFA, SSO, sessions, invites, provisioning                                 | Auth principal lifecycle. Generic subdomain — build correctly, do not over-invest.                            | Low       |
| People / Directory  | person profiles, employee records, HRIS IDs, dependents, contact details, external identifiers      | Business person model. Decoupled from credentials. Source of truth for who participates in workflows.         | Medium    |
| Tenant Management   | tenants, settings, feature flags, domain configuration, HRIS config, subscription state             | The organizational unit. Configuration here. Scopes all other contexts.                                       | Low       |
| Workflow Definition | process templates, step definitions, branching rules, trigger configs, template versions            | Schema of work. Authored by admins. Versioned, rarely changed. The knowledge of the business encoded as data. | Very High |
| Workflow Runtime    | process instances, step instances, lifecycle state machines, activation rules, orchestration events | THE business core. Maximum design investment. Owns all state transitions.                                     | Very High |
| Task Management     | tasks, assignments, due dates, delegation, completion, comments, reminders, escalation              | Human-facing work surface. Produces from step activations. May support standalone tasks.                      | High      |
| Document Management | document records, requests, versions, signing pipeline, acceptance state, storage refs              | Documents as business artifacts. S3 for blobs, Postgres for lifecycle state.                                  | High      |
| Communications      | email delivery, in-app notifications, SMS (future), templates, preferences, recipient routing       | Reacts to domain events only. Strictly async. Never called synchronously.                                     | Medium    |
| Benefits & Rates    | benefit plans, rate tables, enrollments, eligibility rules, enrollment events                       | Distinct sub-domain with its own calculation logic. Receives process outcomes.                                | Medium    |
| Reporting           | operational reports, dashboards, exports, materialized views, read models                           | Read-only over operational data. Never writes to core tables.                                                 | Low       |
| Integrations        | ADP sync, HRIS connectors, webhooks, OAuth credentials, anti-corruption layer                       | All async. External models translated here before touching domain.                                            | Medium    |
| Audit & Compliance  | audit events, append-only log, retention, compliance reports                                        | Append-only. Receives events from all contexts. Never modified.                                               | Low       |

**Non-negotiable boundary rules:**

- **Workflow Runtime MUST NOT import from Document Management or Communications. It emits domain events; those contexts react.**
- Identity & Access MUST NOT bleed role-checking logic into other modules. Each module enforces its own access policy.
- People / Directory and Identity & Access are linked by a nullable foreign key — they are NOT merged into a single entity.
- Benefits & Rates MUST NOT contain process execution logic. A benefit enrollment is a workflow task output.
- Reporting is read-only. Any module that writes to reporting tables has violated the boundary.
- Integrations is the anti-corruption layer. ADP's data model does not infect the core domain.

---

## 4. The Real Business Core

> **The Workflow Runtime Engine is the irreplaceable core. Not authentication. Not documents. Not communications. The thing that makes Insynctive irreplaceable to its customers is that it executes, tracks, and enforces structured processes across organizations.**
>
> In DDD terms, this is the core domain — where maximum design investment belongs. Bugs here are not technical debt. They are business failures.

### 4.1 Runtime Aggregate Boundaries

An aggregate boundary defines what is transactionally consistent, what is the root of identity, and what can only be changed through a single entry point. These boundaries determine locking strategy, query patterns, and event emission rules.

| Aggregate         | Root entity                             | Owns transactionally                                                                                                                                  | Does NOT own                                                                                                             |
| ----------------- | --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Process Instance  | ProcessInstance                         | Instance lifecycle state (CREATED/IN_PROGRESS/COMPLETED/CANCELLED/ARCHIVED), step activation order, branching decisions, template snapshot at launch. | Task content, document content, notification delivery. Creates these via domain events — does not own them.              |
| Step Instance     | StepInstance (child of ProcessInstance) | Step state (PENDING/ACTIVE/COMPLETED/SKIPPED/BLOCKED), step-level metadata, completion timestamp, completedBy actor.                                  | The tasks and document requests that a step produces. Those are emitted as events and owned by their respective modules. |
| Workflow Template | WorkflowTemplate                        | Template version, step definitions, branching rules, required document types, task templates, trigger configurations.                                 | Runtime state. Templates are immutable after being published. A new version creates a new template record.               |

**Aggregate design decision — ProcessInstance vs StepInstance:**

StepInstances are child entities of ProcessInstance in the same aggregate root for most cases. This simplifies transactional consistency: completing a step and activating the next step happen in one database transaction. The exception is high-throughput scenarios where many steps complete simultaneously — in that case StepInstance may be promoted to its own aggregate with optimistic locking.

### 4.2 Workflow Runtime Invariants

> **These invariants must ALWAYS hold. Any code path that violates them is a bug, not a feature. They must be encoded as policy functions and enforced before any state mutation.**

| Invariant                                                                        | Enforcement point                                                                                                 | Violation consequence                                                     |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Only Workflow Runtime can transition step state                                  | Policy enforced in runtime flow functions. No other module writes to `step_instances.status`.                     | Workflow state corruption. Audit trail gaps. Out-of-order completions.    |
| A BLOCKED step cannot produce active tasks                                       | Checked before task creation events are emitted. BLOCKED means prerequisite not met.                              | Tasks created for work that cannot be actioned yet, confusing users.      |
| A CANCELLED process cannot accept step completions                               | Validated at the start of every step-completion flow.                                                             | Ghost completions on dead processes. Audit confusion.                     |
| Completing a required step must attempt to activate downstream steps             | Transactional. Activation logic runs inside the same tx as step completion.                                       | Workflow stalls. Users waiting for next step that never appears.          |
| Duplicate process launch for same Participant+Template+Window must be idempotent | Idempotency key on (tenant_id, template_id, participant_id, idempotency_key). Returns existing instance if found. | Duplicate workflows. Double task assignment. Duplicate document requests. |
| Template rules are snapshotted at launch, not read live                          | Template data is copied into the process instance at creation.                                                    | A template edit mid-flight silently alters running processes.             |
| SKIPPED steps must have an explicit actor and reason                             | Skip action requires actor_id and skip_reason. Implicit skips are forbidden.                                      | Audit gap. No accountability for skipped required steps.                  |

### 4.3 Template Snapshot Strategy

When a Process Instance is created from a Workflow Template, a subset of the template's rules is snapshotted into the instance record. This is the single most important correctness decision in the Workflow Runtime design.

| Data                                              | Snapshotted?                 | Why                                                                                 |
| ------------------------------------------------- | ---------------------------- | ----------------------------------------------------------------------------------- |
| Step definitions (names, types, order, branching) | YES — always                 | A template edit must not alter in-flight processes.                                 |
| Required document types per step                  | YES — always                 | A document type added to a template mid-flight should not affect running instances. |
| Task templates (name, default assignee role)      | YES — always                 | Task creation uses snapshot, not live template.                                     |
| Branching / conditional rules                     | YES — always                 | Logic cannot change under a running process.                                        |
| Template version identifier                       | YES — always                 | Enables audit: "this instance ran template v3."                                     |
| Template display name and description             | Reference only (foreign key) | These are presentational and safe to update.                                        |
| Email templates / notification content            | Reference only (foreign key) | Notification content is resolved at send time by Communications context.            |

### 4.4 Task vs Workflow Boundary (Explicit)

This is one of the highest-probability sources of accidental cross-boundary coupling. The boundary must be explicit and documented.

| Concern                                         | Owned by Workflow Runtime                                                 | Owned by Task Management                                                                         |
| ----------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| When work becomes required                      | ✓ Step activation triggers task creation event                            | —                                                                                                |
| Task lifecycle (assignee, due date, delegation) | —                                                                         | ✓ Full ownership after creation event received                                                   |
| Step completion signaling                       | ✓ Task Management publishes "task completed" event → Runtime processes it | —                                                                                                |
| Overdue / reminder logic                        | —                                                                         | ✓ Task Management owns SLA, escalation, reminders                                                |
| Blocking a step on task completion              | ✓ Step stays ACTIVE until required tasks complete                         | —                                                                                                |
| Task reassignment / delegation                  | —                                                                         | ✓ Task Management handles. Does not require Runtime coordination unless step assignment changes. |
| Comments on task work                           | —                                                                         | ✓ Task Management only                                                                           |

**Explicit stance:** All tasks in Phase 1 are process-derived (created by Step activation). Standalone tasks are a Phase 2 decision. Making this decision explicit now prevents Task Management from growing a duplicate orchestration layer.

---

## 5. Recommended Runtime Architecture

The sync/async boundary is the most consequential architectural decision after the module split. Getting it wrong creates either a slow, brittle request path or an eventually-consistent nightmare where users cannot trust what they see.

### 5.1 Synchronous Operations

| Operation                         | Why synchronous                                                                                             |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Authentication & session creation | User is waiting. Must succeed or fail immediately.                                                          |
| All GET / read requests           | Reads are always synchronous. No eventual consistency for reads.                                            |
| Starting a process instance       | Create the instance record synchronously. Side effects (notifications, task creation) are async via outbox. |
| Completing a step                 | State transition is atomic and immediately visible. Downstream activations are async events.                |
| Invite acceptance                 | Token consumption and membership activation are atomic. Must be immediate.                                  |
| Document upload acknowledgment    | The upload confirmation is sync. Generation/signing pipeline is async.                                      |

### 5.2 Asynchronous Operations (Outbox-Mandatory)

| Operation                                   | Pattern                                                                        |
| ------------------------------------------- | ------------------------------------------------------------------------------ |
| Email delivery                              | DB outbox → email worker → provider. Never SMTP in a request handler.          |
| In-app notifications                        | DB outbox → notification worker → notification_feed table.                     |
| Task creation from step activation          | Outbox event from Runtime → Task Management worker creates task records.       |
| Document generation (PDF)                   | Job queue with status polling. May take 2–10s.                                 |
| Document signing pipeline                   | External provider callback (webhook). Async receiver → outbox → runtime event. |
| Bulk workflow start / bulk send             | bulk_jobs table + dedicated worker. Progress tracked in DB.                    |
| ADP / HRIS sync                             | Scheduled worker. Idempotent re-runs. Never in request path.                   |
| Downstream workflow triggers                | Step completion → outbox → runtime worker evaluates next step activations.     |
| Audit event writes (failure path)           | Must survive transaction rollback. Written outside tx.                         |
| Report materialization / read model refresh | Scheduled refresh worker. Never in request path.                               |

### 5.3 The Outbox Is the Async Foundation

> **Use the DB outbox pattern as the universal foundation for all async side effects. Do not introduce a message broker until the outbox is demonstrably insufficient. That threshold is much higher than most teams think.**

Every async operation: the producing flow inserts an outbox row inside its DB transaction. A background worker polls, claims with a lease, processes, marks done. Crash recovery via lease expiry. Dead-letter after N retries.

### 5.4 When to Introduce a Real Message Broker

Justified only when ALL three are simultaneously true: (1) outbox worker throughput is measurably saturated, (2) multiple independent services need to consume the same event stream, (3) the ops team can reliably run a broker. Insynctive does not yet meet these criteria.

### 5.5 Consistency, Concurrency & Idempotency Model

> **Insynctive is a retry-heavy, async, bulk, integration-heavy system. Every mutating operation must have an explicit answer to: what happens when this runs twice?**

**Locking strategy:**

| Operation                                       | Strategy                                                                           | Reasoning                                                                    |
| ----------------------------------------------- | ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Step state transition                           | Optimistic locking (version column on step_instances)                              | High contention only in bulk scenarios. Optimistic is sufficient with retry. |
| Process instance lifecycle (cancel/complete)    | Pessimistic lock (SELECT FOR UPDATE on process_instances)                          | Preventing double-cancel or double-complete warrants a short lock.           |
| Outbox claim                                    | UPDATE ... WHERE claimed_at IS NULL RETURNING — atomic claim without explicit lock | Standard claim-lease pattern. No lock held during send.                      |
| Token consumption (invite, reset, verification) | UPDATE ... WHERE used_at IS NULL RETURNING — atomic one-time use                   | Prevents replay attacks at the DB level.                                     |
| Bulk job claim                                  | UPDATE ... WHERE status = QUEUED RETURNING + worker_id stamp                       | Prevents two workers processing same bulk job.                               |

**Idempotency requirements — every one of these must be idempotent:**

| Operation                   | Idempotency key                                                                | Behavior on duplicate                                                            |
| --------------------------- | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| Start process instance      | (tenant_id, template_id, participant_id, client_idempotency_key)               | Return existing instance. Do not create duplicate.                               |
| Accept invite               | invite.token_hash consumed atomically — one-time use enforced by DB constraint | Second call returns 409 ALREADY_ACCEPTED.                                        |
| External webhook processing | (provider, event_id) stored in webhook_events table                            | Second delivery: detect duplicate, skip processing, return 200.                  |
| Bulk item execution         | bulk_job_items.idempotency_key per item                                        | Item already PROCESSED: skip. Do not re-execute.                                 |
| Document signing callback   | (provider, envelope_id, event_type) unique constraint                          | Duplicate callback: idempotent update of signing state.                          |
| HRIS import record          | (tenant_id, hris_id, sync_run_id) on person records                            | Upsert: update if exists, create if not. Same sync run never creates duplicates. |
| Outbox delivery             | (outbox_id, attempt_number) checked before send                                | Provider-level deduplication via message ID header.                              |

**At-least-once delivery and correctness:**

All outbox workers operate with at-least-once delivery semantics. Correctness is preserved through: (1) idempotency keys on every downstream operation, (2) status checks before acting ("is this step already COMPLETED?"), and (3) version/timestamp guards on state transitions.

### 5.6 Observability & Operability Standards

> **Observability is not a post-launch concern. It is a design constraint. Every async flow, every worker, every outbox message must carry the identifiers needed to trace it end-to-end.**

**Required correlation identifiers — on every log line, metric, and trace:**

| Identifier           | When present                                   | Why                                                              |
| -------------------- | ---------------------------------------------- | ---------------------------------------------------------------- |
| request_id           | All HTTP requests                              | End-to-end trace from browser to DB.                             |
| tenant_id            | All authenticated operations + all worker jobs | Critical for isolating tenant-specific failures.                 |
| process_instance_id  | All operations touching a process              | Full workflow trace across runtime, tasks, documents.            |
| job_id / bulk_job_id | All worker operations                          | Link worker log lines to the admin job that triggered them.      |
| outbox_id            | Outbox worker processing                       | Correlate delivery attempt logs to the originating domain event. |
| module               | All log lines                                  | Immediately identify which bounded context emitted the log.      |

**Key operational metrics (per module or worker):**

| Metric                             | Owner                 | Alert threshold                              |
| ---------------------------------- | --------------------- | -------------------------------------------- |
| outbox_queue_depth                 | Outbox worker         | > 500 rows unclaimed for > 5 min → PagerDuty |
| outbox_retry_rate                  | Outbox worker         | > 5% retry rate sustained for > 10 min       |
| worker_dead_letter_count           | All workers           | Any dead letter → immediate alert            |
| bulk_job_duration_p95              | Bulk worker           | > 10 min for standard bulk → alert           |
| document_generation_latency_p95    | Doc generation worker | > 30s → alert                                |
| notification_delivery_failure_rate | Notification worker   | > 1% in 15 min window                        |
| hris_sync_last_success_at          | HRIS sync worker      | Not run in expected window → alert           |
| step_completion_p99_latency        | Workflow Runtime      | > 500ms sustained → investigate              |

**Logging levels:** INFO for normal operation events. WARN for recoverable errors and retries. ERROR for failed operations requiring operator attention. FATAL for system-level failures. Audit-relevant events are NEVER logged — they are written to the `audit_events` table only. PII (email, name) is excluded from all log lines; use entity IDs only.

---

## 6. Recommended Data & Storage Architecture

### 6.1 PostgreSQL — Operational Core

| Table group       | Key tables                                                                               |
| ----------------- | ---------------------------------------------------------------------------------------- |
| Identity & People | users, people, memberships, auth_identities, invites, password_reset_tokens, mfa_secrets |
| Tenant            | tenants, tenant_settings, tenant_features                                                |
| Workflow          | workflow_templates, template_steps, process_instances, step_instances, process_snapshots |
| Task              | tasks, task_assignments, task_comments, task_attachments, task_escalations               |
| Document          | documents, document_requests, document_versions, signing_requests, signing_events        |
| Communications    | outbox, notification_feed, email_templates, notification_preferences                     |
| Benefits          | benefit_plans, rate_tables, enrollments, enrollment_events                               |
| Integration       | integration_credentials, sync_runs, sync_errors, import_jobs, inbound_webhooks           |
| Operations        | bulk_jobs, bulk_job_items, scheduled_jobs, system_scheduled_jobs                         |
| Audit             | audit_events (append-only, partitioned by month)                                         |

**Index requirements (non-negotiable at this scale):**

- Every foreign key gets an index. At millions of rows, unindexed FKs cause JOIN scans.
- Composite index (tenant_id, created_at) on all tenant-scoped paginated tables.
- Partial indexes on status columns: `WHERE status = 'PENDING'`, `WHERE status = 'ACTIVE'`.
- `audit_events`: partition by created_at month via `pg_partman` from day one. Do not wait.
- `process_instances`: index on (tenant_id, template_id, status) for admin dashboard queries.

### 6.2 Document Lifecycle Model

> **Documents in Insynctive are business artifacts, not files. They have legal meaning, compliance requirements, and formal lifecycle states. Model them as first-class domain entities, not as storage metadata.**

| State             | Meaning                                                                 | Who can transition                        | Next valid states                |
| ----------------- | ----------------------------------------------------------------------- | ----------------------------------------- | -------------------------------- |
| REQUESTED         | A Step has indicated this document is required. No artifact yet exists. | Workflow Runtime (via domain event)       | GENERATED, UPLOADED, CANCELLED   |
| GENERATED         | System has auto-generated the document (PDF merge, template fill).      | Document generation worker                | UPLOADED, UNDER_REVIEW           |
| UPLOADED          | A Participant has uploaded the document artifact.                       | Participant (via API)                     | UNDER_REVIEW, ACCEPTED, REJECTED |
| UNDER_REVIEW      | Document is awaiting reviewer decision.                                 | Reviewer actor (Admin or designated role) | ACCEPTED, REJECTED               |
| ACCEPTED          | Document has been formally accepted by the designated reviewer.         | Reviewer                                  | SIGNATURE_PENDING, ARCHIVED      |
| REJECTED          | Document was rejected. Participant may need to re-upload.               | Reviewer                                  | REQUESTED (restart cycle)        |
| SIGNATURE_PENDING | Document has been sent to signing provider (DocuSign/HelloSign).        | Document signing worker                   | SIGNED, SIGNATURE_VOIDED         |
| SIGNED            | All required signatories have signed.                                   | Signing provider webhook                  | ARCHIVED                         |
| ARCHIVED          | Document is retained but no longer active. Immutable.                   | System (scheduled archival) or Admin      | Terminal state                   |

**Versioning:** document versions are immutable. Each upload creates a new version record. The current accepted version is a pointer. Prior versions are retained for audit. Deletion of a version is not permitted — only archival.

**Ownership:** a document is always attached to a Process Instance (via a `document_request` record). A document that exists without a process context must be explicitly modeled as a tenant-owned direct upload — this is a Phase 2 feature decision, not an assumed default.

### 6.3 Redis — Focused Responsibilities

| Redis job                                 | Key pattern                                | TTL                  |
| ----------------------------------------- | ------------------------------------------ | -------------------- |
| Server-side sessions                      | `session:{sessionId}`                      | 24h sliding          |
| Rate limit counters                       | `rl:{endpoint}:{key}`                      | Window duration      |
| Idempotency keys                          | `idem:{clientKey}`                         | 24h                  |
| Distributed locks (bulk jobs)             | `lock:{jobId}`                             | Job timeout + buffer |
| Short-lived tokens (MFA nonce, SSO state) | `mfa_nonce:{userId}` / `sso_state:{nonce}` | 5 min / 10 min       |

> **Redis is coordination and cache — not a database. Never store data in Redis that cannot be reconstructed from Postgres. Session loss means re-authentication. Nothing is permanently lost.**

### 6.4 Object Storage (S3)

- All binary document data lives in S3. Postgres stores metadata and lifecycle state only.
- Path convention: `{tenantId}/{context}/{entityId}/{fileName}-{versionId}`
- Client uploads directly to S3 via pre-signed URL. Binary never passes through the app server.
- Downloads via pre-signed URLs with short expiry (15 min). Never public URLs.
- Server-side encryption at rest (SSE-S3 minimum, SSE-KMS for compliance tenants).
- Lifecycle policy: STANDARD_IA after 90 days, Glacier after 12 months for archived documents.

### 6.5 Read Models & Reporting

Phase 1: Postgres materialized views, hourly refresh. Phase 2: read replica for analytical queries when operational performance is measurably impacted. Phase 3: dedicated analytics pipeline only when a read replica is insufficient.

> **Do not build a data warehouse on day one. The signal is: "Analytical queries degrade operational performance even on a read replica." You are not there yet.**

### 6.6 Data Retention & Archival Strategy

| Data type            | Active retention                        | Archival policy                                                    | Hard delete?                        |
| -------------------- | --------------------------------------- | ------------------------------------------------------------------ | ----------------------------------- |
| Audit events         | Indefinite (partitioned)                | Compress partitions > 13 months. Never delete.                     | Never — legal record.               |
| Documents & versions | Active for process lifetime             | Archive 90 days after process completion. Glacier after 12 months. | Only with legal hold clearance.     |
| Process instances    | Active for tenant subscription lifetime | Soft-archive 12 months after completion.                           | No — process records are permanent. |
| Notification feed    | 90 days active                          | Delete after 180 days.                                             | Yes — no legal requirement.         |
| Outbox messages      | Until delivered                         | Hard delete after 30 days post-delivery.                           | Yes — transient infrastructure.     |
| Bulk job logs        | 90 days                                 | Archive after 90 days.                                             | After 12 months.                    |
| HRIS sync run logs   | 30 days active                          | Delete after 90 days.                                              | Yes — operational logs only.        |
| Sessions (Redis)     | 24h TTL                                 | Expired automatically.                                             | N/A — ephemeral.                    |

---

## 7. Multi-Tenant Architecture Strategy

### 7.1 Model: Shared Schema, Row-Level Isolation

Recommended: shared schema with row-level tenant isolation. Every tenant-scoped table has a `tenant_id` column. Every query against those tables includes `WHERE tenant_id = ?` enforced at the typed DAL layer, not application layer.

### 7.2 The Four Isolation Layers

| Layer                     | Mechanism                                                                                                  | What it prevents                                                              |
| ------------------------- | ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| 1 — URL Resolution        | Tenant resolved from URL subdomain on every request. Structural, not claimable.                            | URL spoofing. Tenant ID in request body cannot override this.                 |
| 2 — Session Binding       | Session bound to tenantKey at creation. Middleware verifies match on every request. Mismatch → silent 401. | Session replay across tenants. Stolen session used on wrong subdomain.        |
| 3 — Typed DAL Enforcement | tenantId is a required typed parameter in every DAL function touching tenant data. TypeScript enforces it. | Developers forgetting WHERE clauses. Query construction without tenant scope. |
| 4 — 404 not 403           | Cross-tenant resource access returns 404, never 403.                                                       | Tenant existence probing. Information leak about other tenants' data.         |

### 7.3 Tenant Configuration Architecture

- Tenant settings are loaded once per request at tenant resolution and placed into request context.
- Modules read settings from context — they do not re-query the DB per request.
- Settings changes are audit-logged. Default values are defined in code, not discovered from DB.
- Feature flags (`hris_import_enabled`, `public_signup_enabled`) are tenant settings, not code flags.

### 7.4 Defense-in-Depth Tenancy Strategy

> **The query layer is primary enforcement. But primary enforcement is not sufficient alone for a compliance-grade platform. Plan defense-in-depth from the start.**

| Defense layer                               | Status                | Implementation                                                                                                                                                     |
| ------------------------------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Query-layer typed enforcement               | Current (primary)     | tenantId required parameter in every DAL function. TypeScript types enforce it at compile time.                                                                    |
| Integration & HRIS worker tenant validation | Required now          | Every async worker that processes tenant-scoped jobs must re-validate tenant_id from the job record — not trust the caller.                                        |
| Automated tenant isolation tests            | Required now          | CI test suite: for every module, verify that a query with tenant_id=A cannot return rows with tenant_id=B. Run on every PR.                                        |
| Postgres Row Level Security (RLS)           | Phase 2 consideration | Apply RLS on the highest-risk tables (process_instances, documents, audit_events) as a secondary enforcement layer. Not a replacement for query-layer enforcement. |
| Regular penetration testing                 | Deployment phase      | Cross-tenant access testing by an external party at least annually.                                                                                                |

**Critical rule for async workers:** a bulk job worker that processes `process_instance_id=X` must validate that `X.tenant_id` matches the job's `tenant_id` before processing. Workers are a common place where tenant isolation is accidentally bypassed because "the job already has the right IDs."

---

## 8. Communications & Notifications Architecture

> **Communications is a distinct bounded context that reacts to domain events. It must never be called synchronously from business logic. Every communication originates from the outbox. The producing module does not know or care how the communication is delivered.**

### 8.1 Email Architecture

- Producing flow enqueues an outbox row inside its DB transaction. The row contains: `{ channel: "email", templateKey, recipientUserId, tenantId, payload: {...variables} }`.
- Email worker claims the row, resolves the tenant-customized template (with fallback to global default), renders it, calls the email provider, marks delivered.
- Failed delivery: exponential backoff up to N retries, then dead-letter. Ops alert on dead-letter.
- Template rendering happens in the worker, not in the producing flow. Template customizations by tenants take effect without code changes.

### 8.2 In-App Notifications

| Concern          | Design                                                                                                                          |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Storage          | `notification_feed(id, user_id, tenant_id, type, payload, read_at, created_at, expires_at)`                                     |
| Fan-out          | Worker reads domain event, determines recipients via People / Directory, bulk-inserts notification rows. Batch, not one-by-one. |
| Browser delivery | Phase 1: polling 30s. Phase 2: SSE. Phase 3: WebSockets if bidirectional needed.                                                |
| Preferences      | `notification_preferences(user_id, tenant_id, notification_type, channel, enabled)`. Default: all on.                           |
| Retention        | Soft-delete or expire after 90 days. Hard delete after 180 days.                                                                |

### 8.3 Channel Abstraction (SMS / Push Ready)

Design the outbox row schema for channel abstraction now: `{ channel: "email" | "sms" | "push" | "in_app", templateKey, recipientId, tenantId, payload }`. The worker routes to the correct provider. Adding SMS means adding a new provider implementation behind the same interface — no change to producing modules.

Recipient routing logic (does this user have SMS enabled? what is their phone? what are their preferences?) lives entirely in Communications. Producing modules pass the userId and event type only.

---

## 9. Bulk Operations, Scheduled Jobs & Integrations

### 9.1 Bulk Operations Design

Bulk operations must be designed for: tenant isolation (one tenant's job must not degrade others), observability (progress is queryable), correctness (partial failures must not silently succeed), and idempotency (re-running a failed job must be safe).

**Pattern: Job table + worker pool**

1. Admin initiates bulk operation → system creates `bulk_jobs` row (status: QUEUED, totalItems: N). HTTP returns immediately with `job_id`.
2. Bulk worker polls for QUEUED jobs, claims with `UPDATE ... WHERE status = QUEUED RETURNING`.
3. Worker processes in batches of 50. Each batch is a single Postgres transaction.
4. Batch failures are recorded individually on `bulk_job_items`. The rest of the batch continues.
5. After all batches: status → COMPLETED or COMPLETED_WITH_ERRORS. Failed items are queryable.
6. Admin can retry failed items only. Idempotency key per item prevents double-processing.

| bulk_jobs column                           | Purpose                                                              |
| ------------------------------------------ | -------------------------------------------------------------------- |
| id, tenant_id, type                        | Identity and tenant scoping                                          |
| status                                     | QUEUED \| PROCESSING \| COMPLETED \| COMPLETED_WITH_ERRORS \| FAILED |
| total_items, processed_items, failed_items | Progress tracking for admin UI                                       |
| claimed_at, worker_id                      | Ownership for crash recovery via lease expiry                        |
| idempotency_key                            | Prevents duplicate job creation for same admin action                |
| error_summary                              | JSON summary of failure reasons — shown in admin job detail UI       |

### 9.2 Scheduled Jobs

- Every scheduled job has a DB row: `last_run_at`, `next_run_at`, `status`, `error`. Never use OS cron alone.
- Scheduler is a worker polling for jobs `WHERE next_run_at <= now`. Stale claimed jobs auto-released after timeout.
- Each execution has a `run_id` as idempotency key. Running the same job twice in the same window is safe.
- Tenant-level jobs (run this checklist for all new hires monthly) are rows in `scheduled_jobs` scoped by `tenant_id`.
- Platform jobs (ADP sync) are rows in `system_scheduled_jobs` with no tenant scope.

### 9.3 External Integrations (Anti-Corruption Layer)

> **Integrations are the most dangerous place to violate architecture principles. External systems have unreliable APIs, unexpected data shapes, and their own retry semantics. The anti-corruption layer is not optional.**

- **ADP employee data is parsed into an intermediate `AdpEmployee` type first. Never directly written to domain tables.**
- Translation to domain commands (`CreatePersonCommand`, `CreateMembershipCommand`) happens at the boundary.
- If ADP changes schema, only the integration layer changes. Core domain is unaffected.
- Webhook receivers are thin: validate signature, write to `inbound_webhooks` table, return 200. A worker processes the row.
- All external API calls are async — never in request handlers. ADP being slow cannot affect login latency.

### 9.4 Failure Handling & Operator UX

Operators (admins and support staff) must be able to observe, diagnose, and recover from failures without engineering involvement for standard failure modes.

| Failure scenario                         | Operator-visible surface                                                                              | Recovery action available                                                                        |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Bulk job partially failed                | `bulk_job_items` table with per-item error reason. Admin UI shows "N items failed" with reason codes. | Admin can trigger "retry failed items" which re-queues failed items only.                        |
| Job stuck in PROCESSING (worker crashed) | `bulk_jobs.claimed_at` > timeout threshold. Worker health metric missing.                             | Auto-release via lease expiry. Ops runbook SQL query to manually release if needed.              |
| Permanent error (unretryable)            | Item status = PERMANENTLY_FAILED with error code. Different from retryable errors.                    | Admin sees clear message. Engineering ticket required. Not shown as retryable.                   |
| HRIS sync failure                        | `sync_runs` table with status, error, duration. Admin dashboard shows last sync status.               | Admin can trigger manual re-sync. Error shows which records failed and why.                      |
| Document generation pipeline failure     | `document.status` = GENERATION_FAILED with error detail.                                              | Admin can trigger retry. If provider error, system shows provider status page link.              |
| Email dead-lettered                      | `outbox.status` = DEAD_LETTER. Ops alert sent.                                                        | Engineering reviews dead-letter. Admin can trigger manual resend for invite/reset emails via UI. |

**Error taxonomy:** every error exposed to operators must classify as: RETRYABLE (temporary provider/network issue, worker will auto-retry), OPERATOR_ACTION_REQUIRED (bad input data that a human must correct), or ENGINEERING_REQUIRED (system bug, requires code fix). This distinction prevents operators from retrying permanently-failed items indefinitely.

---

## 10. Microservices vs. Modular Monolith

> **Recommendation: Do not build microservices now. This is not a risk-averse hedge — it is the correct engineering decision for the current team, scale, and domain maturity.**

### 10.1 The Case Against Microservices Now

| Problem                               | Concrete impact on Insynctive                                                                                                                                                                                    |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Distributed transactions              | Completing a workflow step triggers task creation, document requests, and notifications — all currently in one ACID transaction. Distributed sagas for this are 10× the complexity with no user-visible benefit. |
| Network latency in hot paths          | Login → session → membership check → MFA check is 4+ synchronous network hops if separate services. The monolith does this in-process.                                                                           |
| Operational overhead                  | Each service needs its own deployment pipeline, health checks, logging, tracing, and scaling policy. A small team maintaining 10+ services spends more time on infrastructure than product.                      |
| Schema coupling disguised as services | Without mature domain boundaries, microservices become distributed monoliths — sharing a DB or calling each other synchronously. Worst of both worlds.                                                           |
| No proven scaling need                | No module has a measured, proven need for independent scaling today. Build separately only when the need is proven.                                                                                              |

### 10.2 What Prevents the Monolith from Becoming a Big Ball of Mud

- **No module imports another module's DAL or internal types. Cross-module calls go through defined service interfaces only.**
- Outbox is the cross-module async communication channel. No direct service calls across async boundaries.
- Each module exclusively owns its DB tables. No cross-module JOINs.
- Modules are structured as independent deployable units in the filesystem — preserving future extraction.
- Architecture fitness functions (Section 12.1) enforce boundaries in CI — not by convention alone.

### 10.3 Extraction Criteria — All Three Must Be True

| #   | Criterion                             | Signal                                                                                    |
| --- | ------------------------------------- | ----------------------------------------------------------------------------------------- |
| 1   | Measured, proven scale bottleneck     | Module X is the measured cause of p95 latency above SLA. Not suspected — traced with APM. |
| 2   | Different deployment cadence required | Module X must deploy multiple times per day independently of the rest of the system.      |
| 3   | Clean domain boundary already exists  | Module has no direct DB coupling to others. Extraction is mechanical, not architectural.  |

---

## 11. Future Extraction Map

Extraction order is driven by natural async boundary isolation, not module importance. The most important module (Workflow Runtime) is extracted last or not at all.

| Module                                     | Timeline                  | Extract?                                                          | Rationale                                                                  |
| ------------------------------------------ | ------------------------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Document Processing (generation + signing) | Medium-term 12–24 months  | Yes — if document volume or provider complexity demands isolation | High throughput external provider. Already async-only. Natural extraction. |
| Communications / Notifications             | Long-term 18–36 months    | Yes — when multi-channel fan-out volume is high                   | Already async-only. No sync dependencies. Clean extraction.                |
| Integrations / Sync Workers                | Long-term 18–36 months    | Yes — if integration count grows beyond 5–10                      | Already isolated. Different deployment cadence possible.                   |
| Benefits & Rates                           | Long-term or never        | Only if calculation complexity demands dedicated compute          | Bounded sub-domain. May warrant extraction if becomes complex.             |
| Reporting / Analytics                      | Long-term or never        | Only if analytics require separate compute                        | Read-only. Read replica usually sufficient.                                |
| Workflow Runtime Engine                    | Very long-term or never   | Only if runtime scale is measurably unsustainable                 | Core domain. Highest risk. Last to extract.                                |
| Identity & Access                          | Never (or very long-term) | Only if becoming a standalone auth product                        | Tightly coupled to session/tenant lifecycle.                               |
| Tenant Management                          | Never                     | No                                                                | Too many cross-cutting dependencies.                                       |

> **Extraction order: Document Processing → Communications → Integrations → (reassess everything else). The Workflow Runtime stays in the monolith longest. The auth layer stays forever unless Insynctive becomes an auth platform product.**

---

## 12. Major Risks & Anti-Patterns

| Sev. | Anti-pattern                                             | What goes wrong                                                                                               | Prevention                                                                                                          |
| ---- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| P0   | Tenant isolation bug in query layer                      | Row-level isolation by convention fails when a WHERE clause is forgotten. At scale, this is a data breach.    | tenantId required typed parameter in every DAL function. CI tenant isolation tests on every module. Annual pentest. |
| P0   | Business logic in outbox workers                         | Worker makes a business decision. Creates a hidden logic layer with no tests.                                 | Workers transform and deliver events only. Business decisions happen in flows before the event is enqueued.         |
| P1   | Vocabulary drift: task vs step vs process vs checklist   | Engineers casually mix terms. Domain model corrupts in 6 months.                                              | Section 2.1 canonical vocabulary. Enforced in code reviews and PRs. Reject PRs with wrong terminology.              |
| P1   | God User object (auth identity + business person merged) | User table becomes the catch-all for auth credentials, profile, employment data, HR IDs, and preferences.     | Enforce Identity & Access / People split from day one. Never add employment data to the users table.                |
| P1   | Sync external HTTP in request paths                      | ADP API called during a user request. ADP is slow or down. All users affected.                                | Zero synchronous external HTTP calls in request handlers. All external calls are async via workers.                 |
| P1   | Audit event gaps on new endpoints                        | New endpoints ship without audit events. Compliance-sensitive actions have no trail.                          | PR template: mandatory audit checklist. Reviewer checks coverage. CI fails if mutating endpoint has no audit call.  |
| P1   | Template mutation affecting in-flight processes          | Admin edits a template. Running process instances change behavior mid-execution.                              | Invariant 4.3: rules are snapshotted at launch. Template changes never affect running instances.                    |
| P1   | Unbounded audit_events table                             | At millions of events/month, full-table scans kill the DB.                                                    | Partition `audit_events` by `created_at` month from day one via `pg_partman`.                                       |
| P2   | Bulk jobs running synchronously in HTTP request          | Admin triggers bulk for 5,000 records via HTTP. Request times out. Half-created state.                        | Bulk operations are always async. Request creates `bulk_jobs` row, returns `job_id` immediately.                    |
| P2   | Event soup — async everything                            | Every module emits events. A single action spawns 15 events. Debugging requires tracing the full event graph. | Use outbox for external side effects only. Intra-flow logic stays in the flow function as direct calls.             |
| P2   | Cross-module table access                                | Module A and Module B both write to the same table. Distributed monolith anti-pattern.                        | Each module owns its tables exclusively. CI import rules block cross-module internal access.                        |
| P3   | Missing idempotency on retry paths                       | Outbox retries. Email provider was slow but did deliver. User receives duplicate email.                       | Idempotency key on every outbox message. Pre-check before processing: "was this already delivered?"                 |

### 12.1 Architecture Fitness Functions

> **Architecture fitness functions turn the anti-patterns above into measurable, CI-enforced rules. Good intent without enforcement degrades over time. These rules must run on every PR.**

| Fitness function                                 | Enforcement mechanism                                                                              | Fail condition                                                         |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| No cross-module internal imports                 | ESLint `eslint-plugin-import` no-restricted-paths rule. Configured per module.                     | Any file importing from `src/modules/X/dal/*` from outside module X.   |
| tenantId required in all DAL functions           | TypeScript strict types. DAL function signatures enforce tenantId parameter.                       | TypeScript compilation error on any DAL function missing tenantId.     |
| No synchronous external HTTP in request handlers | ESLint custom rule banning direct fetch/axios calls outside `/integrations` or `/workers` folders. | HTTP call found in `/modules/*/flows/*` or `/modules/*/controllers/*`  |
| Every mutating endpoint has audit coverage       | Custom test assertion: every POST/PUT/PATCH/DELETE E2E test must assert audit_events row created.  | E2E test passes but no `audit_events` row found for the action.        |
| Every async producer uses outbox                 | ESLint rule banning direct email provider calls outside `/workers` or `/outbox`.                   | Email provider SDK called directly in a flow or service.               |
| Every bulk operation exposes progress state      | PR checklist item: new bulk operation must have `bulk_jobs` + `bulk_job_items` rows.               | Bulk endpoint without a corresponding `bulk_jobs` entry in the schema. |
| Tenant isolation test per module                 | Automated test: query with tenant_id=A must not return data with tenant_id=B.                      | Tenant isolation test fails for any module.                            |
| New reporting queries must not hit OLTP hot path | PR review gate: queries against large operational tables require EXPLAIN ANALYZE evidence.         | Query without index that performs seq scan > 10K rows.                 |
| Extraction readiness review (quarterly)          | Quarterly architecture review against the 3 extraction criteria from Section 10.3.                 | No extraction performed without all three criteria being met.          |

---

## 13. Recommended North-Star Architecture Statement

> **Insynctive is a structured process execution platform for multi-tenant organizations. Its architecture must reflect that identity at every layer.**
>
> The Workflow Runtime Engine is the irreplaceable core — every other module exists to support, record, or communicate what it produces. Process, Step, Task, and Participant are the canonical terms of the domain. These terms must never be used interchangeably. The template defines what can happen. The runtime instance owns what is happening. The task is the human-facing unit of work. These are different things and must be modeled as different things.
>
> A login identity is not a business person. An Auth Principal owns credentials. A Person owns business participation. HRIS-imported employees, external participants, and dependents all exist in the domain without necessarily having credentials. This separation is non-negotiable.
>
> The architecture is a disciplined modular monolith with intentional async boundaries. Module boundaries are enforced by CI fitness functions, not by team discipline alone. Cross-module communication is explicit: synchronous service interfaces for immediate state changes, DB outbox for all side-effecting async work. No module queries another module's tables.
>
> Tenant isolation is enforced at four independent layers. A data leak between tenants is a platform-level failure. Every layer must hold independently because no single layer is sufficient.
>
> Complexity is introduced when proven necessary, not when imaginable. PostgreSQL + Redis + S3 + the outbox pattern will carry this system further than most teams believe. Extraction of services follows measured operational necessity. What ships correct, observable, and maintainable today is more valuable than what is theoretically scalable tomorrow.

---

## Architecture Principles Summary

| Principle                                  | What it means in practice                                                                                       |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| Domain language before infrastructure      | Canonical vocabulary (Section 2.1) is the first architecture decision, not a nice-to-have.                      |
| Identity ≠ Person                          | Auth Principal and business Person are always separate entities linked by a nullable key.                       |
| Runtime correctness over delivery speed    | A bug in the workflow engine is a business failure. Get the domain model right first.                           |
| Boundaries enforced structurally           | Fitness functions in CI. Not conventions. Not documentation. Compiled, tested rules.                            |
| Outbox before broker                       | The outbox is the async infrastructure. A broker is introduced only when the outbox is measurably insufficient. |
| Idempotency everywhere async               | Every retry path, every webhook, every import, every bulk item must be safe to process twice.                   |
| Tenant isolation is four layers deep       | URL + session + typed DAL + 404-not-403. Each layer holds independently.                                        |
| Observability is a design constraint       | Correlation IDs, tenant IDs, and entity IDs on every log line and metric from day one.                          |
| Operators can self-serve standard failures | Retryable vs permanent vs engineering-required errors. Admin UI surfaces job status clearly.                    |
| Prove before distributing                  | No extraction without all three criteria: measured bottleneck, deployment cadence, clean boundary.              |
