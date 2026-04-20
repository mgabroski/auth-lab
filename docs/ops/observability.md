# Observability

## Purpose

This document defines the current operability surface for the Auth Lab stack.

It exists so operators can answer, with evidence:

- what failed
- when it started
- who is affected
- whether a release likely caused it
- how to triage it

This document is intentionally implementation-grounded.
It only describes signals that the repository can emit today or that are directly tied to code paths already added in the current repo state.
It does **not** assume Grafana, Prometheus server, Datadog, OpenTelemetry collectors, or any other external observability platform.

---

## Operating principles

### 1. Same-origin and topology rules remain authoritative

Observability must not weaken the locked architecture.

That means:

- browser requests remain same-origin under `/api/*`
- tenant identity remains host-derived
- SSR continues to forward the headers the backend requires
- cookies and session truth remain backend-authoritative
- observability must not introduce cross-tenant data leakage

### 2. Structured logs before dashboards

Dashboards and alerts are only useful if they are backed by stable emitted signals.

The current baseline therefore starts with:

- structured logs
- request correlation
- low-cardinality metrics
- smoke checks proving those signals exist

### 3. Low-cardinality metrics only

Metrics must stay safe and operable.

Never use any of the following as metric labels:

- request IDs
- tenant keys
- user IDs
- membership IDs
- invite IDs
- email addresses
- raw paths with dynamic identifiers
- token values of any kind

### 4. Request ID is the primary correlation key

For the current repo baseline, `x-request-id` is the canonical correlation key.

Rules:

- if a valid inbound `x-request-id` exists, preserve it
- otherwise fall back to `x-correlation-id`
- otherwise generate a new request ID
- backend responses echo `x-request-id`
- frontend SSR/server paths forward `x-request-id` to backend requests

### 5. Release correlation must be visible

Logs must include release context where available so operators can judge whether a release likely caused a new failure pattern.

Current expectation:

- backend logs include `release`
- frontend server-path logs include `release`
- Sentry release remains useful for unhandled backend exceptions

---

## Current observability surface

## Structured logs

### Backend

The backend emits structured JSON logs for:

- request start
- request completion
- handled application errors
- unhandled errors
- outbox worker lifecycle and failure paths

Important event families:

- `request.started`
- `request.completed`
- `app_error`
- `unhandled_error`
- `outbox.worker.started`
- `outbox.worker.stopped`
- `outbox.tick.done`
- `outbox.tick.failed`
- `outbox.claimed`
- `outbox.sent`
- `outbox.retry_scheduled`
- `outbox.dead_lettered`
- `outbox.finalize_lost_claim`

### Control Plane mutation logs and audit trail

The Control Plane currently relies on structured backend logs plus the shared audit trail for mutation diagnosis.
There is no separate CP metrics family yet.

Structured backend log events currently emitted by the CP accounts service include:

- `cp.accounts.created`
- `cp.accounts.published`
- `cp.accounts.status_toggled`
- `cp.accounts.create.failure_audit_failed`
- `cp.accounts.access.failure_audit_failed`
- `cp.accounts.account_settings.failure_audit_failed`
- `cp.accounts.modules.failure_audit_failed`
- `cp.accounts.personal.failure_audit_failed`
- `cp.accounts.integrations.failure_audit_failed`
- `cp.accounts.status_toggle.failure_audit_failed`
- `cp.accounts.publish.failure_audit_failed`

The shared audit trail is the canonical evidence source for successful and failed CP account mutations.
Current CP audit actions include:

- `cp.account.created`
- `cp.account.access.saved`
- `cp.account.account_settings.saved`
- `cp.account.modules.saved`
- `cp.account.personal.saved`
- `cp.account.integrations.saved`
- `cp.account.published`
- `cp.account.status_toggled`
- `cp.account.create.failed`
- `cp.account.access.save.failed`
- `cp.account.account_settings.save.failed`
- `cp.account.modules.save.failed`
- `cp.account.personal.save.failed`
- `cp.account.integrations.save.failed`
- `cp.account.publish.failed`
- `cp.account.status_toggle.failed`

For CP troubleshooting, correlate the backend request log, `x-request-id`, CP mutation log event, and the matching audit row. That is the current honest diagnosis path until dedicated CP dashboards or metrics exist.

### Frontend server paths

The frontend server logger is used for SSR/bootstrap and backend transport failures.

Important event families:

- `ssr.api.transport_failed`
- `auth.bootstrap.config_failed`
- `auth.bootstrap.config_transport_failed`
- `auth.bootstrap.me_failed`
- `auth.bootstrap.me_transport_failed`
- `auth.bootstrap.unknown_failure`

---

## Metrics surface

## Export format

The backend exposes metrics at:

```text
/metrics
```

Content type:

```text
text/plain; version=0.0.4; charset=utf-8
```

The reverse-proxied production-style path is therefore:

```text
/api/metrics
```

## Current metric catalog

### HTTP lifecycle

#### `http_requests_total`

Counter.

Purpose:

- total completed HTTP requests by normalized route, method, and status

Labels:

- `method`
- `route`
- `status`
- `status_class`

#### `http_request_duration_ms`

Histogram.

Purpose:

- request duration by normalized route, method, and status class

Labels:

- `method`
- `route`
- `status_class`

### Auth failures

#### `auth_login_failures_total`

Counter.

Purpose:

- failed login attempts

Labels:

- `reason`
- `code`
- `status`

#### `password_reset_failures_total`

Counter.

Purpose:

- password reset request and confirm failures

Labels:

- `step`
- `reason`
- `code`
- `status`

#### `mfa_failures_total`

Counter.

Purpose:

- MFA setup, verify, and recovery failures

Labels:

- `step`
- `reason`
- `code`
- `status`

#### `sso_failures_total`

Counter.

Purpose:

- SSO start and callback failures

Labels:

- `step`
- `provider`
- `reason`
- `code`
- `status`

### Invite and tenant failures

#### `invite_failures_total`

Counter.

Purpose:

- invite create, resend, cancel, and accept failures

Labels:

- `action`
- `reason`
- `code`
- `status`

#### `tenant_resolution_failures_total`

Counter.

Purpose:

- failures where tenant context cannot be resolved correctly

Labels:

- `route`
- `reason`
- `status`

### SSR/bootstrap failures

#### `ssr_bootstrap_failures_total`

Counter.

Purpose:

- backend failures observed during SSR/bootstrap requests marked with `x-auth-bootstrap: 1`

Labels:

- `target`
- `reason`
- `status`

Important note:

- frontend transport failures that do not reach the backend are logged on the frontend server path but are not counted in this metric

### Email delivery failures

#### `email_delivery_failures_total`

Counter.

Purpose:

- outbox email decryption and delivery failures

Labels:

- `message_type`
- `stage`
- `reason`

### Control Plane note

The repository does not currently emit a dedicated CP metrics family.
CP diagnosis depends on normalized request metrics, structured backend logs, and the shared audit trail described above.

---

## Metric reason taxonomy

The current reason classifier intentionally stays small.

Recognized normalized reasons include:

- `rate_limited`
- `unauthorized`
- `forbidden`
- `not_found`
- `conflict`
- `validation`
- `unexpected`
- `other`

Tenant-resolution specific reasons currently include:

- `missing_key`
- `missing_context`
- `inactive`
- `not_found`
- `workspace_unavailable`

Email delivery reasons currently include:

- `decrypt_failed`
- `retryable`
- `non_retryable`
- `max_attempts_exceeded`
- `unexpected`

---

## Route normalization rules

Metrics must use normalized route names, never raw per-resource URLs.

Examples:

- `/auth/sso/google` → `/auth/sso/:provider`
- `/auth/sso/google/callback` → `/auth/sso/:provider/callback`
- `/admin/invites/123/resend` → `/admin/invites/:inviteId/resend`
- `/admin/invites/123` → `/admin/invites/:inviteId`

This keeps metrics cardinality safe and keeps dashboard grouping stable.

---

## Dashboard design

The repository does not currently assume a dashboard vendor.
Until a vendor is selected, this section defines the required dashboard panels logically.

## Dashboard 1 — Auth journey health

Purpose:

- answer whether core auth flows are degrading

Required panels:

1. login failures by reason over time
   - source: `auth_login_failures_total`

2. password reset failures by step over time
   - source: `password_reset_failures_total`

3. MFA failures by step over time
   - source: `mfa_failures_total`

4. SSO failures by provider and step over time
   - source: `sso_failures_total`

5. HTTP request rate and error rate for auth routes
   - source: `http_requests_total`

6. auth route latency
   - source: `http_request_duration_ms`

## Dashboard 2 — Tenant/bootstrap health

Purpose:

- answer whether tenant routing or SSR bootstrap is failing

Required panels:

1. tenant-resolution failures over time
   - source: `tenant_resolution_failures_total`

2. SSR/bootstrap failures by target over time
   - source: `ssr_bootstrap_failures_total`

3. request error rate for `/auth/config` and `/auth/me`
   - source: `http_requests_total`

4. request latency for `/auth/config` and `/auth/me`
   - source: `http_request_duration_ms`

## Dashboard 3 — Email / outbox health

Purpose:

- answer whether user-facing email flows are degrading

Required panels:

1. email delivery failures by message type and reason
   - source: `email_delivery_failures_total`

2. invite failures by action
   - source: `invite_failures_total`

3. password reset failures over time
   - source: `password_reset_failures_total`

4. request rate / error rate for invite and reset routes
   - source: `http_requests_total`

## Dashboard 4 — Control Plane mutation health

Purpose:

- answer whether CP create, Step 2 save, publish, or status-toggle flows are failing
- give operators one triage path for CP mutation incidents even before dedicated CP metrics exist

Required panels:

1. CP mutation request rate / error rate
   - source: `http_requests_total` filtered to `/cp/*` routes

2. CP mutation latency
   - source: `http_request_duration_ms` filtered to `/cp/*` routes

3. CP mutation log events over time
   - source: structured backend logs for `cp.accounts.*`

4. CP audit mutations over time
   - source: shared audit storage filtered to `cp.account.*` actions

---

## Alert policy

The repository does not currently wire alerts into an external paging system.
This section defines the severity tiers that any chosen alerting system must implement.

## Severity model

### Sev 1

Use when:

- login failures spike sharply for most tenants or all tenants
- tenant resolution fails broadly
- SSR/bootstrap failures prevent the app from loading for most users
- `/api/health` or `/api/metrics` is unavailable in a release candidate or deployed stack

Operator expectation:

- immediate investigation
- release impact considered immediately
- rollback candidate considered quickly if coincident with deployment

### Sev 2

Use when:

- one critical auth flow is degraded but not fully down
- one SSO provider begins failing significantly
- email delivery failures spike for invite/reset/verification flows
- latency or 5xx rate rises materially on critical auth routes

Operator expectation:

- urgent investigation during active hours
- correlate with deployment and recent config changes

### Sev 3

Use when:

- isolated or low-rate failures trend upward
- one failure reason begins appearing unusually often
- non-critical operational noise needs cleanup before it becomes real incident risk

Operator expectation:

- ticket and track
- no paging unless it worsens

## Recommended initial alert rules

These are the first alerts worth wiring once a metrics backend is selected.

1. Auth login failure spike
   - signal: `auth_login_failures_total`
   - severity: Sev 1 or Sev 2 depending on rate and blast radius

2. Tenant resolution failures detected
   - signal: `tenant_resolution_failures_total`
   - severity: Sev 1 if broad, otherwise Sev 2

3. SSR/bootstrap failure spike
   - signal: `ssr_bootstrap_failures_total`
   - severity: Sev 1 or Sev 2

4. SSO callback failure spike by provider
   - signal: `sso_failures_total{step="callback"}`
   - severity: Sev 2

5. Email delivery failure spike
   - signal: `email_delivery_failures_total`
   - severity: Sev 2

6. Critical route 5xx or latency regression
   - signal: `http_requests_total`, `http_request_duration_ms`
   - severity: Sev 2

---

## First SLO set

These SLOs are deliberately realistic for the current implementation.
They should only be adopted if the metrics backend can compute them reliably.

## SLO 1 — Auth bootstrap availability

Goal:

- SSR/bootstrap for `/auth/config` remains highly available

Measured by:

- proportion of successful `/auth/config` requests using `http_requests_total`
- correlated with `ssr_bootstrap_failures_total`

Suggested initial target:

- 99.9% successful `/auth/config` responses over 30 days

## SLO 2 — Session bootstrap availability

Goal:

- authenticated session bootstrap requests to `/auth/me` succeed when the backend should be able to answer them

Measured by:

- success/error ratio for `/auth/me`
- interpret 401 carefully because 401 can be expected for unauthenticated sessions

Suggested initial target:

- 99.9% of non-expected `/auth/me` backend responses succeed over 30 days

## SLO 3 — Invite and reset delivery path health

Goal:

- invite and password reset flows do not silently degrade due to backend or delivery failures

Measured by:

- `invite_failures_total`
- `password_reset_failures_total`
- `email_delivery_failures_total`

Suggested initial target:

- no sustained Sev 2 degradation over 30 days

## SLO 4 — Critical auth route latency

Goal:

- core auth routes stay fast enough for normal user-facing behavior

Measured by:

- `http_request_duration_ms`

Initial candidate routes:

- `/auth/login`
- `/auth/config`
- `/auth/me`
- `/auth/sso/:provider/callback`

Suggested initial target:

- p95 below an operator-agreed threshold after baseline measurement

Important note:

- latency SLO thresholds should be locked only after baseline measurement in the target environment

---

## Smoke checks

## Operability smoke scope

The CI/deploy smoke script for the current baseline must prove:

- `/api/health` works through the proxy
- `x-request-id` is returned on a normal proxied request
- `/api/metrics` is reachable through the proxy
- `/api/metrics` returns Prometheus text
- a deterministic failed login increments `auth_login_failures_total`

This is the minimum durable proof that observability is real and usable.

## Why this smoke matters

Without it, observability can silently regress while the app still “works.”

The smoke check protects against:

- request correlation regressions
- metrics endpoint regressions
- failure counter regressions
- proxy path regressions that break operability even if app pages still load

---

## Triage workflow

Use this order during an incident.

### 1. Confirm whether the issue is broad or narrow

Check:

- health endpoint
- metrics endpoint
- recent request error rates
- whether failures cluster around one route, one provider, or one flow

### 2. Check whether a release likely caused it

Check:

- current release values in logs
- deployment timeline
- whether the signal changed immediately after a release or config change

### 3. Check request correlation

Use `x-request-id` to correlate:

- frontend server-path logs
- backend request logs
- backend error logs
- outbox logs if relevant

### 4. Check the flow-specific counters

Examples:

- login issue → `auth_login_failures_total`
- tenant host issue → `tenant_resolution_failures_total`
- SSR load issue → `ssr_bootstrap_failures_total`
- email issue → `email_delivery_failures_total`

### 5. Move into the relevant runbook

This document defines the signals.
The triage procedure lives in `docs/ops/runbooks.md`.

---

## Evidence expectations during incidents

For an incident review against the current baseline, capture:

- time window of degradation
- affected routes and flows
- affected tenant scope if known from safe evidence
- correlated request IDs when available
- metric screenshots or query output
- release or deploy correlation
- mitigation and recovery steps taken

---

## Deferred but expected later

These are intentionally **not** part of the current minimum:

- external metrics backend selection
- dashboard vendor implementation details
- paging platform integration
- long-term log retention policy
- distributed tracing across external services
- tenant-scoped business analytics dashboards

They may be added later, but they are not required to make the current observability baseline real.

---

## Change rules

Do not add a new dashboard, alert, or SLO to this document unless:

1. the underlying signal already exists in code, or
2. the change includes the code work that emits the signal

Do not add observability artifacts that are not backed by real emitted metrics or real structured log events.

This document must stay tied to actual operability proof, not aspiration.
