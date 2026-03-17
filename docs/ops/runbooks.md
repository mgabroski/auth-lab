# Hubins — Operational Runbooks

_Tier 2 — Global Growing_
_Organized by operational concern, not by module._
_Add sections as new modules ship. Never split into per-module files._

This document is the single home for all Hubins operational procedures.

When something breaks in production, this document should be the second thing you open — after the logs.

Runbooks are organized by **symptom and response**, not by which module owns the underlying code. An on-call engineer responds to "the outbox is stalled," not "the invites module's outbox is stalled."

---

## How to use this document

1. Identify the symptom from alerts, logs, or user reports
2. Find the matching section below
3. Follow the investigation steps in order
4. Escalate or resolve based on findings
5. If this runbook did not help, add the missing steps after resolving the incident

---

## System Dependencies and Health Checks

### Health endpoint

The backend exposes a liveness/readiness probe at `GET /health`.

**What it checks:**

- `checks.db: true` — backend can reach Postgres with a trivial query
- `checks.redis: true` — backend can write to Redis

**What a 503 means:**
The process is alive but cannot reach a critical dependency. Traffic should not be routed to this instance.

**What a connection failure means:**
The process itself is unhealthy (crash, OOM, port not binding). Check process manager logs.

**Normal response shape (non-production):**

```json
{
  "ok": true,
  "env": "production",
  "service": "auth-lab-backend",
  "checks": {
    "db": true,
    "redis": true
  }
}
```

---

## Authentication and Session Issues

### Symptom: users cannot stay logged in or are bounced back to login

**Likely causes:**

- cookie domain/path/secure mismatch
- proxy not forwarding cookies correctly
- frontend/browser request path bypassing same-origin `/api/*`
- backend session store outage or Redis connectivity problem
- host-derived tenant mismatch because the wrong host is being used

**Investigation steps:**

1. Confirm browser requests go to the frontend origin and use `/api/*`
2. Confirm proxy/SSR forwarding preserves `Host`, `Cookie`, and `X-Forwarded-*`
3. Check backend logs for session creation/lookup failures
4. Check Redis connectivity via `/health`
5. Reproduce using the exact tenant host that triggered the issue

**Do not do this during incident response:**

- do not hot-patch the app into direct browser-to-backend mode
- do not bypass host-derived tenant behavior with ad hoc overrides

---

## Outbox / Email Delivery

### Symptom: emails are not being delivered

This section covers invite, verify-email, reset-password, and other outbox-backed SMTP mail.

#### Quick triage

1. Confirm the triggering action actually enqueued an outbox message
2. Confirm the outbox poller is running
3. Confirm SMTP credentials/config are correct for the current environment
4. Inspect provider response classification in backend logs
5. Confirm whether the failure is retryable or permanent

#### Key local vs staging expectations

- **Local:** SMTP should point at Mailpit
- **Staging:** SMTP should point at a sandbox provider, not a real production mailbox provider
- **Production:** out of scope for this phase and should follow a separate controlled rollout

---

## Phase 2 email delivery proof procedures

These procedures are the operational source of truth for the email-delivery proof added in Phase 2.

### A. Local email capture proof

#### Goal

Prove that email-dependent auth flows send through real SMTP locally and arrive in a local capture inbox, with correct tenant-based links.

#### Local provider choice

Use **Mailpit** as the local SMTP sink and message viewer.

#### Required local config

Backend should be configured with values equivalent to:

```env
EMAIL_PROVIDER=smtp
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_SECURE=false
SMTP_FROM=Hubins <noreply@hubins.local>
SMTP_PUBLIC_BASE_URL=http://{tenantKey}.localhost:3000
```

#### Start local infra

Infra-only mode:

```bash
docker compose -f infra/docker-compose-infra.yml up -d
```

Full stack mode:

```bash
docker compose -f infra/docker-compose.yml up -d --build
```

#### Mailpit ports

- SMTP: `1025`
- UI/API: `8025`

Open Mailpit UI:

- `http://localhost:8025`

#### Local proof checklist

##### Proof 1 — Invite email

1. Start infra and app(s)
2. Ensure dev seed ran or run the explicit dev-seed entry point
3. Open Mailpit UI
4. Confirm invite email arrival for the seeded admin recipient
5. Open the message and copy/inspect the invite link
6. Verify the host uses the tenant-aware pattern, for example `goodwill-ca.localhost:3000`

##### Proof 2 — Verify-email email

1. Trigger a verification mail from the implemented flow
2. Confirm the email appears in Mailpit
3. Open the message and inspect the verification link
4. Verify tenant host correctness

##### Proof 3 — Password-reset email

1. Trigger forgot-password for a valid local account
2. Confirm reset mail arrival in Mailpit
3. Open the message and inspect the reset link
4. Verify tenant host correctness

#### What counts as a pass

All of the following must be true:

- real SMTP send path used
- message arrives in Mailpit
- intended template/body is present
- tokenized link exists
- link is constructed with the correct tenant-based host pattern

#### If local proof fails

Check, in order:

1. Mailpit container/process health
2. backend SMTP env values
3. outbox poller status
4. outbox table state / pending attempts
5. backend SMTP logs and provider error classification
6. tenant/public-base-url configuration

---

### B. Staging sandbox delivery proof

#### Goal

Prove that staging sends through a real sandbox SMTP provider, mail lands in a sandbox inbox, and provider failure behavior maps correctly to backend SMTP classification.

#### Staging provider choice

Use **Mailtrap Email Sandbox** for staging proof.

Rationale:

- sandboxed and non-production by design
- supports real SMTP credentials
- safe for staging proof of arrival
- practical for validating provider responses without delivering to real user inboxes

#### Credential handling rule

Do **not** commit staging SMTP credentials.

Store them in the staging secret manager / deployment-secret mechanism already used for environment variables.

At minimum, staging must provide:

```env
EMAIL_PROVIDER=smtp
SMTP_HOST=<mailtrap-host>
SMTP_PORT=<mailtrap-port>
SMTP_SECURE=<provider-specific>
SMTP_USER=<mailtrap-username>
SMTP_PASS=<mailtrap-password>
SMTP_FROM=<approved-sandbox-from>
SMTP_PUBLIC_BASE_URL=https://{tenantKey}.<staging-frontend-domain>
```

#### Staging proof checklist

##### Proof 1 — Invite email

1. Deploy backend with sandbox SMTP credentials
2. Trigger an invite in staging
3. Confirm the message appears in the Mailtrap sandbox inbox
4. Open the message and inspect the invite link
5. Confirm tenant-aware host construction for the staging frontend domain

##### Proof 2 — Verify-email email

1. Trigger verify-email in staging
2. Confirm the message appears in the Mailtrap sandbox inbox
3. Inspect the link
4. Confirm tenant-aware host construction

#### Provider permanent-failure classification validation

The backend SMTP adapter already distinguishes retryable vs permanent provider failures.
This phase requires validating that classification against a real provider response.

##### Safe validation approach

Use one controlled failing configuration or request that produces a provider-side permanent SMTP failure in staging sandbox conditions.

Examples:

- intentionally invalid sandbox SMTP credentials
- intentionally invalid authenticated sender configuration if the provider rejects it with a permanent response
- another sandbox-safe provider action that yields a clear 5xx permanent response

##### Validation goal

Confirm all of the following:

- backend records/logs the provider failure
- backend classifies permanent failure as non-retryable/dead-letter behavior according to current implementation
- backend does **not** loop indefinitely retrying a clearly permanent provider rejection

#### If staging proof fails

Check, in order:

1. staging secrets injected correctly
2. network egress from staging to provider SMTP host/port
3. provider sandbox credentials and inbox selection
4. sender/from restrictions enforced by the provider
5. backend SMTP classification logs
6. staging `SMTP_PUBLIC_BASE_URL`

---

## SMTP classification investigation guide

### Symptom: mail stays pending/retries forever

**Possible causes:**

- provider/network failure is being treated as retryable
- provider is timing out or intermittently unavailable
- a supposed permanent rejection is actually being surfaced as a transient/network error

**Steps:**

1. inspect backend logs for SMTP adapter error details
2. inspect provider response code/message if available
3. confirm whether the adapter classified it as retryable or permanent
4. compare with the intended provider behavior
5. if classification is wrong, open a targeted bug with the exact provider response and current classification outcome

### Symptom: mail goes directly to permanent failure

**Possible causes:**

- bad credentials
- sender/from rejection
- malformed recipient/address rejected by provider
- provider sandbox restriction violation

**Steps:**

1. confirm credentials and sender identity
2. inspect the exact provider response
3. verify the current backend classification is expected
4. correct configuration before replaying

---

## Data Reset / Recovery

### Symptom: local environment is too inconsistent to trust

Use a full local reset.

#### Infra-only reset

```bash
docker compose -f infra/docker-compose-infra.yml down -v
docker compose -f infra/docker-compose-infra.yml up -d
```

Then rerun backend/frontend and reseed.

#### Full-stack reset

```bash
docker compose -f infra/docker-compose.yml down -v
docker compose -f infra/docker-compose.yml up -d --build
```

After reset, verify:

- `/health`
- Mailpit UI
- seeded invite email

---

## Logging guidance during incidents

When investigating auth/email incidents, prioritize logs that answer these questions:

1. Did the request reach the backend through the expected topology path?
2. Which tenant/host was derived?
3. Was an outbox message created?
4. Did the poller attempt delivery?
5. What exact SMTP/provider response came back?
6. How was the failure classified?

If logs do not make those questions answerable, capture that gap and improve observability after the incident.

---

## Escalation guidance

Escalate when:

- dependency health cannot be restored quickly
- tenant identity is being derived incorrectly and risks cross-tenant behavior
- SMTP classification appears wrong for a real provider response
- staging sandbox proof cannot be completed due to networking or secret-management blockers
- the system can only be made to work by violating the locked topology

---

## Change discipline reminder

Operational pressure is not permission to rewrite architecture.

During incidents or proof work:

- do not bypass same-origin browser routing
- do not move tenant truth into the frontend
- do not replace host-derived tenant identity with manual toggles
- do not swap sandbox/local delivery for production delivery shortcuts

Repair within the locked system model.
