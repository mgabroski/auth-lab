# Hubins Auth-Lab — Operations Runbooks (Auth + Control Plane)

## Purpose

This document is the operator-facing runbook for the currently implemented Auth + User Provisioning and Control Plane foundations.

It is intentionally practical.
It is not a design essay.
It exists to answer:

- how to check whether the stack is healthy
- how to bootstrap and validate the current auth flows
- how to validate and recover the current Control Plane publish/status flows
- how to triage the most likely auth and CP failures
- how to rotate security-sensitive keys safely in the current repo
- what adversarial review must happen before major releases

This file is only about the repository's current, real surface.
If a flow is not implemented, this runbook does not pretend it exists.

---

## 1. System dependencies and health checks

## 1.1 Local full-stack health check

Before testing or debugging any auth issue locally, confirm the stack is actually healthy.

### Expected services

- frontend
- backend
- Postgres
- Redis
- Mailpit
- local proxy
- Control Plane frontend

### Commands
