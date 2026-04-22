# Settings API

## Purpose

This document describes the currently shipped Settings-native backend read and write surface.

Current scope in this repo:

- `GET /settings/bootstrap`
- `GET /settings/overview`
- `GET /settings/access`
- `POST /settings/access/acknowledge`
- `GET /settings/account`
- `PUT /settings/account/branding`
- `PUT /settings/account/org-structure`
- `PUT /settings/account/calendar`
- `GET /settings/modules`
- `GET /settings/modules/personal`

This is the currently shipped Settings-native tenant surface used by the frontend `/admin`, `/admin/settings`, the dedicated `/admin/settings/access` page, the dedicated `/admin/settings/account` page, the real Modules hub at `/admin/settings/modules`, and the real Personal foundation page at `/admin/settings/modules/personal`.
It establishes the persisted Settings state engine, the real overview DTOs, the real Access acknowledge path, the real Account per-card save boundaries, and the Phase 6 Modules hub + Personal foundation reads.
It does **not** mean the full tenant Settings write surface is already shipped.

---

## Guard model

All endpoints in this document require a fully authenticated admin session.

Controller guard:

- `role = ADMIN`
- `requireMfa = true`
- `requireEmailVerified = true`

Unauthenticated or under-qualified requests fail through the normal auth guard path.

---

## GET `/settings/bootstrap`

### Purpose

Returns the bootstrap-safe Settings truth that `/admin` may consume.

This endpoint is intentionally minimal.
It is the Settings-native replacement foundation for using auth scaffolding as the long-term owner of setup semantics.

### Response
