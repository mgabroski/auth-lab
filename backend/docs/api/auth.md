# Auth API Contract

This document describes the **current backend Auth API contract** implemented in this repository.

It is a contract document, not a product brief.
That means:

- it describes what the backend actually exposes now
- it must stay aligned with `backend/src/modules/auth/*`
- it must not describe planned frontend flows as if they already exist

Read this after:

1. `README.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/decision-log.md`
5. `backend/docs/engineering-rules.md`

---

## 1. Scope

This file covers the Auth module endpoints registered in:

- `backend/src/modules/auth/auth.routes.ts`

Current route surface:

- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`
- `GET /auth/config`
- `POST /auth/forgot-password`
- `POST /auth/reset-password`
- `POST /auth/reset-password/validate`
- `POST /auth/mfa/setup`
- `POST /auth/mfa/verify-setup`
- `POST /auth/mfa/verify`
- `POST /auth/mfa/recover`
- `GET /auth/sso/:provider`
- `GET /auth/sso/:provider/callback`
- `POST /auth/signup`
- `POST /auth/verify-email`
- `POST /auth/resend-verification`
- `POST /auth/logout`

---

## 2. Topology assumptions

This contract is designed for the locked Hubins topology.

### Browser path

Browser code should call these endpoints through same-origin relative paths:

```text
/api/auth/*
```

Example:

```text
GET /api/auth/me
POST /api/auth/login
```

### SSR path

SSR/server-side frontend code may call the backend directly through `INTERNAL_API_URL`, but it must forward request identity headers correctly.

### Tenant routing

Tenant identity is derived from the request host/subdomain.
The caller does **not** provide tenant identity in the body.

### Session model

The backend uses server-side sessions and cookies.
The browser does not manage an auth token in local storage.

---

## 3. Auth result vocabulary

Several auth endpoints return the shared `AuthResult` shape.

### `AuthResult`

```ts
{
  status: 'AUTHENTICATED' | 'EMAIL_VERIFICATION_REQUIRED';
  nextAction: 'NONE' | 'MFA_SETUP_REQUIRED' | 'MFA_REQUIRED' | 'EMAIL_VERIFICATION_REQUIRED';
  user: {
    id: string;
    email: string;
    name: string | null;
  }
  membership: {
    id: string;
    role: 'ADMIN' | 'MEMBER';
  }
}
```

### `nextAction` meaning

- `NONE` — fully authenticated for current rules
- `MFA_SETUP_REQUIRED` — user must set up MFA before continuing
- `MFA_REQUIRED` — user must verify MFA before continuing
- `EMAIL_VERIFICATION_REQUIRED` — user must verify email before continuing

This is a load-bearing frontend contract.
The frontend bootstrap flow should use `nextAction` instead of re-deriving these decisions independently.

---

## 4. Bootstrap endpoints

These two endpoints are the key frontend bootstrap contract.

## 4.1 `GET /auth/me`

### Purpose

Returns the authenticated session-facing identity and current continuation state for the current tenant.

### Auth requirement

Requires a valid session cookie.
Without a valid session, returns `401`.

### Request body

None.

### Response shape

```ts
{
  user: {
    id: string;
    email: string;
    name: string | null;
  }
  membership: {
    id: string;
    role: 'ADMIN' | 'MEMBER';
  }
  tenant: {
    id: string;
    key: string;
    name: string;
  }
  session: {
    mfaVerified: boolean;
    emailVerified: boolean;
  }
  nextAction: 'NONE' | 'MFA_SETUP_REQUIRED' | 'MFA_REQUIRED' | 'EMAIL_VERIFICATION_REQUIRED';
}
```

### Guarantees

- session is already tenant-bound
- tenant mismatch does not authenticate the user
- response contains no raw secrets or tokens
- `nextAction` follows backend policy precedence

### Why it exists

This endpoint is intended for frontend auth/bootstrap decisions.
It should be the primary source of truth for:

- current authenticated user
- current tenant identity
- continuation requirement (`nextAction`)

---

## 4.2 `GET /auth/config`

### Purpose

Returns the public-safe tenant auth configuration used for unauthenticated/bootstrap UI.

### Auth requirement

Public endpoint.
No session is required.

### Request body

None.

### Response shape

```ts
{
  tenant: {
    name: string;
    isActive: boolean;
    publicSignupEnabled: boolean;
    signupAllowed: boolean;
    allowedSso: ('google' | 'microsoft')[];
    setupCompleted: boolean;
  };
}
```

### `signupAllowed` vs `publicSignupEnabled`

**Always use `signupAllowed` to gate signup UI — never `publicSignupEnabled` alone.**

`signupAllowed` is derived as: `publicSignupEnabled && !adminInviteRequired`.

A tenant can have `publicSignupEnabled: true` and still block public signup via `adminInviteRequired: true`. In that state, `signupAllowed` is `false` and the backend will reject any public signup attempt with `403`. If the frontend renders signup UI based on `publicSignupEnabled` alone, it will show a signup path that immediately fails.

`publicSignupEnabled` is preserved in the response for informational purposes (e.g., "signup would be available if admin invite was not required").

### Important anti-enumeration behavior

For an:

- unknown tenant
- or inactive tenant

this endpoint returns the same unavailable shape:

```ts
{
  tenant: {
    name: '';
    isActive: false;
    publicSignupEnabled: false;
    signupAllowed: false;
    allowedSso: [];
    setupCompleted: false;
  }
}
```

### Deliberately excluded fields

This endpoint must not expose tenant-sensitive settings such as:

- `allowedEmailDomains`
- `memberMfaRequired`
- `adminInviteRequired` (exposed only through the derived `signupAllowed`)
- other internal tenant policy details not needed for public bootstrap

### Current workspace-setup scaffold note

`setupCompleted` is part of the current shipped auth/bootstrap contract because the repo already ships:

- the admin dashboard workspace-setup banner
- the SSR-gated `/admin/settings` placeholder route
- the tenant-scoped `POST /auth/workspace-setup-ack` acknowledgement flow

This is honest current behavior, but it is **temporary scaffolding**, not the final Settings bootstrap ownership model.
The locked Settings implementation baseline moves Settings bootstrap semantics to a future `GET /settings/bootstrap` surface once the native Settings state engine exists.
Until that rollout bridge is implemented, `/auth/config` remains the current shipped source for the banner's `setupCompleted` input only.

### Why it exists

This endpoint is intended for frontend bootstrap before authentication, for example:

- whether signup should be shown (`signupAllowed`)
- which SSO providers should be shown (`allowedSso`)
- whether the tenant is effectively available (`isActive`)
- whether the current shipped admin banner scaffold should render (`setupCompleted`)

---

## 5. Session-establishing endpoints

These endpoints create or upgrade authenticated state and set the session cookie.

## 5.1 `POST /auth/register`

### Purpose

Accept an invite-based registration and create the first authenticated session for that user.

### Auth requirement

Public endpoint.
No session required.

### Request body

```ts
{
  email: string;
  password: string; // min 8
  name: string; // 1..200
  inviteToken: string; // min 20
}
```

### Success response

- status: `201`
- sets session cookie
- returns `AuthResult`

### Notes

- this is invite-driven registration, not public self-signup
- tenant context is derived from host/subdomain

---

## 5.2 `POST /auth/login`

### Purpose

Authenticate an existing user by password and establish a session.

### Auth requirement

Public endpoint.
No session required.

### Request body

```ts
{
  email: string;
  password: string;
}
```

### Success response

- status: `200`
- sets session cookie
- returns `AuthResult`

### Notes

The returned `nextAction` may require the frontend to continue into:

- email verification
- MFA setup
- MFA verification

The frontend should not assume login means "go directly to app shell."

---

## 5.3 `POST /auth/signup`

### Purpose

Self-service registration for tenants where public signup is enabled and not blocked by admin invite requirement.

### Auth requirement

Public endpoint.
No session required.

### Request body

```ts
{
  email: string;
  password: string; // min 8
  name: string; // 1..200
}
```

### Success response

- status: `201`
- sets session cookie
- returns `AuthResult`

### Notes

Signup may legitimately return:

- `status: 'EMAIL_VERIFICATION_REQUIRED'`
- `nextAction: 'EMAIL_VERIFICATION_REQUIRED'`

That is expected and should drive continuation UX.

The backend checks both `publicSignupEnabled` and `adminInviteRequired` before allowing signup.
Use `signupAllowed` from `GET /auth/config` to gate the signup UI on the frontend.

---

## 6. Password reset endpoints

## 6.1 `POST /auth/forgot-password`

### Purpose

Request a password reset email.

### Auth requirement

Public endpoint.
No session required.

### Request body

```ts
{
  email: string;
}
```

### Success response

Always returns `200` with:

```ts
{
  message: 'If an account with that email exists, a password reset link has been sent.';
}
```

### Why always 200

This is deliberate anti-enumeration behavior.
The endpoint does not reveal whether the email exists.

---

## 6.2 `POST /auth/reset-password`

### Purpose

Consume a password reset token and set a new password.

### Auth requirement

Public endpoint.
No session required.

### Request body

```ts
{
  token: string; // min 20
  newPassword: string; // min 8
}
```

### Success response

Returns `200` with:

```ts
{
  message: 'Password updated successfully. Please sign in with your new password.';
}
```

### Notes

This endpoint updates the password but does not automatically log the user in.

---

## 6.3 `POST /auth/reset-password/validate`

### Purpose

Validate a password reset token without consuming it.

### Auth requirement

Public endpoint.  
No session required.

### Request body

```ts
{
  token: string; // min 20
}
```

### Success response

Returns `200` with:

```ts
{
  valid: true;
}
```

## 7. Email verification endpoints

## 7.1 `POST /auth/verify-email`

### Purpose

Consume an email verification token and upgrade the existing authenticated session state so `emailVerified` becomes true.

### Auth requirement

Requires an authenticated session.

### Request body

```ts
{
  token: string; // min 20
}
```

### Success response

Returns `200` with the verification result.

Current backend intent:

- verification is performed against the authenticated user/session
- session state is upgraded server-side
- user should not need to log out and log back in after verifying email

### Important note

This endpoint is **not** gated by `requireEmailVerified`, because it is the email verification flow itself.

---

## 7.2 `POST /auth/resend-verification`

### Purpose

Request a new verification email for the authenticated user.

### Auth requirement

Requires an authenticated session.

### Request body

No body required.

### Success response

Always returns `200` with:

```ts
{
  message: 'If your email is unverified, a new verification link has been sent.';
}
```

### Why always 200

This avoids exposing detailed verification state or rate-limit details through the public response shape.

### Important note

This endpoint is **not** gated by `requireEmailVerified`, because it is part of the verification continuation flow.

---

## 8. MFA endpoints

### Session guard summary

All MFA endpoints require a valid authenticated session. The table below shows which additional guards are enforced:

| Endpoint                         | Session required | `emailVerified: true` required | `mfaVerified: true` required | Notes                                                                                                                 |
| -------------------------------- | ---------------- | ------------------------------ | ---------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `POST /auth/mfa/setup`           | ✅               | ✅                             | ❌                           | User must verify email before setting up MFA                                                                          |
| `POST /auth/mfa/verify-setup`    | ✅               | ✅                             | ❌                           | User must verify email before completing MFA setup                                                                    |
| `POST /auth/mfa/verify`          | ✅               | ✅                             | ❌                           | This IS the MFA completion step; mfaVerified is false on entry                                                        |
| `POST /auth/mfa/recover`         | ✅               | ✅                             | ❌                           | This IS the MFA recovery step; mfaVerified is false on entry                                                          |
| `POST /auth/logout`              | ✅               | ❌                             | ❌                           | Deliberately NOT gated — trapping unverified users from logging out creates a support burden with no security benefit |
| `POST /auth/verify-email`        | ✅               | ❌                             | ❌                           | Deliberately NOT gated — this IS the verification flow                                                                |
| `POST /auth/resend-verification` | ✅               | ❌                             | ❌                           | Deliberately NOT gated — part of the verification flow                                                                |

### Why `emailVerified` is required for all MFA endpoints

MFA setup and verification are post-signup operations that happen after a user has an authenticated session. If MFA endpoints were accessible without email verification, an attacker who obtained a session for an unverified email could configure MFA recovery codes that outlive any verification failure.

The deliberate gate order is: verify email first, then set up MFA. This is enforced in the controller via `requireSession({ requireEmailVerified: true })`.

---

## 8.1 `POST /auth/mfa/setup`

### Purpose

Start MFA setup for the authenticated user.

### Auth requirement

Requires authenticated session and `emailVerified: true`.

### Request body

None.

### Success response

Returns `200` with:

```ts
{
  secret: string;
  qrCodeUri: string;
  recoveryCodes: string[];
}
```

### Notes

This starts setup but does not yet mark MFA as fully configured/verified.

---

## 8.2 `POST /auth/mfa/verify-setup`

### Purpose

Verify the initial MFA setup code and elevate the current session into MFA-verified state.

### Auth requirement

Requires authenticated session and `emailVerified: true`.

### Request body

```ts
{
  code: string; // exactly 6 digits
}
```

### Success response

Returns `200` with:

```ts
{
  status: 'AUTHENTICATED';
  nextAction: 'NONE';
}
```

### Cookie behavior

The backend rotates the session ID on privilege elevation and sets a new session cookie.
This is a load-bearing security behavior.

---

## 8.3 `POST /auth/mfa/verify`

### Purpose

Verify MFA for a session that still requires MFA completion.

### Auth requirement

Requires authenticated session and `emailVerified: true`.

### Request body

```ts
{
  code: string; // exactly 6 digits
}
```

### Success response

Returns `200` with:

```ts
{
  status: 'AUTHENTICATED';
  nextAction: 'NONE';
}
```

### Cookie behavior

The backend rotates the session ID on privilege elevation and sets a new session cookie.

---

## 8.4 `POST /auth/mfa/recover`

### Purpose

Recover access using a recovery code and elevate the current session into MFA-verified state.

### Auth requirement

Requires authenticated session and `emailVerified: true`.

### Request body

```ts
{
  recoveryCode: string; // min 8, max 64
}
```

### Success response

Returns `200` with:

```ts
{
  status: 'AUTHENTICATED';
  nextAction: 'NONE';
}
```

### Cookie behavior

The backend rotates the session ID on privilege elevation and sets a new session cookie.

---

## 9. SSO endpoints

Supported providers are currently:

- `google`
- `microsoft`

## 9.1 `GET /auth/sso/:provider`

### Purpose

Start the SSO flow by generating the provider redirect URL and browser-bound state.

### Auth requirement

Public endpoint.
No session required.

### Route param

```ts
provider: 'google' | 'microsoft';
```

### Query params

Optional:

```ts
returnTo?: string
```

### `returnTo` safety rule

Only safe relative paths are accepted.
Unsafe values are silently dropped rather than failing the whole SSO attempt.

Accepted example:

- `/dashboard`

Rejected examples:

- `//evil.com`
- `https://evil.com`
- `javascript:...`

### Success behavior

- if `:provider` is enabled for the current tenant, sets short-lived `sso-state` cookie and responds with `302` redirect to the provider authorization URL
- if `:provider` is disabled by tenant policy, returns `403` and does **not** set the SSO state cookie or start the provider redirect

### Denied response example

```ts
{
  error: {
    code: 'FORBIDDEN';
    message: 'This sign-in method is not enabled for this workspace.';
  }
}
```

### Notes

The state cookie is part of CSRF protection and must survive the provider redirect callback flow.

---

## 9.2 `GET /auth/sso/:provider/callback`

### Purpose

Handle provider callback, validate state, create/login the user, establish a session, and redirect back into the app.

### Auth requirement

Public endpoint.
No pre-existing session required.

### Route param

```ts
provider: 'google' | 'microsoft';
```

### Required query params

```ts
code: string;
state: string;
```

### Validation behavior

The backend requires:

- callback `state` query param
- matching `sso-state` cookie value

Missing or mismatched cookie/state is a hard rejection.
This is deliberate CSRF protection.

### Success behavior

- sets authenticated session cookie
- clears `sso-state` cookie
- responds with `302` redirect to backend-chosen `redirectTo`

### Notes

The redirect target is derived from the validated encrypted SSO state, not from an arbitrary callback query override.

---

## 10. Logout endpoint

## `POST /auth/logout`

### Purpose

Destroy the current authenticated session and clear the session cookie.

### Auth requirement

Requires an authenticated session.

### Request body

None.

### Success response

Returns `200` with:

```ts
{
  message: 'Logged out.';
}
```

### Cookie behavior

The backend clears the session cookie immediately.

### Important note

This endpoint deliberately does **not** require `emailVerified: true`.
An unverified user must still be able to log out.

---

## 11. Error and privacy posture

## 11.1 Validation

Invalid request shapes are rejected through the backend validation/error model.
This includes:

- invalid bodies
- invalid route params
- missing required SSO callback query params

## 11.2 Authentication failures

Endpoints requiring a session return `401` when the session is missing or invalid.

## 11.3 Anti-enumeration behaviors

The following are intentionally privacy-preserving and should not be "simplified" casually:

- `GET /auth/config` returns the same unavailable shape for unknown and inactive tenants
- `POST /auth/forgot-password` always returns generic success
- `POST /auth/resend-verification` always returns generic success

These are contract decisions, not implementation accidents.

---

## 12. Frontend contract guidance

If you are building frontend auth/bootstrap behavior, these are the most important rules:

### Use `/auth/config` before authentication

Use it to determine:

- tenant availability
- whether signup is visible — use **`signupAllowed`**, not `publicSignupEnabled`
- which SSO buttons to show

### Use `/auth/me` after a session exists

Use it to determine:

- current user
- current tenant
- membership role
- session continuation state
- `nextAction`

### Trust `nextAction`

Do not duplicate backend continuation logic in the frontend.
Drive continuation UX from backend truth.

### Do not hardcode backend origins in browser code

Browser calls must stay same-origin through `/api/*`.

---

## 13. When to update this file

Update this file whenever:

- an auth endpoint is added, removed, or renamed
- request/response shapes change
- bootstrap contract behavior changes
- SSO callback/start behavior changes
- auth continuation semantics (`nextAction`) change
- privacy/anti-enumeration behavior changes

If the route surface changed and this file did not, this file is stale.
