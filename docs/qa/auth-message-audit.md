# Auth + Provisioning — User-Visible Message Audit

**Module:** Auth + User Provisioning  
**Status:** Complete for current shipped scope  
**Last updated:** 2026-04  
**Audit method:** Source inspection of `backend/src/modules/auth/auth.controller.ts`,
`backend/src/modules/auth/invite/invite.controller.ts`,
`backend/src/modules/auth/admin-invite/admin-invite.controller.ts`,
and the shared error handler / `AppError` factory.

This document records every user-visible message produced by the auth and provisioning
module. Its purpose is to confirm that production copy is intentional, consistently safe,
and free of information leaks.

---

## 1. Success Messages (2xx responses with a `message` field)

| Endpoint                         | HTTP status | Message text                                                                 | Intentional? | Notes                                                                                                           |
| -------------------------------- | ----------- | ---------------------------------------------------------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------- |
| `POST /auth/logout`              | 200         | `Logged out.`                                                                | ✅ Yes       | Clean, minimal, correct                                                                                         |
| `POST /auth/forgot-password`     | 200         | `If an account with that email exists, a password reset link has been sent.` | ✅ Yes       | **Deliberately vague.** Must never confirm or deny email existence. This phrasing is correct.                   |
| `POST /auth/reset-password`      | 200         | `Password updated successfully. Please sign in with your new password.`      | ✅ Yes       | Directs user to login after reset. Actionable.                                                                  |
| `POST /auth/resend-verification` | 200         | `If your email is unverified, a new verification link has been sent.`        | ✅ Yes       | **Deliberately vague.** Matches forgot-password pattern — no account-existence leak.                            |
| `POST /auth/workspace-setup-ack` | 200         | `{ status: 'ACKNOWLEDGED' }`                                                 | ✅ Yes       | Not user-facing copy — internal status field consumed by the frontend SSR call only.                            |
| `POST /auth/reset-password/validate` | 200     | `{ valid: true }`                                                            | ✅ Yes       | Not end-user copy. Internal validation result used by the reset-password page to decide whether to show the form. |

---

## 2. Error Messages (4xx / 5xx using `{ error: { code, message } }` shape)

The backend uses a centralized `AppError` factory. Error messages are mapped by the shared
error handler. The following tables record every user-visible error message by domain.

### 2.1 Authentication errors

| Code                            | Message                                                            | HTTP | Assessment | Notes                                                                            |
| ------------------------------- | ------------------------------------------------------------------ | ---- | ---------- | -------------------------------------------------------------------------------- |
| `AUTH_INVALID_CREDENTIALS`      | `Invalid credentials.`                                             | 401  | ✅ Correct | Generic — does not confirm which field is wrong. Correct behavior.               |
| `AUTH_SESSION_REQUIRED`         | `Authentication required.`                                         | 401  | ✅ Correct | Clear, actionable                                                                |
| `AUTH_FORBIDDEN`                | `You do not have permission to perform this action.`               | 403  | ✅ Correct | Generic — does not leak role or membership state                                 |
| `AUTH_TENANT_INACTIVE`          | `This workspace is not available.`                                 | 403  | ✅ Correct | Does not expose internal tenant state detail                                     |
| `AUTH_EMAIL_NOT_VERIFIED`       | `Email verification is required to continue.`                      | 403  | ✅ Correct | Clear continuation instruction                                                   |
| `AUTH_MFA_REQUIRED`             | `MFA verification is required to continue.`                        | 403  | ✅ Correct | Clear continuation instruction                                                   |
| `AUTH_MFA_INVALID_CODE`         | `Invalid or expired MFA code.`                                     | 401  | ✅ Correct | Does not distinguish invalid from expired — avoids timing information disclosure |
| `AUTH_MFA_ALREADY_VERIFIED`     | `MFA is already verified for this session.`                        | 400  | ✅ Correct | Clear, non-leaking                                                               |
| `AUTH_SSO_PROVIDER_NOT_ALLOWED` | `This sign-in method is not enabled for this workspace.`           | 403  | ✅ Correct | Does not expose which providers are allowed or what the tenant config is         |
| `AUTH_SSO_CALLBACK_INVALID`     | `SSO sign-in could not be completed. Please try again.`            | 400  | ✅ Correct | Generic — no token or state parameter leakage                                    |
| `AUTH_SSO_STATE_EXPIRED`        | `Your sign-in session expired. Please try again.`                  | 400  | ✅ Correct | Clear, actionable recovery                                                       |
| `AUTH_SSO_INVITE_EXPIRED`       | `Your invitation has expired. Please ask your admin to resend it.` | 403  | ✅ Correct | Communicates LOCK-4 recovery path explicitly to the user                         |

### 2.2 Invite errors

| Code                      | Message                                                                 | HTTP | Assessment | Notes                                                                                            |
| ------------------------- | ----------------------------------------------------------------------- | ---- | ---------- | ------------------------------------------------------------------------------------------------ |
| `INVITE_NOT_FOUND`        | `Invitation not found or already used.`                                 | 404  | ✅ Correct | Combines not-found and already-used — does not leak which state applies. Prevents state probing. |
| `INVITE_EXPIRED`          | `This invitation has expired. Please ask your admin to send a new one.` | 400  | ✅ Correct | Clear recovery path                                                                              |
| `INVITE_ALREADY_ACCEPTED` | `This invitation has already been accepted.`                            | 400  | ✅ Correct | Clear state communication                                                                        |
| `INVITE_TENANT_MISMATCH`  | `This invitation is not valid for this workspace.`                      | 400  | ✅ Correct | Does not expose tenant internal identifiers                                                      |

### 2.3 Password errors

| Code                       | Message                                                                        | HTTP | Assessment | Notes                                                                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------ | ---- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AUTH_PASSWORD_TOO_WEAK`   | `Password does not meet minimum requirements.`                                 | 400  | ✅ Correct | Generic — does not reveal exact rules, which prevents targeted password crafting                                                                  |
| `AUTH_RESET_TOKEN_INVALID` | `This password reset link is invalid or has expired. Please request a new one.` | 400  | ✅ Correct | Unified copy now used for invalid, expired, and already-used reset-link cases. Safer and simpler than exposing separate invalid vs expired states. |
| `AUTH_RESET_TOKEN_EXPIRED` | `This password reset link is invalid or has expired. Please request a new one.` | 400  | ✅ Correct | Intentionally aligned with `AUTH_RESET_TOKEN_INVALID` so the user sees one recovery path regardless of exact token state.                         |
| `AUTH_SSO_ONLY_ACCOUNT`    | `This account uses SSO sign-in. Password reset is not available.`              | 400  | ✅ Correct | Correct — there is no password to reset. Disclosure of SSO status is acceptable in this context because the user is the account holder.           |

### 2.4 Admin / provisioning errors

| Code                           | Message                                                       | HTTP | Assessment  | Notes                                                                                                                           |
| ------------------------------ | ------------------------------------------------------------- | ---- | ----------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `INVITE_LIMIT_EXCEEDED`        | `You have reached the maximum number of pending invitations.` | 400  | ✅ Correct  | Does not expose the exact numeric limit                                                                                         |
| `INVITE_EMAIL_ALREADY_MEMBER`  | `This email address is already a member of this workspace.`   | 409  | ✅ Accepted | Discloses that the email exists as a member. Acceptable: admin-only endpoint, authenticated actor with legitimate need to know. |
| `INVITE_EMAIL_ALREADY_PENDING` | `An invitation for this email is already pending.`            | 409  | ✅ Accepted | Same rationale as above — admin-only authenticated context.                                                                     |

### 2.5 Rate limit error

| Code                  | Message                                      | HTTP | Assessment | Notes                                     |
| --------------------- | -------------------------------------------- | ---- | ---------- | ----------------------------------------- |
| `RATE_LIMIT_EXCEEDED` | `Too many requests. Please try again later.` | 429  | ✅ Correct | No window length or numeric limit exposed |

### 2.6 Generic fallback

| Code             | Message                         | HTTP | Assessment | Notes                                                                                                                       |
| ---------------- | ------------------------------- | ---- | ---------- | --------------------------------------------------------------------------------------------------------------------------- |
| `INTERNAL_ERROR` | `An unexpected error occurred.` | 500  | ✅ Correct | Generic. Stack traces, file paths, and internal detail never appear in the response body. Verified by shared error handler. |

---

## 3. Password Reset Link Validation Surface

This flow was updated so reset-link validity is checked on page load before the password form
is rendered.

| Surface | Endpoint | User-visible error message | Expected UI behavior |
| ------- | -------- | -------------------------- | -------------------- |
| Reset-password page load prevalidation | `POST /auth/reset-password/validate` | `This password reset link is invalid or has expired. Please request a new one.` | Error shown immediately. Password form is hidden. |
| Reset-password submit fallback | `POST /auth/reset-password` | `This password reset link is invalid or has expired. Please request a new one.` | Same message remains the submit-time fallback if the token becomes invalid before submission. |

### Notes

- No new user-facing copy was introduced for reset-link invalidation.
- The change is in **when** the message appears:
  - before: only after the user clicked **Update password**
  - now: immediately when the user opens an already-used, expired, or invalid reset link
- This is the intended UX and matches the QA expectation for already-used reset links.

---

## 4. Audit Findings

| Finding                                                                                    | Severity                    | Status      | Rationale                                                                                                             |
| ------------------------------------------------------------------------------------------ | --------------------------- | ----------- | --------------------------------------------------------------------------------------------------------------------- |
| `forgot-password` returns 200 even for unknown emails                                      | Intentional                 | ✅ Closed   | Prevents email-existence probing. Correct behavior, not a bug.                                                        |
| `resend-verification` follows the same "if unverified…" vague pattern                      | Intentional                 | ✅ Closed   | Same rationale as forgot-password.                                                                                    |
| `AUTH_INVALID_CREDENTIALS` does not distinguish email-not-found from wrong-password        | Intentional                 | ✅ Closed   | Prevents username enumeration. Correct behavior.                                                                      |
| `INVITE_NOT_FOUND` combines not-found and already-used                                     | Intentional                 | ✅ Closed   | Prevents state probing. Consistent with reset-token pattern.                                                          |
| Password reset invalid/expired/already-used flows now use one unified recovery message     | Intentional                 | ✅ Closed   | Prevents unnecessary token-state disclosure and keeps the recovery path simple.                                       |
| Reset-link invalidation is now surfaced on page load, not only on submit                   | Intentional                 | ✅ Closed   | Better UX and matches QA expectations while preserving the same safe copy.                                            |
| No stack trace or internal path appears in any 4xx or 5xx response body                    | Verified by error handler   | ✅ Closed   | Confirmed by inspection of shared error handler mapping.                                                              |
| SSO callback errors do not reveal state parameter values or token content                  | Verified by code inspection | ✅ Closed   | Generic messages used throughout SSO error paths.                                                                     |
| `INVITE_EMAIL_ALREADY_MEMBER` and `INVITE_EMAIL_ALREADY_PENDING` disclose membership state | Accepted disclosure         | ✅ Accepted | Admin-only endpoint. Authenticated actor. Operationally necessary for invite management UX. No further action needed. |

**No P0 or P1 security findings identified in this audit.**

---

## 5. Copy Consistency Checks

The following conventions apply to all messages audited above:

| Convention                                                                                                        | Compliant? |
| ----------------------------------------------------------------------------------------------------------------- | ---------- |
| All user-facing error messages use sentence case                                                                  | ✅ Yes     |
| Recovery path instructions use actionable phrasing ("Please try again", "Please ask your admin to…")              | ✅ Yes     |
| No message reveals an internal identifier (tenant ID, user ID, token value, row ID)                               | ✅ Yes     |
| The generic fallback (`An unexpected error occurred.`) is the last resort and never replaced with internal detail | ✅ Yes     |
| Deliberately vague messages (forgot-password, resend-verification) use "If…" phrasing consistently                | ✅ Yes     |
| Reset-link validation and reset submission use the same invalid-link copy                                         | ✅ Yes     |

---

## 6. Out of Scope for This Audit

- **Frontend-only UI copy** — button labels, form placeholder text, heading copy, and validation messages rendered purely in the frontend are not covered here. A separate content review should cover those when the UI is stabilized.
- **Email template body copy** — invite email, verification email, and reset email body text lives in the outbox email renderer. A separate content review of email templates should happen before production sends real user email.
- **Admin audit log viewer messages** — these are operator-facing, not end-user-facing, and are intentionally more verbose than public-facing copy.