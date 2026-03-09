# Auth / User Provisioning — Configuration Guide

`docs/modules/auth-user-provisioning.md`

This document explains the tenant-level configuration options that control Auth / User Provisioning behavior. It is written for product managers, QA engineers, and other stakeholders who need to understand Auth / User Provisioning behavior without reading code.

---

## What this module controls

This module is responsible for how users get into the platform, how they authenticate, and how their access is managed. Every user-facing action related to identity — signing up, logging in, resetting a password, verifying an email, setting up MFA, using SSO — is governed by this module.

The settings described in this document control which of those actions are available, for which tenants, and under what conditions.

---

## How configuration works

Every tenant (workspace) has its own settings. One tenant can allow public signup while another requires invites only. One can use Google SSO while another uses passwords only.

Settings are stored per tenant and are intended to be applied without redeploy.

Some features also require platform-level credentials to be configured (for example, Google SSO requires a Google client ID and secret in the server environment). Those are noted where relevant.

---

## The flags

---

### Public signup

**What it does:** Controls whether anyone can create an account at the tenant's URL without being invited first.

| Setting         | What happens                                                                          |
| --------------- | ------------------------------------------------------------------------------------- |
| Off _(default)_ | The signup page is not available. Users must receive an invite from an admin to join. |
| On              | Any user can visit the tenant URL and register an account directly.                   |

**Things to know:**

- When public signup is off, admins are the only way to bring new users in.
- When public signup is on, you can optionally restrict which email domains are allowed (see [Allowed email domains](#allowed-email-domains)).
- Password-based public signups require email verification by default. SSO-based signups do not — the SSO provider acts as the verification.

**What users see when it's off:** "Sign-up is disabled for this workspace. You need an invitation to join."

---

### Admin invites

**What it does:** Controls whether tenant admins can invite new users by email through the admin panel.

| Setting        | What happens                                                 |
| -------------- | ------------------------------------------------------------ |
| On _(default)_ | Admins can send invite emails, resend them, and cancel them. |
| Off            | The invite creation controls are disabled for this tenant.   |

**Things to know:**

- Turning this off does not cancel invites that have already been sent. Users with a valid pending invite can still accept it.
- If both public signup and admin invites are off, users must be provisioned through another administrative or platform-controlled process.

---

### Password login

**What it does:** Controls whether users can sign in with an email address and password.

| Setting        | What happens                                                       |
| -------------- | ------------------------------------------------------------------ |
| On _(default)_ | The email + password login form is available.                      |
| Off            | Password login is blocked. Users must sign in via an SSO provider. |

**Things to know:**

- If you turn this off, make sure at least one SSO provider (Google or Microsoft) is turned on. At least one login method should remain available at all times.
- Users who previously used a password to sign in will not be able to until this is re-enabled.
- Password reset becomes unavailable automatically when password login is off.

**What users see when it's off:** "Please sign in using your SSO provider."

---

### Password reset

**What it does:** Controls whether users can request a "forgot my password" email.

| Setting        | What happens                                                                                       |
| -------------- | -------------------------------------------------------------------------------------------------- |
| On _(default)_ | Users can request a password reset email from the login page.                                      |
| Off            | No reset email is sent. The page still shows "Check your email" — this is intentional (see below). |

**Things to know:**

- The forgot-password page always shows the same confirmation message regardless of whether the email exists in the system or whether this flag is on or off. This is a deliberate security decision — it prevents anyone from discovering which email addresses have accounts.
- Users who sign in only via Google or Microsoft cannot reset a password — they don't have one. The system silently skips them regardless of this setting.
- This flag has no effect when password login is off.

---

### Email verification

**What it does:** Controls whether users who sign up with a password must verify their email address before they can access the workspace.

| Setting        | What happens                                                                                                      |
| -------------- | ----------------------------------------------------------------------------------------------------------------- |
| On _(default)_ | After signing up, users receive a verification email. They cannot access the workspace until they click the link. |
| Off            | Signup immediately grants access. No verification email is sent.                                                  |

**Things to know:**

- Email verification only applies to password-based public signup. Invited users and SSO users are not asked to verify — the invite or the SSO provider is already a sufficient signal of identity.
- If your email delivery is delayed or unreliable, make sure resend verification is also on so users are not stuck.

---

### Resend verification email

**What it does:** Controls whether users who haven't yet verified their email can request another verification email.

| Setting        | What happens                                                           |
| -------------- | ---------------------------------------------------------------------- |
| On _(default)_ | A "resend verification email" option is available to unverified users. |
| Off            | Users cannot request another verification email.                       |

**Things to know:**

- Only relevant when email verification is on.
- Resend requests are rate-limited (a user can only request a few per hour) regardless of this setting. This protects against abuse.

---

### Google SSO

**What it does:** Controls whether users can sign in with a Google account.

| Setting         | What happens                                            |
| --------------- | ------------------------------------------------------- |
| Off _(default)_ | No Google sign-in button is shown.                      |
| On              | Users can sign in with their Google account via OAuth2. |

**Things to know:**

- Requires Google OAuth credentials to be set up at the platform level. If those credentials are not configured, turning this on has no visible effect.
- Users who sign in via Google are not asked to set a password and are not subject to password reset.
- If Google SSO is later turned off, users who only have a Google login will not be able to sign in until it is re-enabled or they set a password via an admin-initiated flow.

---

### Microsoft SSO

**What it does:** Controls whether users can sign in with a Microsoft (Office 365 / Azure AD) account.

| Setting         | What happens                                               |
| --------------- | ---------------------------------------------------------- |
| Off _(default)_ | No Microsoft sign-in button is shown.                      |
| On              | Users can sign in with their Microsoft account via OAuth2. |

**Things to know:**

- Requires Microsoft OAuth credentials to be set up at the platform level.
- Behaves identically to Google SSO in all other respects.

---

### MFA (multi-factor authentication)

**What it does:** Controls whether TOTP-based MFA (Google Authenticator, Authy, etc.) is available for users in this tenant.

| Setting        | What happens                                                                                                                     |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| On _(default)_ | MFA setup and verification are available. Admins are required to complete MFA on every login. Members follow the tenant setting. |
| Off            | MFA is not required or available for members.                                                                                    |

**Things to know:**

- **Admin MFA is always required.** This cannot be turned off by tenant configuration. An admin who has not set up MFA will be prompted to do so before they can access the workspace. This is a platform-wide security guarantee.
- Turning this off disables MFA for members only.
- When MFA is off, the MFA recovery option below has no effect.

---

### MFA recovery codes

**What it does:** Controls whether users are given one-time recovery codes during MFA setup, which they can use if they lose access to their authenticator device.

| Setting        | What happens                                                                                                   |
| -------------- | -------------------------------------------------------------------------------------------------------------- |
| On _(default)_ | Recovery codes are generated at MFA setup time and can be used as a fallback login method.                     |
| Off            | No recovery codes are issued. Users who lose their device cannot self-recover and must contact an admin or IT. |

**Things to know:**

- Users who already have recovery codes from a previous setup will retain them even if this setting is turned off. Turning this off only affects new MFA setups going forward.
- Only relevant when MFA is on.

---

### Allowed email domains

**What it does:** Restricts which email addresses are permitted to join the tenant, based on their domain.

| Setting                                   | What happens                                                                  |
| ----------------------------------------- | ----------------------------------------------------------------------------- |
| Empty _(default)_                         | No domain restriction. Any email can be invited or sign up.                   |
| One or more domains set (e.g. `acme.com`) | Only email addresses from those domains are accepted. All others are blocked. |

**Things to know:**

- This restriction applies at every entry point: public signup, admin invite creation, invite acceptance, and SSO login.
- Domain matching is exact and case-insensitive. Setting `acme.com` permits `user@acme.com` but not `user@mail.acme.com`.
- A user who was previously a member and then changes their email to a non-permitted domain is not automatically removed. This restriction only applies at the point of joining.

**What users see when blocked:** "Your email domain is not permitted for this workspace. Contact your admin."

---

## How flags interact

A few combinations are worth knowing before you configure a tenant.

**If you turn off password login:**
Password reset becomes unavailable automatically. At least one SSO provider must be on. Check that your users have SSO identities set up before making this change.

**If you turn on public signup:**
Email verification should also be on unless you have a separate reason to trust unverified emails. Without verification, anyone can claim any email address.

**If you turn off MFA:**
This only affects members. Admin MFA remains mandatory and cannot be disabled.

**If you set allowed email domains:**
This applies to every entry point. Test with a realistic email address before rolling out to avoid locking out users unexpectedly.

---

## Common tenant setups

### Invite-only with passwords

Users must be invited by an admin. They sign in with email and password. Admins require MFA.

```
Public signup:          Off
Admin invites:          On
Password login:         On
Password reset:         On
Email verification:     Off   (invite is sufficient verification)
Google SSO:             Off
Microsoft SSO:          Off
MFA:                    On
MFA recovery:           On
Allowed domains:        acme.com
```

---

### SSO-only (no passwords)

Users must be invited. They sign in with Google only. No passwords are managed by the platform.

```
Public signup:          Off
Admin invites:          On
Password login:         Off
Password reset:         Off   (automatic — no passwords)
Email verification:     Off
Google SSO:             On
Microsoft SSO:          Off
MFA:                    On
MFA recovery:           On
Allowed domains:        acme.com
```

---

### Open community signup

Anyone can register. Email is verified to prevent throwaway accounts.

```
Public signup:          On
Admin invites:          On
Password login:         On
Password reset:         On
Email verification:     On
Resend verification:    On
Google SSO:             On
Microsoft SSO:          Off
MFA:                    On
MFA recovery:           On
Allowed domains:        (none — open)
```

---

### Enterprise — Microsoft, no self-service

Large organisation. All users provisioned by HR import. Sign-in via Microsoft only. IT manages device recovery.

```
Public signup:          Off
Admin invites:          Off
Password login:         Off
Password reset:         Off
Email verification:     Off
Google SSO:             Off
Microsoft SSO:          On
MFA:                    On
MFA recovery:           Off   (IT manages recovery)
Allowed domains:        corp.acme.com
```

---

## What QA should check when a flag changes

**When turning public signup on:**

- Unauthenticated users can reach the signup page.
- Email verification prompt appears after registration (if verification is on).
- Users outside allowed domains are blocked at submission.
- Users inside allowed domains can complete registration.

**When turning public signup off:**

- Signup page returns the correct blocked message.
- Existing members are not affected.

**When turning an SSO provider on or off:**

- SSO button appears or disappears on the login page.
- Users who only have that SSO identity cannot sign in when the provider is off.
- Users with a fallback password identity can still sign in via password when SSO is off.

**When turning MFA off for members:**

- Members can complete login without being prompted for a code.
- Admins are still prompted for MFA — this must not change.

**When changing allowed email domains:**

- Invite creation with a non-permitted domain fails with the correct message.
- Public signup with a non-permitted domain fails with the correct message.
- SSO login from a non-permitted domain fails with the correct message.
- Users who were already members are not affected.

---

_End of auth-user-provisioning.md_
_Update this document when a flag is added, removed, or its behavior changes._
