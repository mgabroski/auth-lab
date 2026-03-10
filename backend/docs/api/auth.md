<!--
WHY:
- Documents the auth HTTP contract used by the frontend bootstrap flow.
- Keeps /auth/me and /auth/config behavior explicit in the same PR as implementation.

RULES:
- Reflect the real backend contract only.
- Do not document secrets, internal DB fields, or hidden enforcement policy.
- Unknown and inactive workspaces share the same /auth/config response shape.
-->

# Auth API

---

## GET /auth/me

Returns the authenticated session bootstrap payload for the current tenant context.

### Auth

- Session required
- Any valid session is accepted regardless of `mfaVerified` or `emailVerified` state — this endpoint reports state, it does not gate on it
- Cross-tenant cookie mismatch returns `401`

### Request body

None

### 200 Response

```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "Jane Doe"
  },
  "membership": {
    "id": "uuid",
    "role": "ADMIN"
  },
  "tenant": {
    "id": "uuid",
    "key": "acme",
    "name": "Acme Corp"
  },
  "session": {
    "mfaVerified": false,
    "emailVerified": true
  },
  "nextAction": "MFA_REQUIRED"
}
```

### Response fields

| Field                   | Type                  | Description                                   |
| ----------------------- | --------------------- | --------------------------------------------- |
| `user.id`               | `string`              | Global user ID                                |
| `user.email`            | `string`              | Login email address                           |
| `user.name`             | `string \| null`      | Display name; null if not set                 |
| `membership.id`         | `string`              | Membership ID for the current tenant          |
| `membership.role`       | `"ADMIN" \| "MEMBER"` | Role within the current tenant                |
| `tenant.id`             | `string`              | Tenant ID from the session                    |
| `tenant.key`            | `string`              | Subdomain key                                 |
| `tenant.name`           | `string`              | Tenant display name                           |
| `session.mfaVerified`   | `boolean`             | Whether the current session has completed MFA |
| `session.emailVerified` | `boolean`             | Whether the user has a verified email         |
| `nextAction`            | `AuthNextAction`      | See nextAction values below                   |

### nextAction values

| Value                         | Meaning                                                                |
| ----------------------------- | ---------------------------------------------------------------------- |
| `NONE`                        | Session is fully resolved — user may access the app                    |
| `EMAIL_VERIFICATION_REQUIRED` | User must verify their email before proceeding                         |
| `MFA_SETUP_REQUIRED`          | Admin user must configure TOTP before proceeding                       |
| `MFA_REQUIRED`                | Admin user has MFA configured but this session has not verified it yet |

### 401 Response

Returned in either of these cases:

- No valid session cookie present
- Session cookie belongs to a different tenant subdomain than the current request

---

## GET /auth/config

Returns the public frontend bootstrap configuration for the tenant resolved from the request subdomain.

### Auth

None — public endpoint. No session required.

### Request body

None

### 200 Response

```json
{
  "tenant": {
    "name": "Acme Corp",
    "isActive": true,
    "publicSignupEnabled": false,
    "allowedSso": ["google", "microsoft"]
  }
}
```

### Unavailable response shape

Returned as `200` for all of the following cases:

- Unknown tenant key (subdomain not found)
- Inactive tenant
- Missing tenant key

```json
{
  "tenant": {
    "name": "",
    "isActive": false,
    "publicSignupEnabled": false,
    "allowedSso": []
  }
}
```

Both unknown and inactive tenants return the identical unavailable shape. This is intentional: distinguishing them would leak whether a subdomain is known to the system.

### Response fields

| Field                        | Type                          | Description                                            |
| ---------------------------- | ----------------------------- | ------------------------------------------------------ |
| `tenant.name`                | `string`                      | Tenant display name; empty string when unavailable     |
| `tenant.isActive`            | `boolean`                     | Whether the workspace is active and accepting requests |
| `tenant.publicSignupEnabled` | `boolean`                     | Whether self-service signup is enabled for this tenant |
| `tenant.allowedSso`          | `("google" \| "microsoft")[]` | SSO providers enabled for this tenant                  |

### Response notes

- Always returns `200` — never `404` or `500`
- `allowedSso` is always ordered: `google` before `microsoft`, regardless of storage order
- `allowedEmailDomains` is never returned — server-side enforcement only
- `memberMfaRequired` is never returned — internal enforcement policy
