/**
 * backend/src/modules/invites/invite.types.ts
 *
 * WHY:
 * - Domain types for the Invites module.
 * - Queries shape DB rows into these types (keeps DB shapes isolated).
 *
 * RULES:
 * - Keep aligned with DB schema (invites.used_at is the acceptance timestamp).
 * - Avoid leaking DB naming (snake_case) outside DAL/queries.
 * - InviteSummary is the safe API-facing DTO — tokenHash is always excluded.
 */

export type InviteStatus = 'PENDING' | 'ACCEPTED' | 'CANCELLED' | 'EXPIRED';

export type InviteRole = 'ADMIN' | 'MEMBER';

export type InviteId = string;

export type Invite = {
  id: InviteId;
  tenantId: string;

  email: string;
  role: InviteRole;
  status: InviteStatus;

  tokenHash: string;

  expiresAt: Date;
  usedAt: Date | null;

  createdAt: Date;
  createdByUserId: string | null;
};

/**
 * InviteSummary — safe DTO for all API responses.
 *
 * RULES:
 * - tokenHash is intentionally excluded — must never appear in any API response.
 * - Used by all admin invite endpoints: create, list, resend, cancel.
 */
export type InviteSummary = {
  id: InviteId;
  tenantId: string;

  email: string;
  role: InviteRole;
  status: InviteStatus;

  expiresAt: Date;
  usedAt: Date | null;

  createdAt: Date;
  createdByUserId: string | null;
};
