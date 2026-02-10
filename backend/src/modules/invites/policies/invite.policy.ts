/**
 * backend/src/modules/invites/policies/invite.policy.ts
 *
 * WHY:
 * - Centralizes invite acceptance safety rules.
 * - Pure logic (no DB / no I/O) => easy to unit test.
 *
 * RULES:
 * - Pure functions only.
 * - Throws module-level InviteErrors.
 * - Pass "now" for deterministic tests.
 */

import type { Invite } from '../invite.types';
import { InviteErrors } from '../invite.errors';

export function assertInviteExists(invite: Invite | undefined): asserts invite is Invite {
  if (!invite) throw InviteErrors.inviteNotFound();
}

export function assertInviteIsPending(invite: Invite): void {
  if (invite.status !== 'PENDING') {
    if (invite.status === 'ACCEPTED') {
      throw InviteErrors.inviteAlreadyAccepted({ inviteId: invite.id });
    }
    throw InviteErrors.inviteNotPending({ inviteId: invite.id, status: invite.status });
  }
}

export function assertInviteNotExpired(invite: Invite, now = new Date()): void {
  if (invite.expiresAt.getTime() <= now.getTime()) {
    throw InviteErrors.inviteExpired({ inviteId: invite.id });
  }
}

export function assertInviteBelongsToTenant(invite: Invite, tenantId: string): void {
  if (invite.tenantId !== tenantId) {
    throw InviteErrors.tenantMismatch({ inviteId: invite.id });
  }
}
