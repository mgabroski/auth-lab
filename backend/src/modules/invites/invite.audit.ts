/**
 * backend/src/modules/invites/invite.audit.ts
 *
 * WHY:
 * - Typed audit helpers for the Invites module.
 * - Keeps audit metadata consistent and typo-free per domain action.
 * - Module owns its own shapes; shared AuditWriter stays generic.
 *
 * RULES:
 * - Each function maps one domain action to one audit write.
 * - No DB access (delegates to AuditWriter).
 * - No business rules (call these AFTER the action succeeds).
 * - Never include raw tokens in metadata.
 * - File is exactly invite.audit.ts — never invites.audit.ts, never under /admin/.
 *
 * BRICK 12 UPDATE:
 * - Activated auditInviteCreated, auditInviteCancelled, auditInviteResent.
 */

import type { AuditWriter } from '../../shared/audit/audit.writer';
import type { Invite } from './invite.types';

export function auditInviteAccepted(writer: AuditWriter, invite: Invite): Promise<void> {
  return writer.append('invite.accepted', {
    inviteId: invite.id,
    email: invite.email,
    role: invite.role,
  });
}

export function auditInviteCreated(
  writer: AuditWriter,
  invite: { id: string; email: string; role: string; createdByUserId: string },
): Promise<void> {
  return writer.append('invite.created', {
    inviteId: invite.id,
    email: invite.email,
    role: invite.role,
    createdByUserId: invite.createdByUserId,
  });
}

export function auditInviteCancelled(
  writer: AuditWriter,
  invite: { id: string; email: string; role: string },
): Promise<void> {
  return writer.append('invite.cancelled', {
    inviteId: invite.id,
    email: invite.email,
    role: invite.role,
  });
}

export function auditInviteResent(
  writer: AuditWriter,
  data: { oldInviteId: string; newInviteId: string; email: string; role: string },
): Promise<void> {
  return writer.append('invite.resent', {
    oldInviteId: data.oldInviteId,
    newInviteId: data.newInviteId,
    email: data.email,
    role: data.role,
  });
}
