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

// Future helpers (add as use cases grow):
//
// export function auditInviteCreated(writer: AuditWriter, invite: Invite): Promise<void> {
//   return writer.append('invite.created', {
//     inviteId: invite.id,
//     email: invite.email,
//     role: invite.role,
//   });
// }
//
// export function auditInviteCancelled(writer: AuditWriter, invite: Invite): Promise<void> {
//   return writer.append('invite.cancelled', {
//     inviteId: invite.id,
//     email: invite.email,
//   });
// }
