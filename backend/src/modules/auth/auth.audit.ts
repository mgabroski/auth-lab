/**
 * backend/src/modules/auth/auth.audit.ts
 *
 * WHY:
 * - Typed audit helpers for the Auth module.
 * - Keeps audit metadata consistent per domain action.
 *
 * RULES:
 * - Each function maps one domain action to one audit write.
 * - No DB access (delegates to AuditWriter).
 * - No business rules.
 * - Never include passwords, hashes, or tokens in metadata.
 */

import type { AuditWriter } from '../../shared/audit/audit.writer';

export function auditRegisterSuccess(
  writer: AuditWriter,
  data: { userId: string; email: string; membershipId: string; role: string },
): Promise<void> {
  return writer.append('auth.register.success', {
    userId: data.userId,
    email: data.email,
    membershipId: data.membershipId,
    role: data.role,
  });
}

export function auditUserCreated(
  writer: AuditWriter,
  data: { userId: string; email: string },
): Promise<void> {
  return writer.append('user.created', {
    userId: data.userId,
    email: data.email,
  });
}

export function auditMembershipActivated(
  writer: AuditWriter,
  data: { membershipId: string; userId: string; role: string },
): Promise<void> {
  return writer.append('membership.activated', {
    membershipId: data.membershipId,
    userId: data.userId,
    role: data.role,
  });
}

export function auditMembershipCreated(
  writer: AuditWriter,
  data: { membershipId: string; userId: string; role: string },
): Promise<void> {
  return writer.append('membership.created', {
    membershipId: data.membershipId,
    userId: data.userId,
    role: data.role,
  });
}

export function auditLoginSuccess(
  writer: AuditWriter,
  data: { userId: string; email: string; membershipId: string; role: string },
): Promise<void> {
  return writer.append('auth.login.success', {
    userId: data.userId,
    email: data.email,
    membershipId: data.membershipId,
    role: data.role,
  });
}

export function auditLoginFailed(
  writer: AuditWriter,
  data: { email: string; reason: string },
): Promise<void> {
  return writer.append('auth.login.failed', {
    email: data.email,
    reason: data.reason,
  });
}
