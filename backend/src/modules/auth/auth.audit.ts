/**
 * src/modules/auth/auth.audit.ts
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
 *
 * PASSWORD RESET AUDIT PATTERN:
 * - auth.password_reset.requested is written on EVERY forgot-password request,
 *   including "user not found", "SSO only", and "rate limited" silent paths.
 *   This gives admins full visibility without leaking information to end users.
 * - The `outcome` field distinguishes cases: 'sent' | 'user_not_found' |
 *   'sso_only' | 'rate_limited'.
 * - auth.password_reset.completed is written only on successful reset.
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

/**
 * Written on every forgot-password request path, including silent (no-email) paths.
 * `outcome` distinguishes what actually happened for admin visibility.
 */
export function auditPasswordResetRequested(
  writer: AuditWriter,
  data: {
    outcome: 'sent' | 'user_not_found' | 'sso_only' | 'rate_limited';
  },
): Promise<void> {
  return writer.append('auth.password_reset.requested', {
    outcome: data.outcome,
  });
}

/**
 * Written only when the password is successfully changed.
 * Written outside any transaction (same pattern as auditLoginFailed) because
 * the service destroys all sessions after the DB write — we want the audit to
 * survive regardless.
 */
export function auditPasswordResetCompleted(
  writer: AuditWriter,
  data: { userId: string },
): Promise<void> {
  return writer.append('auth.password_reset.completed', {
    userId: data.userId,
  });
}
