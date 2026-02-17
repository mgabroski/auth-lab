/**
 * src/shared/audit/audit.types.ts
 *
 * WHY:
 * - Central audit event types (compliance trail stored in DB).
 * - Keeps audit writes consistent across all modules.
 * - AuditContext groups the request-level fields that repeat on every event.
 * - AuditAction uses a union + escape hatch to catch typos early
 *   while still allowing new actions without touching this file.
 *
 * RULES:
 * - Keep types explicit and safe.
 * - Metadata is a plain object (repo serializes to JSON for DB).
 * - Add known actions to the union as modules grow.
 * - Never import module types here (shared must stay module-agnostic).
 */

// Known audit actions (add as modules grow)
export type KnownAuditAction =
  // Invites (Brick 6)
  | 'invite.accepted'
  | 'invite.created'
  | 'invite.cancelled'
  | 'invite.resent'
  // Auth (Brick 7)
  | 'auth.register.success'
  | 'auth.login.success'
  | 'auth.login.failed'
  // Auth — Password Reset (Brick 8)
  | 'auth.password_reset.requested'
  | 'auth.password_reset.completed'
  // Auth — MFA (Brick 9) (dots-only naming)
  | 'auth.mfa.setup.started'
  | 'auth.mfa.setup.completed'
  | 'auth.mfa.verify.succeeded'
  | 'auth.mfa.verify.failed'
  | 'auth.mfa.recovery.used'
  | 'auth.mfa.recovery.failed'
  // Users (Brick 7)
  | 'user.created'
  // Memberships (Brick 7)
  | 'membership.activated'
  | 'membership.created';

// Escape hatch: allows new actions without updating this file every time.
// Remove the escape hatch once all modules are stable.
export type AuditAction = KnownAuditAction | (string & {});

export type AuditMetadata = Record<string, unknown>;

/**
 * Request-level context that is identical across every audit event
 * within a single request. Built progressively as the service resolves
 * tenant → user → membership.
 *
 * All fields are nullable because context is built incrementally:
 * - Start of tx:       requestId, ip, userAgent
 * - After tenant:      + tenantId
 * - After auth (B7+):  + userId, membershipId
 */
export type AuditContext = {
  tenantId: string | null;
  userId: string | null;
  membershipId: string | null;

  requestId: string | null;
  ip: string | null;
  userAgent: string | null;
};

/**
 * Full audit event shape for DB insertion.
 * Used by AuditRepo only (low-level).
 */
export type AuditEventInsert = AuditContext & {
  action: AuditAction;
  metadata?: AuditMetadata;
};
