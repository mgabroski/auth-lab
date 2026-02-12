/**
 * src/modules/auth/helpers/write-register-audits.ts
 *
 * WHY:
 * - register() conditionally writes 2–4 audit events depending on provision flags.
 * - This branching logic was inline in the service, mixing orchestration with
 *   audit decisions.
 * - Extracting puts all "which events fire on register" decisions in one place.
 *   When a new audit event is needed, this is the only file to touch.
 *
 * RULES:
 * - Delegates to the typed audit helpers in auth.audit.ts.
 * - No DB access directly.
 * - No business rules.
 */

import type { AuditWriter } from '../../../shared/audit/audit.writer';
import type { ProvisionResult } from '../../_shared/use-cases/provision-user-to-tenant.usecase';
import {
  auditUserCreated,
  auditMembershipActivated,
  auditMembershipCreated,
  auditRegisterSuccess,
} from '../auth.audit';

export async function writeRegisterAudits(
  audit: AuditWriter,
  result: ProvisionResult,
): Promise<void> {
  const { user, membership } = result;

  if (result.userCreated) {
    await auditUserCreated(audit, { userId: user.id, email: user.email });
  }

  if (result.membershipActivated) {
    await auditMembershipActivated(audit, {
      membershipId: membership.id,
      userId: user.id,
      role: membership.role,
    });
  }

  if (result.membershipCreated) {
    await auditMembershipCreated(audit, {
      membershipId: membership.id,
      userId: user.id,
      role: membership.role,
    });
  }

  await auditRegisterSuccess(audit, {
    userId: user.id,
    email: user.email,
    membershipId: membership.id,
    role: membership.role,
  });
}
