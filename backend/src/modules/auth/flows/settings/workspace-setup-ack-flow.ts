/**
 * backend/src/modules/auth/flows/settings/workspace-setup-ack-flow.ts
 *
 * WHY:
 * - Implements the idempotent acknowledgement that marks a workspace as set up.
 * - Called by POST /auth/workspace-setup-ack which is triggered by the
 *   /admin/settings SSR page on load when config.tenant.setupCompleted is false.
 * - Once written, GET /auth/config returns setupCompleted: true for all admins
 *   in this workspace, and the setup banner disappears for everyone.
 *
 * RULES:
 * - Tenant-scoped: writes to tenants table, not memberships.
 *   Workspace setup state belongs to the workspace, not to individual users.
 * - Only ADMINs may call this endpoint (enforced in the controller via
 *   requireSession({ role: 'ADMIN', requireMfa: true, requireEmailVerified: true })).
 * - Idempotent: UPDATE WHERE setup_completed_at IS NULL is a no-op when
 *   already set. Calling this endpoint multiple times is safe.
 * - No audit event required — this is a UI-state write, not a security
 *   boundary action.
 * - No transaction needed — single-row UPDATE with no dependent state.
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { RequiredAuthContext } from '../../../../shared/http/require-auth-context';

export async function workspaceSetupAckFlow(
  auth: RequiredAuthContext,
  db: DbExecutor,
): Promise<{ status: 'ACKNOWLEDGED' }> {
  await db
    .updateTable('tenants')
    .set({ setup_completed_at: new Date() })
    .where('id', '=', auth.tenantId)
    .where('setup_completed_at', 'is', null)
    .execute();

  return { status: 'ACKNOWLEDGED' };
}
