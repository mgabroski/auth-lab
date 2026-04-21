/**
 * backend/src/modules/auth/flows/settings/workspace-setup-ack-flow.ts
 *
 * WHY:
 * - Implements the current shipped auth-phase acknowledgement used by the
 *   admin banner scaffold.
 * - Bridges that legacy scaffold conservatively into the native Step 10 Phase 1
 *   Settings foundation rows so rollout can begin without creating a permanent
 *   second truth source.
 * - Keeps the user-visible auth contract unchanged while preparing the repo for
 *   the later Settings-native bootstrap/state-engine work.
 *
 * RULES:
 * - Tenant-scoped: writes to tenants table, not memberships.
 *   Workspace setup state belongs to the workspace, not to individual users.
 * - Only ADMINs may call this endpoint (enforced in the controller via
 *   requireSession({ role: 'ADMIN', requireMfa: true, requireEmailVerified: true })).
 * - Idempotent: repeated calls preserve the first acknowledgement timestamp and
 *   do not weaken stronger native Settings states.
 * - This flow remains rollout-bridge behavior only. It must never mark the
 *   aggregate Settings state COMPLETE from legacy acknowledgement alone.
 * - No dedicated settings audit is introduced here. This remains the legacy
 *   auth scaffold bridge, not the final Settings write surface.
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { RequiredAuthContext } from '../../../../shared/http/require-auth-context';
import { SettingsFoundationRepo } from '../../../settings/dal/settings-foundation.repo';
import { SETTINGS_REASON_CODES } from '../../../settings/settings.types';

export async function workspaceSetupAckFlow(
  auth: RequiredAuthContext,
  db: DbExecutor,
): Promise<{ status: 'ACKNOWLEDGED' }> {
  await db.transaction().execute(async (trx) => {
    const tenant = await trx
      .selectFrom('tenants')
      .select(['id', 'setup_completed_at'])
      .where('id', '=', auth.tenantId)
      .executeTakeFirstOrThrow();

    const acknowledgedAt = tenant.setup_completed_at ?? new Date();

    if (tenant.setup_completed_at === null) {
      await trx
        .updateTable('tenants')
        .set({ setup_completed_at: acknowledgedAt })
        .where('id', '=', auth.tenantId)
        .execute();
    }

    const settingsFoundationRepo = new SettingsFoundationRepo(trx);
    const appliedCpRevision = await settingsFoundationRepo.findCurrentCpRevisionForTenant(
      auth.tenantId,
    );

    await settingsFoundationRepo.ensureFoundationRows({
      tenantId: auth.tenantId,
      appliedCpRevision,
      creationReasonCode: SETTINGS_REASON_CODES.LEGACY_AUTH_ACK_BRIDGE,
      transitionAt: acknowledgedAt,
    });

    await settingsFoundationRepo.bridgeLegacyWorkspaceAck({
      tenantId: auth.tenantId,
      acknowledgedAt,
      appliedCpRevision,
      actorUserId: auth.userId,
    });
  });

  return { status: 'ACKNOWLEDGED' };
}
