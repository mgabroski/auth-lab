/**
 * backend/src/shared/settings/settings-foundation-bootstrap.ts
 *
 * WHY:
 * - Provides the shared tenant-bootstrap seed path with the minimum Settings
 *   foundation rows needed by the shipped tenant setup surfaces.
 * - Keeps shared seed code independent from backend/src/modules/* so the repo
 *   guard boundary remains real: shared infrastructure may not import feature
 *   modules.
 *
 * RULES:
 * - Seed/bootstrap helper only. Runtime Settings services still own normal
 *   Settings state transitions and section recomputation.
 * - Idempotent inserts only; callers may run this repeatedly during local/dev
 *   bootstrap without overwriting tenant setup progress.
 * - Keep the section keys and reason code aligned with the Settings module
 *   vocabulary. Do not add new runtime behavior here.
 */

import type { DbExecutor } from '../db/db';

export const SETTINGS_BOOTSTRAP_SECTION_KEYS = [
  'access',
  'account',
  'personal',
  'integrations',
] as const;

export const SETTINGS_TENANT_BOOTSTRAP_FOUNDATION_REASON = 'TENANT_BOOTSTRAP_FOUNDATION';

export async function ensureBootstrapSettingsFoundationRows(params: {
  db: DbExecutor;
  tenantId: string;
  appliedCpRevision: number;
  transitionAt?: Date;
}): Promise<void> {
  const transitionAt = params.transitionAt ?? new Date();

  await params.db
    .insertInto('tenant_setup_state')
    .values({
      tenant_id: params.tenantId,
      overall_status: 'NOT_STARTED',
      version: 1,
      applied_cp_revision: params.appliedCpRevision,
      last_transition_reason_code: SETTINGS_TENANT_BOOTSTRAP_FOUNDATION_REASON,
      last_transition_at: transitionAt,
    })
    .onConflict((oc) => oc.column('tenant_id').doNothing())
    .execute();

  await params.db
    .insertInto('tenant_setup_section_state')
    .values(
      SETTINGS_BOOTSTRAP_SECTION_KEYS.map((sectionKey) => ({
        tenant_id: params.tenantId,
        section_key: sectionKey,
        status: 'NOT_STARTED',
        version: 1,
        applied_cp_revision: params.appliedCpRevision,
        last_transition_reason_code: SETTINGS_TENANT_BOOTSTRAP_FOUNDATION_REASON,
        last_transition_at: transitionAt,
      })),
    )
    .onConflict((oc) => oc.columns(['tenant_id', 'section_key']).doNothing())
    .execute();
}
