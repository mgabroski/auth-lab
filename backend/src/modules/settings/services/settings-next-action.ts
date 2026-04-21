/**
 * backend/src/modules/settings/services/settings-next-action.ts
 *
 * WHY:
 * - Centralises the locked v1 next-action derivation used by bootstrap,
 *   overview, and mutation responses.
 * - Prevents duplicate drift between `/settings/bootstrap`, `/settings/overview`,
 *   and section write responses.
 */

import type { SettingsNextAction, SettingsSetupStatus } from '../settings.types';

export function deriveSettingsNextAction(params: {
  overallStatus: SettingsSetupStatus;
  accessStatus: SettingsSetupStatus;
  personalStatus: SettingsSetupStatus;
  personalRequired: boolean;
}): SettingsNextAction | null {
  if (params.overallStatus === 'COMPLETE') {
    return null;
  }

  if (params.accessStatus !== 'COMPLETE') {
    return {
      key: 'access',
      label: 'Review Access & Security',
      href: '/admin/settings/access',
    };
  }

  if (params.personalRequired && params.personalStatus !== 'COMPLETE') {
    return {
      key: 'modules',
      label:
        params.personalStatus === 'NEEDS_REVIEW'
          ? 'Review Personal settings'
          : 'Continue Personal setup',
      href: '/admin/settings/modules/personal',
    };
  }

  return null;
}
