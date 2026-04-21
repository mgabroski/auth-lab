/**
 * backend/src/modules/settings/settings.errors.ts
 *
 * WHY:
 * - Module-scoped semantic error factories for the Settings module.
 * - Keeps shared AppError clean of Settings-specific conflict and acknowledge semantics.
 */

import { AppError } from '../../shared/http/errors';

export const SettingsErrors = {
  accessSectionVersionConflict() {
    return AppError.conflict(
      'Access settings changed while you were reviewing them. Refresh the page and try again.',
    );
  },

  accessSectionCpRevisionConflict() {
    return AppError.conflict(
      'Access settings changed after this page was loaded. Refresh and review the latest platform-managed access rules before acknowledging.',
    );
  },

  accessSectionBlocked(blockers: string[]) {
    return AppError.conflict(
      'Access & Security cannot be acknowledged while platform-managed blockers remain unresolved.',
      { blockers },
    );
  },
} as const;
