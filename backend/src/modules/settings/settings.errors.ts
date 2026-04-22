/**
 * backend/src/modules/settings/settings.errors.ts
 *
 * WHY:
 * - Module-scoped semantic error factories for the Settings module.
 * - Keeps shared AppError clean of Settings-specific conflict semantics.
 */

import { AppError } from '../../shared/http/errors';

function accountCardLabel(cardKey: 'branding' | 'orgStructure' | 'calendar'): string {
  switch (cardKey) {
    case 'branding':
      return 'Branding';
    case 'orgStructure':
      return 'Organization Structure';
    case 'calendar':
      return 'Company Calendar';
    default: {
      const exhaustiveCheck: never = cardKey;
      return exhaustiveCheck;
    }
  }
}

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

  accountSectionUnavailable() {
    return AppError.notFound('Account Settings is not available for this workspace.');
  },

  accountCardUnavailable(cardKey: 'branding' | 'orgStructure' | 'calendar') {
    return AppError.notFound(`${accountCardLabel(cardKey)} is not available for this workspace.`);
  },

  accountCardVersionConflict(cardKey: 'branding' | 'orgStructure' | 'calendar') {
    return AppError.conflict(
      `${accountCardLabel(cardKey)} changed while you were editing it. Refresh the page and try again.`,
    );
  },

  accountCardCpRevisionConflict(cardKey: 'branding' | 'orgStructure' | 'calendar') {
    return AppError.conflict(
      `${accountCardLabel(cardKey)} changed after this page was loaded. Refresh and review the latest allowed fields before saving.`,
    );
  },

  personalModuleUnavailable() {
    return AppError.notFound('Personal settings is not available for this workspace.');
  },
} as const;
