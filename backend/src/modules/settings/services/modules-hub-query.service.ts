/**
 * backend/src/modules/settings/services/modules-hub-query.service.ts
 *
 * WHY:
 * - Encodes the locked v1 Modules hub rule: the hub is navigation-only,
 *   Personal is the only live actionable entry, and future modules are
 *   placeholder-only when Control Plane allows them.
 */

import type { CpSettingsHandoffSnapshot } from '../../control-plane/accounts/handoff/cp-settings-handoff.types';
import type {
  ModulesHubModuleCardDto,
  SettingsModuleCardKey,
  SettingsSetupStatus,
} from '../settings.types';

export type ModulesHubReadModel = {
  personalEnabled: boolean;
  visibleModuleKeys: SettingsModuleCardKey[];
  cards: ModulesHubModuleCardDto[];
};

function livePersonalCta(status: SettingsSetupStatus): string {
  if (status === 'COMPLETE') {
    return 'Manage';
  }

  if (status === 'NEEDS_REVIEW') {
    return 'Review changes';
  }

  if (status === 'IN_PROGRESS') {
    return 'Continue setup';
  }

  return 'Set up';
}

export class ModulesHubQueryService {
  build(params: {
    personalStatus: SettingsSetupStatus;
    cpHandoff?: CpSettingsHandoffSnapshot;
  }): ModulesHubReadModel {
    const modules = params.cpHandoff?.allowances.modules.modules ?? {
      personal: true,
      documents: false,
      benefits: false,
      payments: false,
    };

    const cards: ModulesHubModuleCardDto[] = [];

    if (modules.personal) {
      cards.push({
        key: 'personal',
        title: 'Personal',
        description:
          'Configure the employee-facing Personal profile surface. Personal is the only live actionable module entry in v1.',
        classification: 'LIVE',
        href: '/admin/settings/modules/personal',
        status: params.personalStatus,
        warnings: [],
        ctaLabel: livePersonalCta(params.personalStatus),
      });
    }

    if (modules.documents) {
      cards.push({
        key: 'documents',
        title: 'Documents',
        description: 'Coming soon. Documents remains a non-interactive placeholder in v1.',
        classification: 'PLACEHOLDER',
        href: null,
        status: 'PLACEHOLDER',
        warnings: [],
        ctaLabel: null,
      });
    }

    if (modules.benefits) {
      cards.push({
        key: 'benefits',
        title: 'Benefits',
        description: 'Coming soon. Benefits remains a non-interactive placeholder in v1.',
        classification: 'PLACEHOLDER',
        href: null,
        status: 'PLACEHOLDER',
        warnings: [],
        ctaLabel: null,
      });
    }

    if (modules.payments) {
      cards.push({
        key: 'payments',
        title: 'Payments',
        description: 'Coming soon. Payments remains a non-interactive placeholder in v1.',
        classification: 'PLACEHOLDER',
        href: null,
        status: 'PLACEHOLDER',
        warnings: [],
        ctaLabel: null,
      });
    }

    return {
      personalEnabled: modules.personal,
      visibleModuleKeys: cards.map((card) => card.key),
      cards,
    };
  }
}
