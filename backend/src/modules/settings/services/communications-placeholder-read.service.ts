/**
 * backend/src/modules/settings/services/communications-placeholder-read.service.ts
 *
 * WHY:
 * - Owns the v1 Communications placeholder page DTO.
 * - Keeps the placeholder route truthful without introducing tenant
 *   Communications configuration, template libraries, notification rules, or
 *   mutation surfaces before the locked v2 build.
 *
 * RULES:
 * - No DB access.
 * - No settings state transitions.
 * - No audit, version, cpRevision, or setup-completion semantics.
 */

import type { PlaceholderPageDto } from '../settings.types';

export class CommunicationsPlaceholderReadService {
  getCommunicationsPlaceholder(): PlaceholderPageDto {
    return {
      key: 'communications',
      title: 'Communications',
      status: 'PLACEHOLDER',
      treatment: 'PLACEHOLDER_ROUTE_ONLY',
      description:
        'Communications is intentionally placeholder-only in v1. There is no tenant configuration surface on this page.',
      liveConfigurationAvailable: false,
      mutationEndpointsAvailable: false,
      notes: [
        'Email templates are not configurable in v1.',
        'Notification rules are not configurable in v1.',
        'No setup action is required here for workspace completion.',
      ],
      backHref: '/admin/settings',
    };
  }
}
