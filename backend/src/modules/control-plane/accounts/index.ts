/**
 * backend/src/modules/control-plane/accounts/index.ts
 *
 * WHY:
 * - Public boundary for the Control Plane Accounts subdomain.
 * - Sibling modules must import from this file instead of deep-importing CP
 *   domain, catalog, or handoff internals.
 */

export {
  createCpSettingsHandoffReader,
  type CpSettingsHandoffReader,
} from './cp-settings-handoff.reader';
export type { CpSettingsHandoffSnapshot } from './handoff/cp-settings-handoff.types';
export {
  INTEGRATION_CATALOG,
  PERSONAL_FAMILY_DEFAULTS,
  PERSONAL_FAMILY_LABELS,
  PERSONAL_FIELD_CATALOG,
  type IntegrationCatalogEntry,
  type PersonalFamilyKey,
  type PersonalFieldCatalogEntry,
} from './cp-accounts.catalog';
