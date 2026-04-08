import type { SetupGroupDefinition, SetupGroupSlug } from './contracts';

export const SETUP_GROUPS: SetupGroupDefinition[] = [
  {
    slug: 'access-identity-security',
    title: 'Access, Identity & Security',
    shortLabel: 'Access, Identity & Security',
    description:
      'Control Plane authorization, tenant identity boundaries, and security defaults are reviewed here.',
  },
  {
    slug: 'account-settings',
    title: 'Account Settings',
    shortLabel: 'Account Settings',
    description:
      'Account-level baseline configuration, naming, and operator-facing setup defaults live here.',
  },
  {
    slug: 'module-settings',
    title: 'Module Settings',
    shortLabel: 'Module Settings',
    description: 'Allowed modules and baseline enablement rules are reviewed here before publish.',
  },
  {
    slug: 'integrations-marketplace',
    title: 'Integrations & Marketplace',
    shortLabel: 'Integrations & Marketplace',
    description:
      'Integration readiness, marketplace visibility, and future dependency surfaces are reviewed here.',
  },
];

export const TOTAL_SETUP_GROUPS = SETUP_GROUPS.length;

export function getSetupGroupBySlug(slug: string): SetupGroupDefinition | null {
  return SETUP_GROUPS.find((group) => group.slug === slug) ?? null;
}

export function isSetupGroupSlug(value: string): value is SetupGroupSlug {
  return getSetupGroupBySlug(value) !== null;
}
