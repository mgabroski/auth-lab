import type { SetupGroupDefinition, SetupGroupSlug } from './contracts';

export const SETUP_GROUPS: SetupGroupDefinition[] = [
  {
    slug: 'access-identity-security',
    title: 'Access, Identity & Security',
    shortLabel: 'Access, Identity & Security',
    description: 'Configure login methods, MFA policy, signup/invite policy, and allowed domains.',
    isRequired: true,
  },
  {
    slug: 'account-settings',
    title: 'Account Settings',
    shortLabel: 'Account Settings',
    description:
      'Choose which branding, organization structure, and company-calendar surfaces are allowed.',
    isRequired: true,
  },
  {
    slug: 'module-settings',
    title: 'Module Settings',
    shortLabel: 'Module Settings',
    description:
      'Decide which modules are allowed. Personal is the only live configurable sub-page in the current shipped surface.',
    isRequired: true,
  },
  {
    slug: 'integrations-marketplace',
    title: 'Integrations & Marketplace',
    shortLabel: 'Integrations & Marketplace',
    description:
      'Choose which integrations are allowed. Explicit save is enough even when no integrations are enabled.',
    isRequired: false,
  },
];

export const TOTAL_SETUP_GROUPS = SETUP_GROUPS.length;

export function getSetupGroupBySlug(slug: string): SetupGroupDefinition | null {
  return SETUP_GROUPS.find((group) => group.slug === slug) ?? null;
}

export function isSetupGroupSlug(value: string): value is SetupGroupSlug {
  return getSetupGroupBySlug(value) !== null;
}
