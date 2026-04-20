/**
 * backend/src/modules/control-plane/accounts/cp-accounts.catalog.ts
 *
 * WHY:
 * - Owns the locked CP catalog and defaults for the four Step 2 setup groups.
 * - Provides one backend-authoritative source for Personal families/fields,
 *   integration keys, group labels, and default draft values.
 * - Keeps service validation and GET response composition aligned.
 *
 * RULES:
 * - This is catalog data only. No DB access. No AppError.
 * - CP allowance truth is persisted in CP tables; these defaults are used only
 *   when a group has not yet been explicitly saved.
 * - Product-locked invariants (System ID auto/system-managed, required baseline
 *   fields) are enforced from here.
 */

export type CpSetupGroupSlug =
  | 'access-identity-security'
  | 'account-settings'
  | 'module-settings'
  | 'integrations-marketplace';

export type PersonalFamilyKey =
  | 'identity'
  | 'contact'
  | 'address'
  | 'dependents'
  | 'emergency'
  | 'identifiers'
  | 'signature';

export type PersonalMinimumRequired = 'none' | 'required' | 'auto';

export type CpSetupGroupCatalogEntry = {
  slug: CpSetupGroupSlug;
  title: string;
  isRequired: boolean;
};

export type PersonalFieldCatalogEntry = {
  familyKey: PersonalFamilyKey;
  fieldKey: string;
  label: string;
  notes: string;
  defaultAllowed: boolean;
  defaultSelected: boolean;
  minimumRequired: PersonalMinimumRequired;
  isSystemManaged: boolean;
};

export type IntegrationCatalogEntry = {
  integrationKey: string;
  label: string;
  defaultAllowed: boolean;
  capabilities: Array<{
    capabilityKey: string;
    label: string;
    defaultAllowed: boolean;
  }>;
};

export const CP_SETUP_GROUPS: CpSetupGroupCatalogEntry[] = [
  {
    slug: 'access-identity-security',
    title: 'Access, Identity & Security',
    isRequired: true,
  },
  {
    slug: 'account-settings',
    title: 'Account Settings',
    isRequired: true,
  },
  {
    slug: 'module-settings',
    title: 'Module Settings',
    isRequired: true,
  },
  {
    slug: 'integrations-marketplace',
    title: 'Integrations & Marketplace',
    isRequired: false,
  },
] as const;

export const REQUIRED_SETUP_GROUP_SLUGS = CP_SETUP_GROUPS.filter((group) => group.isRequired).map(
  (group) => group.slug,
);

export const PERSONAL_FAMILY_LABELS: Record<PersonalFamilyKey, string> = {
  identity: 'Identity',
  contact: 'Contact',
  address: 'Address',
  dependents: 'Dependents',
  emergency: 'Emergency',
  identifiers: 'Identifiers',
  signature: 'Signature',
};

export const PERSONAL_FAMILY_DEFAULTS: Array<{
  familyKey: PersonalFamilyKey;
  label: string;
  defaultAllowed: boolean;
}> = [
  { familyKey: 'identity', label: 'Identity', defaultAllowed: true },
  { familyKey: 'contact', label: 'Contact', defaultAllowed: true },
  { familyKey: 'address', label: 'Address', defaultAllowed: true },
  { familyKey: 'dependents', label: 'Dependents', defaultAllowed: true },
  { familyKey: 'emergency', label: 'Emergency', defaultAllowed: true },
  { familyKey: 'identifiers', label: 'Identifiers', defaultAllowed: true },
  { familyKey: 'signature', label: 'Signature', defaultAllowed: true },
] as const;

export const PERSONAL_FIELD_CATALOG: PersonalFieldCatalogEntry[] = [
  {
    familyKey: 'identity',
    fieldKey: 'person.first_name',
    label: 'First Name',
    notes: 'Required baseline field.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'required',
    isSystemManaged: false,
  },
  {
    familyKey: 'identity',
    fieldKey: 'person.middle_name',
    label: 'Middle Name',
    notes: 'Optional identity field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'identity',
    fieldKey: 'person.last_name',
    label: 'Last Name',
    notes: 'Required baseline field.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'required',
    isSystemManaged: false,
  },
  {
    familyKey: 'identity',
    fieldKey: 'person.date_of_birth',
    label: 'Date of Birth',
    notes: 'Core baseline identity field.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'identity',
    fieldKey: 'person.gender',
    label: 'Gender',
    notes: 'Default selected in the locked CP matrix.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'identity',
    fieldKey: 'person.marital_status',
    label: 'Marital Status',
    notes: 'Default selected in the locked CP matrix.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'identity',
    fieldKey: 'person.ssn',
    label: 'SSN',
    notes: 'Sensitive field. Allowed by default; tenant may later deselect.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'identity',
    fieldKey: 'person.tobacco_user',
    label: 'Tobacco User',
    notes: 'Business-sensitive optional field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'contact',
    fieldKey: 'person.work_email',
    label: 'Work Email',
    notes: 'Required baseline field.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'required',
    isSystemManaged: false,
  },
  {
    familyKey: 'contact',
    fieldKey: 'person.personal_email',
    label: 'Personal Email',
    notes: 'Optional contact field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'contact',
    fieldKey: 'person.mobile_phone',
    label: 'Mobile Phone',
    notes: 'Core contact field.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'contact',
    fieldKey: 'person.work_phone',
    label: 'Work Phone',
    notes: 'Optional contact field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'address',
    fieldKey: 'person.home_street_address',
    label: 'Street Address',
    notes: 'Core home-address field.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'address',
    fieldKey: 'person.home_street_address_2',
    label: 'Address Line 2',
    notes: 'Default selected in the locked CP matrix.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'address',
    fieldKey: 'person.home_city',
    label: 'City',
    notes: 'Core home-address field.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'address',
    fieldKey: 'person.home_state',
    label: 'State',
    notes: 'Core home-address field.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'address',
    fieldKey: 'person.home_zip_code',
    label: 'ZIP Code',
    notes: 'Core home-address field.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'address',
    fieldKey: 'person.home_county',
    label: 'County',
    notes: 'Default selected in the locked CP matrix.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'address',
    fieldKey: 'person.mailing_address',
    label: 'Mailing Street Address',
    notes: 'Optional mailing-address field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'address',
    fieldKey: 'person.mailing_address_2',
    label: 'Mailing Address Line 2',
    notes: 'Optional mailing-address field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'address',
    fieldKey: 'person.mailing_city',
    label: 'Mailing City',
    notes: 'Optional mailing-address field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'address',
    fieldKey: 'person.mailing_state',
    label: 'Mailing State',
    notes: 'Optional mailing-address field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'address',
    fieldKey: 'person.mailing_zip_code',
    label: 'Mailing ZIP Code',
    notes: 'Optional mailing-address field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'address',
    fieldKey: 'person.mailing_county',
    label: 'Mailing County',
    notes: 'Optional mailing-address field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.first_name',
    label: 'First Name',
    notes: 'Core dependent field.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.middle_name',
    label: 'Middle Name',
    notes: 'Optional dependent field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.last_name',
    label: 'Last Name',
    notes: 'Core dependent field.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.relationship',
    label: 'Relationship',
    notes: 'Core dependent field.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.gender',
    label: 'Gender',
    notes: 'Default selected in the locked CP matrix.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.date_of_birth',
    label: 'Date of Birth',
    notes: 'Core dependent field.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.email',
    label: 'Email',
    notes: 'Optional dependent field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.phone',
    label: 'Phone',
    notes: 'Optional dependent field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.ssn',
    label: 'SSN',
    notes: 'Sensitive optional dependent field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.no_ssn',
    label: 'No SSN',
    notes: 'Companion field for dependent SSN.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.home_street_address',
    label: 'Street Address',
    notes: 'Optional dependent-address field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.home_street_address_2',
    label: 'Address Line 2',
    notes: 'Optional dependent-address field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.home_city',
    label: 'City',
    notes: 'Optional dependent-address field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.home_state',
    label: 'State',
    notes: 'Optional dependent-address field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.home_zip_code',
    label: 'ZIP Code',
    notes: 'Optional dependent-address field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.county',
    label: 'County',
    notes: 'Default selected in the locked CP matrix.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.address_flag',
    label: 'Different Address',
    notes: 'Boolean flag for dependent address sub-fields.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.disabled',
    label: 'Disabled',
    notes: 'Conditionally sensitive optional field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'dependents',
    fieldKey: 'dependent.tobacco_user',
    label: 'Tobacco User',
    notes: 'Business-sensitive optional field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'emergency',
    fieldKey: 'emergency_contact.name',
    label: 'Contact Name',
    notes: 'Allowed but not default selected.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'emergency',
    fieldKey: 'emergency_contact.relationship',
    label: 'Relationship',
    notes: 'Allowed but not default selected.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'emergency',
    fieldKey: 'emergency_contact.phone',
    label: 'Phone',
    notes: 'Allowed but not default selected.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'emergency',
    fieldKey: 'emergency_contact.email',
    label: 'Email',
    notes: 'Allowed but not default selected.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
  {
    familyKey: 'identifiers',
    fieldKey: 'person.system_id',
    label: 'System ID',
    notes: 'Read-only auto/system-managed field.',
    defaultAllowed: true,
    defaultSelected: false,
    minimumRequired: 'auto',
    isSystemManaged: true,
  },
  {
    familyKey: 'signature',
    fieldKey: 'signature.value',
    label: 'Signature',
    notes: 'Important field; default selected.',
    defaultAllowed: true,
    defaultSelected: true,
    minimumRequired: 'none',
    isSystemManaged: false,
  },
] as const;

export const EDITABLE_PERSONAL_FIELD_CATALOG = PERSONAL_FIELD_CATALOG.filter(
  (field) => !field.isSystemManaged,
);

export const REQUIRED_BASELINE_PERSONAL_FIELD_KEYS = new Set(
  PERSONAL_FIELD_CATALOG.filter((field) => field.minimumRequired === 'required').map(
    (field) => field.fieldKey,
  ),
);

export const INTEGRATION_CATALOG: IntegrationCatalogEntry[] = [
  {
    integrationKey: 'integration.adp',
    label: 'ADP',
    defaultAllowed: false,
    capabilities: [
      {
        capabilityKey: 'integration.adp.data_sync',
        label: 'Data Import & Sync',
        defaultAllowed: false,
      },
      {
        capabilityKey: 'integration.adp.import_enabled',
        label: 'Import Enabled',
        defaultAllowed: false,
      },
      {
        capabilityKey: 'integration.adp.import_rules',
        label: 'Import Rules',
        defaultAllowed: false,
      },
      {
        capabilityKey: 'integration.adp.field_mapping',
        label: 'Field Mapping',
        defaultAllowed: false,
      },
    ],
  },
  {
    integrationKey: 'integration.hint',
    label: 'Hint',
    defaultAllowed: false,
    capabilities: [
      {
        capabilityKey: 'integration.hint.data_sync',
        label: 'Data Import & Sync',
        defaultAllowed: false,
      },
      {
        capabilityKey: 'integration.hint.import_enabled',
        label: 'Import Enabled',
        defaultAllowed: false,
      },
      {
        capabilityKey: 'integration.hint.import_rules',
        label: 'Import Rules',
        defaultAllowed: false,
      },
      {
        capabilityKey: 'integration.hint.field_mapping',
        label: 'Field Mapping',
        defaultAllowed: false,
      },
    ],
  },
  {
    integrationKey: 'integration.istream',
    label: 'iStream',
    defaultAllowed: false,
    capabilities: [
      {
        capabilityKey: 'integration.istream.data_sync',
        label: 'Data Import & Sync',
        defaultAllowed: false,
      },
      {
        capabilityKey: 'integration.istream.import_enabled',
        label: 'Import Enabled',
        defaultAllowed: false,
      },
      {
        capabilityKey: 'integration.istream.import_rules',
        label: 'Import Rules',
        defaultAllowed: false,
      },
      {
        capabilityKey: 'integration.istream.field_mapping',
        label: 'Field Mapping',
        defaultAllowed: false,
      },
    ],
  },
  {
    integrationKey: 'integration.stripe',
    label: 'Stripe',
    defaultAllowed: false,
    capabilities: [
      {
        capabilityKey: 'integration.stripe.payments_surface',
        label: 'Payments Integration Surface',
        defaultAllowed: false,
      },
    ],
  },
  {
    integrationKey: 'integration.sso.google',
    label: 'Google SSO Integration',
    defaultAllowed: false,
    capabilities: [],
  },
  {
    integrationKey: 'integration.sso.microsoft',
    label: 'Microsoft SSO Integration',
    defaultAllowed: false,
    capabilities: [],
  },
] as const;

export const GOOGLE_SSO_INTEGRATION_KEY = 'integration.sso.google';
export const MICROSOFT_SSO_INTEGRATION_KEY = 'integration.sso.microsoft';

export function getPersonalFieldCatalogEntry(fieldKey: string): PersonalFieldCatalogEntry | null {
  return PERSONAL_FIELD_CATALOG.find((field) => field.fieldKey === fieldKey) ?? null;
}

export function getPersonalFamilyLabel(familyKey: PersonalFamilyKey): string {
  return PERSONAL_FAMILY_LABELS[familyKey];
}

export function getIntegrationCatalogEntry(integrationKey: string): IntegrationCatalogEntry | null {
  return INTEGRATION_CATALOG.find((entry) => entry.integrationKey === integrationKey) ?? null;
}
