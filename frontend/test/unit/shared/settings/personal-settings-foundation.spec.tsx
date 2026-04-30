import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { PersonalSettingsResponse } from '../../../../src/shared/settings/contracts';
import { PersonalSettingsFoundation } from '../../../../src/shared/settings/components/personal-settings-foundation';

vi.mock('next/link', () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) =>
    React.createElement('a', { href }, children),
}));

function makePersonal(overrides: Partial<PersonalSettingsResponse> = {}): PersonalSettingsResponse {
  return {
    sectionKey: 'personal',
    title: 'Personal settings',
    description: 'Configure Personal for your workspace.',
    status: 'IN_PROGRESS',
    version: 2,
    cpRevision: 4,
    warnings: ['Platform changes require your review before Personal can return to Complete.'],
    blockers: [],
    nextAction: {
      key: 'modules',
      label: 'Continue Personal setup',
      href: '/admin/settings/modules/personal',
    },
    progress: {
      reviewedFamiliesCount: 1,
      totalAllowedFamilies: 1,
      requiredFieldsReady: true,
      sectionAssignmentsReady: true,
      blockers: [],
    },
    familyReview: {
      key: 'familyReview',
      title: 'Family Review',
      description: 'Review allowed families.',
      summary: '1 of 1 allowed families have been saved.',
      status: 'IN_PROGRESS',
      families: [
        {
          familyKey: 'identity',
          label: 'Identity',
          reviewDecision: 'IN_USE',
          reviewStatus: 'SAVED',
          isAllowed: true,
          canExclude: false,
          lockedReason:
            'This family contains required-floor or system-managed fields and must stay in use.',
          allowedFieldCount: 2,
          includedFieldCount: 2,
          requiredFieldKeys: ['person.first_name'],
          notes: ['This family remains locked in use under the workspace baseline.'],
          warnings: [],
          blockers: [],
        },
      ],
    },
    fieldConfiguration: {
      key: 'fieldConfiguration',
      title: 'Field Configuration',
      description: 'Configure field behavior.',
      summary: 'Required-floor fields are currently configured.',
      status: 'IN_PROGRESS',
      hiddenVsExcluded: {
        hidden: 'Hidden means not CP-allowed and never shown in the tenant UI.',
        excluded: 'Excluded means CP-allowed but tenant-chosen not in use.',
      },
      families: [
        {
          familyKey: 'identity',
          label: 'Identity',
          reviewDecision: 'IN_USE',
          canExclude: false,
          exclusionLockedReason:
            'This family contains required-floor or system-managed fields and must stay in use.',
          visibleFieldCount: 2,
          includedFieldCount: 2,
          minimumRequiredFieldCount: 1,
          systemManagedFieldCount: 0,
          notes: ['This family remains locked in use under the workspace baseline.'],
          fields: [
            {
              familyKey: 'identity',
              fieldKey: 'person.first_name',
              label: 'First Name',
              notes: 'Required baseline field.',
              minimumRequired: 'required',
              isSystemManaged: false,
              included: true,
              required: true,
              masked: false,
              includeRule: 'LOCKED_INCLUDED',
              requiredRule: 'LOCKED_REQUIRED',
              maskingRule: 'TENANT_CHOICE',
              canToggleInclude: false,
              canToggleRequired: false,
              canToggleMasking: true,
              warnings: [],
              blockers: [],
            },
            {
              familyKey: 'identity',
              fieldKey: 'person.middle_name',
              label: 'Middle Name',
              notes: 'Optional identity field.',
              minimumRequired: 'none',
              isSystemManaged: false,
              included: true,
              required: false,
              masked: false,
              includeRule: 'TENANT_CHOICE',
              requiredRule: 'TENANT_CHOICE',
              maskingRule: 'TENANT_CHOICE',
              canToggleInclude: true,
              canToggleRequired: true,
              canToggleMasking: true,
              warnings: ['Unsaved draft decision. Save Personal Configuration to persist it.'],
              blockers: [],
            },
          ],
        },
      ],
    },
    sectionBuilder: {
      key: 'sectionBuilder',
      title: 'Section Builder',
      description: 'Organize included fields into simple sections.',
      summary: '1 section is ready for review and save.',
      status: 'IN_PROGRESS',
      emptySectionSaveBlocked: true,
      removeOnlyWhenEmpty: true,
      sections: [
        {
          sectionId: 'generated-identity',
          name: 'Identity',
          order: 0,
          fieldCount: 2,
          fields: [
            { fieldKey: 'person.first_name', familyKey: 'identity', label: 'First Name', order: 0 },
            {
              fieldKey: 'person.middle_name',
              familyKey: 'identity',
              label: 'Middle Name',
              order: 1,
            },
          ],
        },
      ],
    },
    conflictGuidance: {
      summary:
        'If a Personal save returns a conflict, keep your local draft, refetch the latest server DTO, and decide how to reconcile before saving again.',
      notes: ['There is no silent auto-merge or silent retry for Personal.'],
    },
    saveActionLabel: 'Save Personal Configuration',
    stickySaveLabel: 'Save Personal Configuration',
    ...overrides,
  };
}

describe('PersonalSettingsFoundation', () => {
  it('renders the final Personal builder with save guidance and section builder content', () => {
    const html = renderToStaticMarkup(<PersonalSettingsFoundation data={makePersonal()} />);

    expect(html).toContain('Family Review');
    expect(html).toContain('Field Configuration');
    expect(html).toContain('Section Builder');
    expect(html).toContain('Save Personal Configuration');
    expect(html).toContain('First Name');
    expect(html).toContain('Middle Name');
    expect(html).toContain('Identity');
    expect(html).toContain('Included');
    expect(html).toContain('Masked');
    expect(html).toContain('Platform changes require your review');
  });
});
