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
    description: 'Personal field-rule foundations.',
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
    moduleEnabled: true,
    familyReview: {
      title: 'Step 1 — Family review',
      description: 'Review allowed families.',
      summary: '2 allowed families are visible.',
      families: [
        {
          familyKey: 'identity',
          label: 'Identity',
          reviewDecision: 'UNREVIEWED',
          reviewStatus: 'NOT_STARTED',
          allowedFieldCount: 2,
          defaultSelectedFieldCount: 1,
          containsLockedRequiredFields: true,
          canExclude: false,
          requiredFieldKeys: ['person.first_name'],
          systemManagedFieldKeys: [],
          notes: ['Contains fields that cannot be excluded under the locked Personal rules.'],
        },
      ],
    },
    fieldConfiguration: {
      key: 'fieldConfiguration',
      title: 'Field Configuration',
      description: 'Review the real field-rule foundation.',
      summary: '2 CP-allowed fields are grouped by family.',
      status: 'CURRENT_FOUNDATION',
      isLiveInCurrentRepo: true,
      hiddenVsExcluded: {
        hidden: 'Hidden means the field is not allowed by Control Plane.',
        excluded: 'Excluded means the field is CP-allowed but tenant-disabled later.',
      },
      conflictGuidance: {
        version: 2,
        cpRevision: 4,
        summary: 'Use the current section version and CP revision as the future conflict baseline.',
        notes: [
          'No Personal mutation route is shipped in this phase, so there is no fake save success path.',
        ],
      },
      families: [
        {
          familyKey: 'identity',
          label: 'Identity',
          canExclude: false,
          exclusionLockedReason: 'Contains minimum-required fields that cannot be excluded.',
          visibleFieldCount: 2,
          defaultSelectedFieldCount: 1,
          minimumRequiredFieldCount: 1,
          systemManagedFieldCount: 0,
          notes: ['Contains fields that cannot be excluded under the locked Personal rules.'],
          fields: [
            {
              familyKey: 'identity',
              fieldKey: 'person.first_name',
              label: 'First Name',
              notes: 'Required baseline field.',
              minimumRequired: 'required',
              isSystemManaged: false,
              presentationState: 'CONFIGURABLE',
              readiness: 'CP_DEFAULT_SELECTED',
              requiredRule: 'LOCKED_REQUIRED',
              maskingRule: 'TENANT_CHOICE_WHEN_INCLUDED',
              canBeExcludedLater: false,
              canToggleRequiredLater: false,
              canToggleMaskingLater: true,
              warnings: [],
              blockers: ['Required-floor field. It cannot be made optional or excluded.'],
            },
            {
              familyKey: 'identity',
              fieldKey: 'person.middle_name',
              label: 'Middle Name',
              notes: 'Optional identity field.',
              minimumRequired: 'none',
              isSystemManaged: false,
              presentationState: 'CONFIGURABLE',
              readiness: 'AVAILABLE_TO_INCLUDE',
              requiredRule: 'TENANT_CHOICE',
              maskingRule: 'TENANT_CHOICE_WHEN_INCLUDED',
              canBeExcludedLater: true,
              canToggleRequiredLater: true,
              canToggleMaskingLater: true,
              warnings: ['This field is CP-allowed but not currently default-selected.'],
              blockers: [],
            },
          ],
        },
      ],
    },
    sectionBuilder: {
      key: 'sectionBuilder',
      title: 'Section Builder',
      description: 'Later phase.',
      status: 'FUTURE_PHASE',
      isLiveInCurrentRepo: false,
      summary: 'Not live yet.',
    },
    ...overrides,
  };
}

describe('PersonalSettingsFoundation', () => {
  it('renders the field-configuration foundation and explicit hidden vs excluded guidance', () => {
    const html = renderToStaticMarkup(<PersonalSettingsFoundation data={makePersonal()} />);

    expect(html).toContain('Field Configuration');
    expect(html).toContain('Hidden');
    expect(html).toContain('Excluded');
    expect(html).toContain('Conflict groundwork');
    expect(html).toContain('Expected version 2');
    expect(html).toContain('Expected CP revision 4');
    expect(html).toContain('First Name');
    expect(html).toContain('Required (locked)');
    expect(html).toContain('Available to include later');
    expect(html).toContain('Family must stay visible');
  });
});
