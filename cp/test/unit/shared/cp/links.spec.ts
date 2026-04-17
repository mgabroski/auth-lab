import { describe, expect, it } from 'vitest';

import {
  CONTROL_PLANE_TITLE,
  CREATE_FLOW_STEPS,
  getAccountsListPath,
  getCreateBasicInfoPath,
  getCreateFlowEntryPath,
  getCreatePersonalSetupPath,
  getCreateReviewPath,
  getCreateSetupGroupPath,
  getCreateSetupPath,
  getEditFlowEntryPath,
  getEditPersonalSetupPath,
  getEditReviewPath,
  getEditSetupGroupPath,
  getEditSetupPath,
} from '@/shared/cp/links';

describe('CP route helpers', () => {
  it('preserves the locked CP shell title and 3-step flow labels', () => {
    expect(CONTROL_PLANE_TITLE).toBe('Control Plane');
    expect(CREATE_FLOW_STEPS).toEqual([
      { stepNumber: 1, name: 'Basic Account Info' },
      { stepNumber: 2, name: 'Account Setup' },
      { stepNumber: 3, name: 'Review & Publish' },
    ]);
  });

  it('builds create-flow paths with query-based accountKey handoff', () => {
    expect(getAccountsListPath()).toBe('/accounts');
    expect(getCreateFlowEntryPath()).toBe('/accounts/create/basic-info');
    expect(getCreateBasicInfoPath()).toBe('/accounts/create/basic-info');
    expect(getCreateSetupPath('acme-1')).toBe('/accounts/create/setup?accountKey=acme-1');
    expect(getCreateSetupGroupPath('module-settings', 'tenant with spaces')).toBe(
      '/accounts/create/setup/module-settings?accountKey=tenant%20with%20spaces',
    );
    expect(getCreatePersonalSetupPath('acme')).toBe(
      '/accounts/create/setup/module-settings/personal?accountKey=acme',
    );
    expect(getCreateReviewPath('acme')).toBe('/accounts/create/review?accountKey=acme');
  });

  it('builds edit/review paths from the accountKey path segment', () => {
    expect(getEditFlowEntryPath('acme')).toBe('/accounts/acme/edit/setup');
    expect(getEditSetupPath('acme')).toBe('/accounts/acme/edit/setup');
    expect(getEditSetupGroupPath('acme', 'access-identity-security')).toBe(
      '/accounts/acme/edit/setup/access-identity-security',
    );
    expect(getEditPersonalSetupPath('acme')).toBe(
      '/accounts/acme/edit/setup/module-settings/personal',
    );
    expect(getEditReviewPath('acme')).toBe('/accounts/acme/edit/review');
  });
});
