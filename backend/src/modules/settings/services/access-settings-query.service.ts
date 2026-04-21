/**
 * backend/src/modules/settings/services/access-settings-query.service.ts
 *
 * WHY:
 * - Composes the Access & Security read model and the v1 read-only page surface
 *   from real CP allowance truth, tenant bridge truth, and integration/runtime
 *   readiness state.
 * - Keeps the locked Phase 4 rules explicit:
 *   - read-only in v1
 *   - explicit acknowledge is the only completion action
 *   - CP mismatch blockers stay distinct from operational readiness warnings
 *
 * RULES:
 * - Pure composition only.
 * - No DB access.
 * - No AppError.
 */

import type { Tenant } from '../../tenants/tenant.types';
import type { CpSettingsHandoffSnapshot } from '../../control-plane/accounts/handoff/cp-settings-handoff.types';
import type {
  AccessSettingsGroupDto,
  AccessSettingsRowDto,
  AccessSettingsRowStatus,
} from '../settings.types';
import type { IntegrationStatusEvaluation } from './settings-evaluators';

export type AccessSettingsReadModel = {
  loginMethods: {
    password: boolean;
    google: boolean;
    microsoft: boolean;
  };
  mfaPolicy: {
    adminRequired: boolean;
    memberRequired: boolean;
  };
  signupPolicy: {
    publicSignup: boolean;
    adminInvitationsAllowed: boolean;
    allowedDomains: string[];
  };
};

export type AccessSettingsSurfaceModel = {
  groups: AccessSettingsGroupDto[];
  blockers: string[];
  warnings: string[];
  canAcknowledge: boolean;
};

function createRow(params: {
  key: string;
  label: string;
  value: string;
  managedBy: 'CONTROL_PLANE' | 'PLATFORM';
  status?: AccessSettingsRowStatus;
  warning?: string | null;
  blocker?: string | null;
  resolutionHref?: string | null;
}): AccessSettingsRowDto {
  return {
    key: params.key,
    label: params.label,
    value: params.value,
    readOnly: true,
    managedBy: params.managedBy,
    status: params.status ?? 'READY',
    warning: params.warning ?? null,
    blocker: params.blocker ?? null,
    resolutionHref: params.resolutionHref ?? null,
  };
}

function boolValue(enabled: boolean, enabledLabel = 'Enabled', disabledLabel = 'Disabled'): string {
  return enabled ? enabledLabel : disabledLabel;
}

function domainsValue(allowedDomains: string[]): string {
  if (allowedDomains.length === 0) {
    return 'Any email domain';
  }

  return allowedDomains.join(', ');
}

function loginMethodRow(params: {
  key: 'password' | 'google' | 'microsoft';
  label: string;
  enabled: boolean;
  managedBy: 'CONTROL_PLANE' | 'PLATFORM';
  integrationAllowed?: boolean;
  integrationStatus?: IntegrationStatusEvaluation;
}): AccessSettingsRowDto | null {
  if (!params.enabled) {
    return null;
  }

  if (params.key === 'password') {
    return createRow({
      key: params.key,
      label: params.label,
      value: 'Enabled',
      managedBy: params.managedBy,
    });
  }

  if (params.integrationAllowed === false) {
    const providerLabel = params.label;
    return createRow({
      key: params.key,
      label: params.label,
      value: 'Enabled',
      managedBy: params.managedBy,
      status: 'BLOCKED',
      blocker: `${providerLabel} login is enabled, but the matching ${providerLabel} SSO integration is not allowed by Control Plane. This workspace fails closed until Control Plane fixes the mismatch.`,
    });
  }

  if (params.integrationStatus?.displayStatus === 'BLOCKED') {
    return createRow({
      key: params.key,
      label: params.label,
      value: 'Enabled',
      managedBy: params.managedBy,
      status: 'WARNING',
      warning: params.integrationStatus.warnings[0] ?? null,
      resolutionHref: '/admin/settings/integrations',
    });
  }

  return createRow({
    key: params.key,
    label: params.label,
    value: 'Enabled',
    managedBy: params.managedBy,
  });
}

export class AccessSettingsQueryService {
  build(params: {
    tenant: Tenant;
    cpHandoff?: CpSettingsHandoffSnapshot;
  }): AccessSettingsReadModel {
    if (params.cpHandoff) {
      return params.cpHandoff.allowances.access;
    }

    return {
      loginMethods: {
        password: true,
        google: params.tenant.allowedSso.includes('google'),
        microsoft: params.tenant.allowedSso.includes('microsoft'),
      },
      mfaPolicy: {
        adminRequired: true,
        memberRequired: params.tenant.memberMfaRequired,
      },
      signupPolicy: {
        publicSignup: params.tenant.publicSignupEnabled,
        adminInvitationsAllowed: true,
        allowedDomains: [...params.tenant.allowedEmailDomains],
      },
    };
  }

  buildSurface(params: {
    access: AccessSettingsReadModel;
    googleIntegrationAllowed: boolean;
    microsoftIntegrationAllowed: boolean;
    googleIntegrationStatus: IntegrationStatusEvaluation;
    microsoftIntegrationStatus: IntegrationStatusEvaluation;
  }): AccessSettingsSurfaceModel {
    const loginMethodRows = [
      loginMethodRow({
        key: 'password',
        label: 'Username & Password',
        enabled: params.access.loginMethods.password,
        managedBy: 'CONTROL_PLANE',
      }),
      loginMethodRow({
        key: 'google',
        label: 'Google SSO',
        enabled: params.access.loginMethods.google,
        managedBy: 'CONTROL_PLANE',
        integrationAllowed: params.googleIntegrationAllowed,
        integrationStatus: params.googleIntegrationStatus,
      }),
      loginMethodRow({
        key: 'microsoft',
        label: 'Microsoft SSO',
        enabled: params.access.loginMethods.microsoft,
        managedBy: 'CONTROL_PLANE',
        integrationAllowed: params.microsoftIntegrationAllowed,
        integrationStatus: params.microsoftIntegrationStatus,
      }),
    ].filter((row): row is AccessSettingsRowDto => row !== null);

    const groups: AccessSettingsGroupDto[] = [
      {
        key: 'loginMethods',
        title: 'Login Methods',
        description:
          'These login methods are platform-managed in v1. Tenant admins may review them here but cannot edit them.',
        rows: loginMethodRows,
      },
      {
        key: 'mfaPolicy',
        title: 'MFA Policy',
        description:
          'MFA policy is defined by the platform envelope in v1. This page is review-only for tenant admins.',
        rows: [
          createRow({
            key: 'adminMfa',
            label: 'Admin MFA',
            value: boolValue(params.access.mfaPolicy.adminRequired, 'Required', 'Not required'),
            managedBy: 'PLATFORM',
          }),
          createRow({
            key: 'memberMfa',
            label: 'Member MFA',
            value: boolValue(params.access.mfaPolicy.memberRequired, 'Required', 'Not required'),
            managedBy: 'CONTROL_PLANE',
          }),
        ],
      },
      {
        key: 'signupPolicy',
        title: 'Signup & Invite Access Policy',
        description:
          'Signup and invite policy stays read-only in v1. Runtime enforcement still belongs to the platform and auth layer.',
        rows: [
          createRow({
            key: 'publicSignup',
            label: 'Public Signup',
            value: boolValue(params.access.signupPolicy.publicSignup),
            managedBy: 'CONTROL_PLANE',
          }),
          createRow({
            key: 'adminInvitationsAllowed',
            label: 'Admin Invitations Allowed',
            value: boolValue(params.access.signupPolicy.adminInvitationsAllowed),
            managedBy: 'CONTROL_PLANE',
          }),
          createRow({
            key: 'allowedDomains',
            label: 'Allowed Domains',
            value: domainsValue(params.access.signupPolicy.allowedDomains),
            managedBy: 'CONTROL_PLANE',
          }),
        ],
      },
    ];

    const blockers = groups
      .flatMap((group) => group.rows)
      .map((row) => row.blocker)
      .filter((value): value is string => Boolean(value));
    const warnings = groups
      .flatMap((group) => group.rows)
      .map((row) => row.warning)
      .filter((value): value is string => Boolean(value));

    return {
      groups,
      blockers,
      warnings,
      canAcknowledge: blockers.length === 0,
    };
  }
}
