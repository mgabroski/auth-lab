/**
 * backend/src/modules/settings/services/integrations-settings-query.service.ts
 *
 * WHY:
 * - Composes the informational Integrations v1 read model from CP allowance
 *   truth, Access/login-method dependency truth, and cached runtime readiness.
 * - Keeps the split v1 model explicit: Google/Microsoft SSO are informational
 *   live cards; HRIS/Stripe are deferred tenant-config surfaces; Marketplace is
 *   placeholder-only and not rendered as a tenant card.
 *
 * RULES:
 * - Pure composition only.
 * - No DB access.
 * - No live provider/network calls.
 * - No tenant credential, mapping, sync, or connection-flow semantics.
 */

import {
  INTEGRATION_CATALOG,
  type CpSettingsHandoffSnapshot,
  type IntegrationCatalogEntry,
} from '../../control-plane/accounts';
import type { Tenant } from '../../tenants/tenant.types';
import { SsoProviderReadinessGateway } from '../gateways/sso-provider-readiness.gateway';
import type {
  DeferredIntegrationCardDto,
  IntegrationSsoCardDto,
  IntegrationsSettingsDto,
  MarketplaceIntegrationDto,
  SettingsNextAction,
  SettingsSetupStatus,
} from '../settings.types';
import {
  IntegrationStatusEvaluator,
  type IntegrationStatusEvaluation,
} from './settings-evaluators';

export type IntegrationsSettingsReadModel = {
  google: IntegrationStatusEvaluation;
  microsoft: IntegrationStatusEvaluation;
  deferredIntegrations: DeferredIntegrationCardDto[];
  marketplace: MarketplaceIntegrationDto;
};

type SsoProviderDescriptor = {
  providerKey: 'google' | 'microsoft';
  integrationKey: 'integration.sso.google' | 'integration.sso.microsoft';
  title: string;
  description: string;
  loginMethodKey: 'auth.login.google' | 'auth.login.microsoft';
};

const SSO_PROVIDERS: SsoProviderDescriptor[] = [
  {
    providerKey: 'google',
    integrationKey: 'integration.sso.google',
    title: 'Google SSO Integration',
    description:
      'Informational status for Google SSO. Tenant credentials and connection controls are not available in v1.',
    loginMethodKey: 'auth.login.google',
  },
  {
    providerKey: 'microsoft',
    integrationKey: 'integration.sso.microsoft',
    title: 'Microsoft SSO Integration',
    description:
      'Informational status for Microsoft SSO. Tenant credentials and connection controls are not available in v1.',
    loginMethodKey: 'auth.login.microsoft',
  },
];

const DEFERRED_INTEGRATION_KEYS = [
  'integration.adp',
  'integration.hint',
  'integration.istream',
  'integration.stripe',
] as const;

function getIntegrationAllowance(params: {
  cpHandoff?: CpSettingsHandoffSnapshot;
  integrationKey: string;
  fallbackAllowed: boolean;
}): boolean {
  return (
    params.cpHandoff?.allowances.integrations.integrations.find(
      (integration) => integration.integrationKey === params.integrationKey,
    )?.isAllowed ?? params.fallbackAllowed
  );
}

function getAccessAllowance(params: { tenant: Tenant; cpHandoff?: CpSettingsHandoffSnapshot }) {
  return (
    params.cpHandoff?.allowances.access.loginMethods ?? {
      password: true,
      google: params.tenant.allowedSso.includes('google'),
      microsoft: params.tenant.allowedSso.includes('microsoft'),
    }
  );
}

function statusLabel(status: IntegrationStatusEvaluation['displayStatus']): string {
  switch (status) {
    case 'HIDDEN':
      return 'Hidden';
    case 'READY':
      return 'Ready';
    case 'NOT_IN_USE':
      return 'Not in use';
    case 'BLOCKED':
      return 'Blocked';
    default: {
      const exhaustiveCheck: never = status;
      return exhaustiveCheck;
    }
  }
}

function dependencyDescription(params: {
  providerLabel: string;
  loginMethodEnabled: boolean;
}): string {
  if (params.loginMethodEnabled) {
    return `${params.providerLabel} login is enabled in Access & Security, so runtime readiness must be truthful here.`;
  }

  return `${params.providerLabel} login is not enabled in Access & Security. The integration is allowed but not currently used for sign-in.`;
}

function toSsoCard(params: {
  descriptor: SsoProviderDescriptor;
  evaluation: IntegrationStatusEvaluation;
}): IntegrationSsoCardDto {
  const providerLabel = params.descriptor.providerKey === 'google' ? 'Google' : 'Microsoft';

  return {
    integrationKey: params.descriptor.integrationKey,
    providerKey: params.descriptor.providerKey,
    title: params.descriptor.title,
    description: params.descriptor.description,
    displayStatus: params.evaluation.displayStatus,
    statusLabel: statusLabel(params.evaluation.displayStatus),
    visible: params.evaluation.displayStatus !== 'HIDDEN',
    cpAllowed: params.evaluation.isAllowed,
    loginMethodEnabled: params.evaluation.loginMethodEnabled,
    tenantConfigurationAvailable: false,
    credentialEntryAvailable: false,
    connectionFlowAvailable: false,
    runtimeReadiness: {
      status: params.evaluation.readinessSnapshot.status,
      checkedAt: params.evaluation.readinessSnapshot.asOf.toISOString(),
      detail: params.evaluation.readinessSnapshot.detail,
    },
    warnings: params.evaluation.warnings,
    blockers: params.evaluation.blockers,
    resolutionHint:
      params.evaluation.displayStatus === 'BLOCKED'
        ? 'Runtime readiness is degraded. Review auth/runtime readiness configuration before relying on this SSO login method.'
        : params.evaluation.displayStatus === 'NOT_IN_USE'
          ? 'Enable the matching login method in Access & Security through Control Plane when this provider should be used.'
          : null,
    accessDependency: {
      loginMethodKey: params.descriptor.loginMethodKey,
      enabled: params.evaluation.loginMethodEnabled,
      description: dependencyDescription({
        providerLabel,
        loginMethodEnabled: params.evaluation.loginMethodEnabled,
      }),
    },
  };
}

function deferredDescription(entry: IntegrationCatalogEntry): string {
  if (entry.integrationKey === 'integration.stripe') {
    return 'Payments integration is conceptually present, but tenant Stripe configuration is deferred in v1.';
  }

  return `${entry.label} HRIS import and sync is conceptually present, but tenant configuration is deferred in v1.`;
}

function deferredReason(entry: IntegrationCatalogEntry): string {
  if (entry.integrationKey === 'integration.stripe') {
    return 'Available after platform configuration and tenant integration secrets management are complete.';
  }

  return 'Available after platform configuration, tenant integration secrets management, import rules, and field mapping foundations are complete.';
}

function buildDeferredCard(entry: IntegrationCatalogEntry): DeferredIntegrationCardDto {
  return {
    integrationKey: entry.integrationKey as DeferredIntegrationCardDto['integrationKey'],
    title: entry.label,
    category: entry.integrationKey === 'integration.stripe' ? 'PAYMENTS' : 'HRIS',
    treatment: 'DEFERRED',
    description: deferredDescription(entry),
    reason: deferredReason(entry),
    tenantConfigurationAvailable: false,
    credentialEntryAvailable: false,
    connectionFlowAvailable: false,
    syncEngineAvailable: false,
    mappingEditorAvailable: false,
    capabilities: entry.capabilities.map((capability) => ({
      capabilityKey: capability.capabilityKey,
      label: capability.label,
      deferred: true,
    })),
  };
}

function buildDeferredIntegrations(): DeferredIntegrationCardDto[] {
  return DEFERRED_INTEGRATION_KEYS.map((integrationKey) => {
    const entry = INTEGRATION_CATALOG.find(
      (candidate) => candidate.integrationKey === integrationKey,
    );
    if (!entry) {
      throw new Error(`Missing integration catalog entry for ${integrationKey}`);
    }

    return buildDeferredCard(entry);
  });
}

function buildMarketplace(): MarketplaceIntegrationDto {
  return {
    integrationKey: 'integration.marketplace',
    treatment: 'PLACEHOLDER_ONLY',
    visible: false,
    reason:
      'Marketplace is placeholder-only in v1 and is intentionally not rendered as a tenant configuration card.',
  };
}

export class IntegrationsSettingsQueryService {
  constructor(private readonly readinessGateway: SsoProviderReadinessGateway) {}

  build(params: {
    tenant: Tenant;
    cpHandoff?: CpSettingsHandoffSnapshot;
  }): IntegrationsSettingsReadModel {
    const access = getAccessAllowance(params);

    const googleAllowed = getIntegrationAllowance({
      cpHandoff: params.cpHandoff,
      integrationKey: 'integration.sso.google',
      fallbackAllowed: params.tenant.allowedSso.includes('google'),
    });

    const microsoftAllowed = getIntegrationAllowance({
      cpHandoff: params.cpHandoff,
      integrationKey: 'integration.sso.microsoft',
      fallbackAllowed: params.tenant.allowedSso.includes('microsoft'),
    });

    return {
      google: IntegrationStatusEvaluator.evaluate({
        integrationKey: 'integration.sso.google',
        isAllowed: googleAllowed,
        loginMethodEnabled: access.google,
        readinessSnapshot: this.readinessGateway.getSnapshot('google'),
      }),
      microsoft: IntegrationStatusEvaluator.evaluate({
        integrationKey: 'integration.sso.microsoft',
        isAllowed: microsoftAllowed,
        loginMethodEnabled: access.microsoft,
        readinessSnapshot: this.readinessGateway.getSnapshot('microsoft'),
      }),
      deferredIntegrations: buildDeferredIntegrations(),
      marketplace: buildMarketplace(),
    };
  }

  toDto(params: {
    status: SettingsSetupStatus;
    version: number;
    cpRevision: number;
    nextAction: SettingsNextAction | null;
    model: IntegrationsSettingsReadModel;
  }): IntegrationsSettingsDto {
    const ssoIntegrations = SSO_PROVIDERS.map((descriptor) =>
      toSsoCard({
        descriptor,
        evaluation:
          descriptor.providerKey === 'google' ? params.model.google : params.model.microsoft,
      }),
    );

    return {
      sectionKey: 'integrations',
      title: 'Integrations',
      description:
        'View truthful SSO integration readiness and deferred tenant-configured integrations. This v1 page is informational only.',
      status: params.status,
      version: params.version,
      cpRevision: params.cpRevision,
      ssoIntegrations,
      deferredIntegrations: params.model.deferredIntegrations,
      marketplace: params.model.marketplace,
      warnings: ssoIntegrations.flatMap((integration) => integration.warnings),
      nextAction: params.nextAction,
    };
  }
}
