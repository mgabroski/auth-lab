import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { IntegrationsSettingsResponse } from '../../../../src/shared/settings/contracts';
import { IntegrationsSettingsView } from '../../../../src/shared/settings/components/integrations-settings-view';

vi.mock('next/link', () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) =>
    React.createElement('a', { href }, children),
}));

function makeIntegrations(
  overrides: Partial<IntegrationsSettingsResponse> = {},
): IntegrationsSettingsResponse {
  return {
    sectionKey: 'integrations',
    title: 'Integrations',
    description: 'View truthful SSO integration readiness and deferred integrations.',
    status: 'NOT_STARTED',
    version: 1,
    cpRevision: 4,
    ssoIntegrations: [
      {
        integrationKey: 'integration.sso.google',
        providerKey: 'google',
        title: 'Google SSO Integration',
        description: 'Informational status for Google SSO.',
        displayStatus: 'BLOCKED',
        statusLabel: 'Blocked',
        visible: true,
        cpAllowed: true,
        loginMethodEnabled: true,
        tenantConfigurationAvailable: false,
        credentialEntryAvailable: false,
        connectionFlowAvailable: false,
        runtimeReadiness: {
          status: 'SNAPSHOT_UNAVAILABLE',
          checkedAt: '2026-04-21T00:00:00.000Z',
          detail: 'snapshot missing',
        },
        warnings: ['Google SSO runtime readiness is unavailable.'],
        blockers: [],
        resolutionHint: 'Review auth/runtime readiness configuration.',
        accessDependency: {
          loginMethodKey: 'auth.login.google',
          enabled: true,
          description: 'Google login is enabled in Access & Security.',
        },
      },
      {
        integrationKey: 'integration.sso.microsoft',
        providerKey: 'microsoft',
        title: 'Microsoft SSO Integration',
        description: 'Informational status for Microsoft SSO.',
        displayStatus: 'HIDDEN',
        statusLabel: 'Hidden',
        visible: false,
        cpAllowed: false,
        loginMethodEnabled: false,
        tenantConfigurationAvailable: false,
        credentialEntryAvailable: false,
        connectionFlowAvailable: false,
        runtimeReadiness: {
          status: 'SNAPSHOT_UNAVAILABLE',
          checkedAt: '2026-04-21T00:00:00.000Z',
          detail: 'snapshot missing',
        },
        warnings: [],
        blockers: [],
        resolutionHint: null,
        accessDependency: {
          loginMethodKey: 'auth.login.microsoft',
          enabled: false,
          description: 'Microsoft login is not enabled in Access & Security.',
        },
      },
    ],
    deferredIntegrations: [
      {
        integrationKey: 'integration.adp',
        title: 'ADP',
        category: 'HRIS',
        treatment: 'DEFERRED',
        description: 'ADP HRIS import and sync is deferred in v1.',
        reason: 'Available after platform configuration is complete.',
        tenantConfigurationAvailable: false,
        credentialEntryAvailable: false,
        connectionFlowAvailable: false,
        syncEngineAvailable: false,
        mappingEditorAvailable: false,
        capabilities: [
          {
            capabilityKey: 'integration.adp.import_rules',
            label: 'Import Rules',
            deferred: true,
          },
        ],
      },
      {
        integrationKey: 'integration.stripe',
        title: 'Stripe',
        category: 'PAYMENTS',
        treatment: 'DEFERRED',
        description: 'Payments integration is deferred in v1.',
        reason: 'Available after platform configuration is complete.',
        tenantConfigurationAvailable: false,
        credentialEntryAvailable: false,
        connectionFlowAvailable: false,
        syncEngineAvailable: false,
        mappingEditorAvailable: false,
        capabilities: [],
      },
    ],
    marketplace: {
      integrationKey: 'integration.marketplace',
      treatment: 'PLACEHOLDER_ONLY',
      visible: false,
      reason: 'Marketplace is placeholder-only in v1.',
    },
    warnings: ['Google SSO runtime readiness is unavailable.'],
    nextAction: null,
    ...overrides,
  };
}

describe('IntegrationsSettingsView', () => {
  it('renders truthful SSO and deferred provider cards without fake connection CTAs', () => {
    const html = renderToStaticMarkup(<IntegrationsSettingsView data={makeIntegrations()} />);

    expect(html).toContain('Google SSO Integration');
    expect(html).toContain('Blocked');
    expect(html).toContain('Google SSO runtime readiness is unavailable.');
    expect(html).toContain('ADP');
    expect(html).toContain('Stripe');
    expect(html).toContain('No credential entry.');
    expect(html).toContain('No mapping editor.');
    expect(html).toContain('No sync execution flow.');
    expect(html).not.toContain('Marketplace');
    expect(html).not.toContain('Connected');
    expect(html).not.toContain('Reconnect');
    expect(html).not.toContain('Connect now');
  });

  it('shows hidden SSO treatment without rendering hidden provider cards as actions', () => {
    const html = renderToStaticMarkup(
      <IntegrationsSettingsView
        data={makeIntegrations({
          ssoIntegrations: makeIntegrations().ssoIntegrations.map((integration) => ({
            ...integration,
            displayStatus: 'HIDDEN',
            statusLabel: 'Hidden',
            visible: false,
            cpAllowed: false,
            warnings: [],
          })),
          warnings: [],
        })}
      />,
    );

    expect(html).toContain('No SSO integrations are visible');
    expect(html).not.toContain('Review Access &amp; Security dependency');
  });
});
