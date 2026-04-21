/**
 * backend/src/modules/settings/services/integrations-settings-query.service.ts
 *
 * WHY:
 * - Composes the informational SSO integration state used by the Settings
 *   overview and future Integrations page.
 * - Keeps deferred HRIS/Stripe treatment separate from live Google/Microsoft
 *   informational status cards.
 */

import type { Tenant } from '../../tenants/tenant.types';
import type { CpSettingsHandoffSnapshot } from '../../control-plane/accounts/handoff/cp-settings-handoff.types';
import { SsoProviderReadinessGateway } from '../gateways/sso-provider-readiness.gateway';
import {
  IntegrationStatusEvaluator,
  type IntegrationStatusEvaluation,
} from './settings-evaluators';

export type IntegrationsSettingsReadModel = {
  google: IntegrationStatusEvaluation;
  microsoft: IntegrationStatusEvaluation;
  deferredKeys: string[];
};

export class IntegrationsSettingsQueryService {
  constructor(private readonly readinessGateway: SsoProviderReadinessGateway) {}

  build(params: {
    tenant: Tenant;
    cpHandoff?: CpSettingsHandoffSnapshot;
  }): IntegrationsSettingsReadModel {
    const access = params.cpHandoff?.allowances.access.loginMethods ?? {
      password: true,
      google: params.tenant.allowedSso.includes('google'),
      microsoft: params.tenant.allowedSso.includes('microsoft'),
    };

    const googleAllowed =
      params.cpHandoff?.allowances.integrations.integrations.find(
        (integration) => integration.integrationKey === 'integration.sso.google',
      )?.isAllowed ?? params.tenant.allowedSso.includes('google');

    const microsoftAllowed =
      params.cpHandoff?.allowances.integrations.integrations.find(
        (integration) => integration.integrationKey === 'integration.sso.microsoft',
      )?.isAllowed ?? params.tenant.allowedSso.includes('microsoft');

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
      deferredKeys: [
        'integration.adp',
        'integration.hint',
        'integration.istream',
        'integration.stripe',
      ],
    };
  }
}
