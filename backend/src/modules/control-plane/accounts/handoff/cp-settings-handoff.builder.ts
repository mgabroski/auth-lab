/**
 * backend/src/modules/control-plane/accounts/handoff/cp-settings-handoff.builder.ts
 *
 * WHY:
 * - Builds the canonical CP producer snapshot that the later Settings state
 *   engine will consume.
 * - Strips CP authoring-progress concerns and keeps only allowance truth,
 *   provisioning truth, and the honest cascade boundary.
 * - Makes the State A stopping point explicit: producer contract exists, live
 *   synchronous cascade does not.
 *
 * RULES:
 * - Pure builder only.
 * - No DB access, no AppError, no logging.
 * - No fake success or fake Settings sync fields.
 */

import type { CpAccountDetail, CpProvisioningResult } from '../cp-accounts.types';
import type {
  CpSettingsHandoffEligibility,
  CpSettingsHandoffSnapshot,
} from './cp-settings-handoff.types';

function buildEligibility(provisioning: CpProvisioningResult): CpSettingsHandoffEligibility {
  return provisioning.isProvisioned
    ? 'READY_FOR_FUTURE_SETTINGS_CONSUMER'
    : 'BLOCKED_UNPUBLISHED_ACCOUNT';
}

function buildBlockingReasons(
  account: Pick<Omit<CpAccountDetail, 'settingsHandoff'>, 'accountKey'>,
  provisioning: CpProvisioningResult,
): string[] {
  const reasons = [
    'Settings Step 10 Phase 2 is not implemented in this repo yet. The Control Plane remains a producer-only source of allowance truth.',
  ];

  if (!provisioning.isProvisioned) {
    reasons.push(
      `Account "${account.accountKey}" is not provisioned to a tenant yet. Publish the account before any future Settings cascade can become eligible.`,
    );
  }

  return reasons;
}

export function buildCpSettingsHandoffSnapshot(params: {
  account: Omit<CpAccountDetail, 'settingsHandoff'>;
  provisioning: CpProvisioningResult;
}): CpSettingsHandoffSnapshot {
  const { account, provisioning } = params;

  return {
    contractVersion: 1,
    producedAt: new Date(),
    mode: 'PRODUCER_ONLY',
    eligibility: buildEligibility(provisioning),
    consumer: {
      settingsEnginePresent: false,
      cascadeStatus: 'NOT_WIRED',
      blockingReasons: buildBlockingReasons(account, provisioning),
    },
    account: {
      accountId: account.id,
      accountKey: account.accountKey,
      accountName: account.accountName,
      cpStatus: account.cpStatus,
      cpRevision: account.cpRevision,
    },
    provisioning: {
      isProvisioned: provisioning.isProvisioned,
      tenantId: provisioning.tenantId,
      tenantKey: provisioning.tenantKey,
      tenantName: provisioning.tenantName,
      tenantState: provisioning.tenantState,
      publishedAt: provisioning.publishedAt,
    },
    allowances: {
      access: {
        loginMethods: { ...account.access.loginMethods },
        mfaPolicy: { ...account.access.mfaPolicy },
        signupPolicy: {
          publicSignup: account.access.signupPolicy.publicSignup,
          adminInvitationsAllowed: account.access.signupPolicy.adminInvitationsAllowed,
          allowedDomains: [...account.access.signupPolicy.allowedDomains],
        },
      },
      account: {
        branding: { ...account.accountSettings.branding },
        organizationStructure: {
          ...account.accountSettings.organizationStructure,
        },
        companyCalendar: { ...account.accountSettings.companyCalendar },
      },
      modules: {
        modules: { ...account.moduleSettings.modules },
      },
      personal: {
        families: account.personal.families.map((family) => ({
          familyKey: family.familyKey,
          isAllowed: family.isAllowed,
        })),
        fields: account.personal.families.flatMap((family) =>
          family.fields.map((field) => ({
            familyKey: field.familyKey,
            fieldKey: field.fieldKey,
            isAllowed: field.isAllowed,
            defaultSelected: field.defaultSelected,
            minimumRequired: field.minimumRequired,
            isSystemManaged: field.isSystemManaged,
          })),
        ),
      },
      integrations: {
        integrations: account.integrations.integrations.map((integration) => ({
          integrationKey: integration.integrationKey,
          isAllowed: integration.isAllowed,
          capabilities: integration.capabilities.map((capability) => ({
            capabilityKey: capability.capabilityKey,
            isAllowed: capability.isAllowed,
          })),
        })),
      },
    },
  };
}
