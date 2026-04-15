'use client';

import { useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import type { CSSProperties } from 'react';
import type {
  AccountFlowMode,
  ControlPlaneAccountDetail,
  FooterAction,
  SaveCpAccessInput,
  SaveCpAccountSettingsInput,
  SaveCpIntegrationsInput,
  SaveCpModuleSettingsInput,
  SetupGroupDefinition,
} from '../contracts';
import {
  saveCpAccess,
  saveCpAccountSettings,
  saveCpIntegrations,
  saveCpModuleSettings,
} from '../cp-accounts-client';
import {
  getCreatePersonalSetupPath,
  getCreateSetupPath,
  getEditPersonalSetupPath,
  getEditSetupPath,
} from '@/shared/cp/links';
import {
  contentPanelStyle,
  infoCardStyle,
  infoGridStyle,
  insetPanelStyle,
  labelStyle,
  mutedTextStyle,
  sectionGridStyle,
  sectionTitleStyle,
  valueStyle,
} from '@/shared/cp/styles';
import { ControlPlaneShell } from '@/shared/cp/components/control-plane-shell';

const formSectionStyle: CSSProperties = {
  display: 'grid',
  gap: '14px',
};

const rowStyle: CSSProperties = {
  display: 'flex',
  alignItems: 'flex-start',
  gap: '10px',
};

const checkboxStyle: CSSProperties = {
  width: '16px',
  height: '16px',
  marginTop: '2px',
};

const helperStyle: CSSProperties = {
  margin: 0,
  fontSize: '13px',
  color: '#64748b',
  lineHeight: 1.6,
};

const textareaStyle: CSSProperties = {
  width: '100%',
  minHeight: '108px',
  padding: '12px',
  borderRadius: '10px',
  border: '1px solid #cbd5e1',
  backgroundColor: '#ffffff',
  color: '#0f172a',
  fontFamily: 'inherit',
  fontSize: '14px',
  lineHeight: 1.6,
  resize: 'vertical',
  boxSizing: 'border-box',
};

const errorBannerStyle: CSSProperties = {
  padding: '12px 16px',
  borderRadius: '10px',
  backgroundColor: '#fef2f2',
  border: '1px solid #fecaca',
  color: '#dc2626',
  fontSize: '14px',
};

const warningBoxStyle: CSSProperties = {
  padding: '12px 16px',
  borderRadius: '10px',
  backgroundColor: '#fffbeb',
  border: '1px solid #fde68a',
  color: '#92400e',
  fontSize: '14px',
  lineHeight: 1.6,
};

const inlineLinkStyle: CSSProperties = {
  color: '#0f172a',
  textDecoration: 'none',
  fontWeight: 700,
};

const capabilityBoxStyle: CSSProperties = {
  padding: '14px',
  borderRadius: '14px',
  border: '1px solid #e2e8f0',
  backgroundColor: '#f8fafc',
  display: 'grid',
  gap: '10px',
};

function parseDomainsInput(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatDomainsInput(values: string[]): string {
  return values.join('\n');
}

function getSetupOverviewPath(mode: AccountFlowMode, accountKey: string): string {
  return mode === 'edit' ? getEditSetupPath(accountKey) : getCreateSetupPath(accountKey);
}

function getPersonalPath(mode: AccountFlowMode, accountKey: string): string {
  return mode === 'edit'
    ? getEditPersonalSetupPath(accountKey)
    : getCreatePersonalSetupPath(accountKey);
}

type AccountSetupGroupScreenProps = {
  mode: AccountFlowMode;
  account: ControlPlaneAccountDetail;
  group: SetupGroupDefinition;
};

export function AccountSetupGroupScreen({
  mode,
  account: initialAccount,
  group,
}: AccountSetupGroupScreenProps) {
  const router = useRouter();
  const [account, setAccount] = useState(initialAccount);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const [accessState, setAccessState] = useState<SaveCpAccessInput>({
    loginMethods: { ...initialAccount.access.loginMethods },
    mfaPolicy: { ...initialAccount.access.mfaPolicy },
    signupPolicy: {
      ...initialAccount.access.signupPolicy,
      allowedDomains: [...initialAccount.access.signupPolicy.allowedDomains],
    },
  });
  const [allowedDomainsInput, setAllowedDomainsInput] = useState(
    formatDomainsInput(initialAccount.access.signupPolicy.allowedDomains),
  );

  const [accountSettingsState, setAccountSettingsState] = useState<SaveCpAccountSettingsInput>({
    branding: { ...initialAccount.accountSettings.branding },
    organizationStructure: { ...initialAccount.accountSettings.organizationStructure },
    companyCalendar: { ...initialAccount.accountSettings.companyCalendar },
  });

  const [moduleState, setModuleState] = useState<SaveCpModuleSettingsInput>({
    modules: { ...initialAccount.moduleSettings.modules },
  });

  const [integrationsState, setIntegrationsState] = useState<SaveCpIntegrationsInput>({
    integrations: initialAccount.integrations.integrations.map((integration) => ({
      integrationKey: integration.integrationKey,
      isAllowed: integration.isAllowed,
      capabilities: integration.capabilities.map((capability) => ({
        capabilityKey: capability.capabilityKey,
        isAllowed: capability.isAllowed,
      })),
    })),
  });

  const setupOverviewPath = getSetupOverviewPath(mode, account.accountKey);
  const personalPath = getPersonalPath(mode, account.accountKey);
  const currentPath =
    mode === 'edit'
      ? `Accounts > Edit Account > Account Setup > ${group.title}`
      : `Accounts > Create Account > Account Setup > ${group.title}`;

  const accessWarnings = useMemo(() => {
    const warnings: string[] = [];
    const googleIntegration = integrationsState.integrations.find(
      (integration) => integration.integrationKey === 'integration.sso.google',
    );
    const microsoftIntegration = integrationsState.integrations.find(
      (integration) => integration.integrationKey === 'integration.sso.microsoft',
    );

    if (accessState.loginMethods.google && !googleIntegration?.isAllowed) {
      warnings.push(
        'Google login method requires Google SSO Integration to be allowed and saved first.',
      );
    }

    if (accessState.loginMethods.microsoft && !microsoftIntegration?.isAllowed) {
      warnings.push(
        'Microsoft login method requires Microsoft SSO Integration to be allowed and saved first.',
      );
    }

    return warnings;
  }, [accessState.loginMethods.google, accessState.loginMethods.microsoft, integrationsState]);

  const integrationWarnings = useMemo(() => {
    const warnings: string[] = [];
    const googleIntegration = integrationsState.integrations.find(
      (integration) => integration.integrationKey === 'integration.sso.google',
    );
    const microsoftIntegration = integrationsState.integrations.find(
      (integration) => integration.integrationKey === 'integration.sso.microsoft',
    );

    if (account.access.loginMethods.google && !googleIntegration?.isAllowed) {
      warnings.push(
        'Google SSO Integration cannot be disabled while Google login method remains enabled in Access, Identity & Security.',
      );
    }

    if (account.access.loginMethods.microsoft && !microsoftIntegration?.isAllowed) {
      warnings.push(
        'Microsoft SSO Integration cannot be disabled while Microsoft login method remains enabled in Access, Identity & Security.',
      );
    }

    return warnings;
  }, [
    account.access.loginMethods.google,
    account.access.loginMethods.microsoft,
    integrationsState,
  ]);

  async function runSave(
    action: () => Promise<ControlPlaneAccountDetail>,
    options?: { closeAfter?: boolean },
  ) {
    setIsSubmitting(true);
    setSubmitError(null);

    try {
      const nextAccount = await action();
      setAccount(nextAccount);
      setAccessState({
        loginMethods: { ...nextAccount.access.loginMethods },
        mfaPolicy: { ...nextAccount.access.mfaPolicy },
        signupPolicy: {
          ...nextAccount.access.signupPolicy,
          allowedDomains: [...nextAccount.access.signupPolicy.allowedDomains],
        },
      });
      setAllowedDomainsInput(formatDomainsInput(nextAccount.access.signupPolicy.allowedDomains));
      setAccountSettingsState({
        branding: { ...nextAccount.accountSettings.branding },
        organizationStructure: { ...nextAccount.accountSettings.organizationStructure },
        companyCalendar: { ...nextAccount.accountSettings.companyCalendar },
      });
      setModuleState({ modules: { ...nextAccount.moduleSettings.modules } });
      setIntegrationsState({
        integrations: nextAccount.integrations.integrations.map((integration) => ({
          integrationKey: integration.integrationKey,
          isAllowed: integration.isAllowed,
          capabilities: integration.capabilities.map((capability) => ({
            capabilityKey: capability.capabilityKey,
            isAllowed: capability.isAllowed,
          })),
        })),
      });

      if (options?.closeAfter) {
        router.push(setupOverviewPath);
        router.refresh();
        return;
      }

      router.refresh();
    } catch (error) {
      setSubmitError(
        error instanceof Error ? error.message : 'Unexpected error. Please try again.',
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  const footerActions: FooterAction[] = [
    {
      label: 'Back',
      href: setupOverviewPath,
      variant: 'ghost',
    },
    {
      label: isSubmitting ? 'Saving…' : 'Save',
      variant: 'secondary',
      disabled: isSubmitting,
      onClick: () => {
        if (group.slug === 'access-identity-security') {
          if (accessWarnings.length > 0) {
            setSubmitError(accessWarnings[0]);
            return;
          }

          const payload: SaveCpAccessInput = {
            loginMethods: { ...accessState.loginMethods },
            mfaPolicy: {
              adminRequired: true,
              memberRequired: accessState.mfaPolicy.memberRequired,
            },
            signupPolicy: {
              publicSignup: accessState.signupPolicy.publicSignup,
              adminInvitationsAllowed: accessState.signupPolicy.adminInvitationsAllowed,
              allowedDomains: parseDomainsInput(allowedDomainsInput),
            },
          };

          void runSave(() => saveCpAccess(account.accountKey, payload));
          return;
        }

        if (group.slug === 'account-settings') {
          void runSave(() => saveCpAccountSettings(account.accountKey, accountSettingsState));
          return;
        }

        if (group.slug === 'module-settings') {
          void runSave(() => saveCpModuleSettings(account.accountKey, moduleState));
          return;
        }

        if (integrationWarnings.length > 0) {
          setSubmitError(integrationWarnings[0]);
          return;
        }

        void runSave(() => saveCpIntegrations(account.accountKey, integrationsState));
      },
    },
    {
      label: 'Save & Close',
      variant: 'primary',
      disabled: isSubmitting,
      onClick: () => {
        if (group.slug === 'access-identity-security') {
          if (accessWarnings.length > 0) {
            setSubmitError(accessWarnings[0]);
            return;
          }

          const payload: SaveCpAccessInput = {
            loginMethods: { ...accessState.loginMethods },
            mfaPolicy: {
              adminRequired: true,
              memberRequired: accessState.mfaPolicy.memberRequired,
            },
            signupPolicy: {
              publicSignup: accessState.signupPolicy.publicSignup,
              adminInvitationsAllowed: accessState.signupPolicy.adminInvitationsAllowed,
              allowedDomains: parseDomainsInput(allowedDomainsInput),
            },
          };

          void runSave(() => saveCpAccess(account.accountKey, payload), { closeAfter: true });
          return;
        }

        if (group.slug === 'account-settings') {
          void runSave(() => saveCpAccountSettings(account.accountKey, accountSettingsState), {
            closeAfter: true,
          });
          return;
        }

        if (group.slug === 'module-settings') {
          void runSave(() => saveCpModuleSettings(account.accountKey, moduleState), {
            closeAfter: true,
          });
          return;
        }

        if (integrationWarnings.length > 0) {
          setSubmitError(integrationWarnings[0]);
          return;
        }

        void runSave(() => saveCpIntegrations(account.accountKey, integrationsState), {
          closeAfter: true,
        });
      },
    },
  ];

  function renderCheckboxRow(options: {
    label: string;
    description: string;
    checked: boolean;
    disabled?: boolean;
    onChange: (checked: boolean) => void;
  }) {
    return (
      <label style={rowStyle}>
        <input
          type="checkbox"
          checked={options.checked}
          disabled={options.disabled || isSubmitting}
          onChange={(event) => {
            setSubmitError(null);
            options.onChange(event.target.checked);
          }}
          style={checkboxStyle}
        />
        <div style={{ display: 'grid', gap: '4px' }}>
          <span style={valueStyle}>{options.label}</span>
          <p style={helperStyle}>{options.description}</p>
        </div>
      </label>
    );
  }

  function renderAccessSection() {
    return (
      <>
        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Login Methods</h2>
          <div style={formSectionStyle}>
            {renderCheckboxRow({
              label: 'Username & Password',
              description: 'Allow password-based login for this tenant.',
              checked: accessState.loginMethods.password,
              onChange: (checked) =>
                setAccessState((current) => ({
                  ...current,
                  loginMethods: { ...current.loginMethods, password: checked },
                })),
            })}
            {renderCheckboxRow({
              label: 'Google SSO',
              description: 'Requires the Google SSO Integration allowance to be enabled and saved.',
              checked: accessState.loginMethods.google,
              onChange: (checked) =>
                setAccessState((current) => ({
                  ...current,
                  loginMethods: { ...current.loginMethods, google: checked },
                })),
            })}
            {renderCheckboxRow({
              label: 'Microsoft SSO',
              description:
                'Requires the Microsoft SSO Integration allowance to be enabled and saved.',
              checked: accessState.loginMethods.microsoft,
              onChange: (checked) =>
                setAccessState((current) => ({
                  ...current,
                  loginMethods: { ...current.loginMethods, microsoft: checked },
                })),
            })}
          </div>
        </article>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>MFA Policy</h2>
          <div style={formSectionStyle}>
            {renderCheckboxRow({
              label: 'Admin MFA',
              description: 'Mandatory at CP level and intentionally locked on.',
              checked: true,
              disabled: true,
              onChange: () => undefined,
            })}
            {renderCheckboxRow({
              label: 'Member MFA',
              description: 'CP-owned policy toggle for member MFA requirement.',
              checked: accessState.mfaPolicy.memberRequired,
              onChange: (checked) =>
                setAccessState((current) => ({
                  ...current,
                  mfaPolicy: { ...current.mfaPolicy, memberRequired: checked },
                })),
            })}
          </div>
        </article>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Signup & Invite Policy</h2>
          <div style={formSectionStyle}>
            {renderCheckboxRow({
              label: 'Public Signup',
              description: 'Allow self-service signup when tenant policy permits it.',
              checked: accessState.signupPolicy.publicSignup,
              onChange: (checked) =>
                setAccessState((current) => ({
                  ...current,
                  signupPolicy: { ...current.signupPolicy, publicSignup: checked },
                })),
            })}
            {renderCheckboxRow({
              label: 'Admin Invitations Allowed',
              description: 'Allow workspace admins to invite users directly.',
              checked: accessState.signupPolicy.adminInvitationsAllowed,
              onChange: (checked) =>
                setAccessState((current) => ({
                  ...current,
                  signupPolicy: { ...current.signupPolicy, adminInvitationsAllowed: checked },
                })),
            })}
            <div style={{ display: 'grid', gap: '8px' }}>
              <label style={labelStyle}>Allowed Domains</label>
              <textarea
                value={allowedDomainsInput}
                onChange={(event) => {
                  setSubmitError(null);
                  setAllowedDomainsInput(event.target.value);
                }}
                disabled={isSubmitting}
                style={textareaStyle}
                placeholder="Enter one domain per line, for example:@goodwill.org"
              />
              <p style={helperStyle}>
                Optional list. Save-time normalization trims whitespace, lowercases values, and
                removes duplicates.
              </p>
            </div>
          </div>
        </article>
      </>
    );
  }

  function renderAccountSettingsSection() {
    return (
      <>
        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Branding</h2>
          <div style={formSectionStyle}>
            {renderCheckboxRow({
              label: 'Logo',
              description: 'Allow tenant-side logo configuration later in Hubins.',
              checked: accountSettingsState.branding.logo,
              onChange: (checked) =>
                setAccountSettingsState((current) => ({
                  ...current,
                  branding: { ...current.branding, logo: checked },
                })),
            })}
            {renderCheckboxRow({
              label: 'Menu Color',
              description: 'Allow tenant-side navigation color customization.',
              checked: accountSettingsState.branding.menuColor,
              onChange: (checked) =>
                setAccountSettingsState((current) => ({
                  ...current,
                  branding: { ...current.branding, menuColor: checked },
                })),
            })}
            {renderCheckboxRow({
              label: 'Font Color',
              description: 'Allow tenant-side font color customization.',
              checked: accountSettingsState.branding.fontColor,
              onChange: (checked) =>
                setAccountSettingsState((current) => ({
                  ...current,
                  branding: { ...current.branding, fontColor: checked },
                })),
            })}
            {renderCheckboxRow({
              label: 'Welcome Message',
              description: 'Allow tenant-side welcome copy configuration.',
              checked: accountSettingsState.branding.welcomeMessage,
              onChange: (checked) =>
                setAccountSettingsState((current) => ({
                  ...current,
                  branding: { ...current.branding, welcomeMessage: checked },
                })),
            })}
          </div>
        </article>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Organization Structure</h2>
          <div style={formSectionStyle}>
            {renderCheckboxRow({
              label: 'Employers',
              description: 'Allow tenant-side employer list management.',
              checked: accountSettingsState.organizationStructure.employers,
              onChange: (checked) =>
                setAccountSettingsState((current) => ({
                  ...current,
                  organizationStructure: {
                    ...current.organizationStructure,
                    employers: checked,
                  },
                })),
            })}
            {renderCheckboxRow({
              label: 'Locations',
              description: 'Allow tenant-side location list management.',
              checked: accountSettingsState.organizationStructure.locations,
              onChange: (checked) =>
                setAccountSettingsState((current) => ({
                  ...current,
                  organizationStructure: {
                    ...current.organizationStructure,
                    locations: checked,
                  },
                })),
            })}
          </div>
        </article>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Company Calendar</h2>
          {renderCheckboxRow({
            label: 'Company Calendar',
            description: 'Allow tenant-side company calendar configuration.',
            checked: accountSettingsState.companyCalendar.allowed,
            onChange: (checked) =>
              setAccountSettingsState((current) => ({
                ...current,
                companyCalendar: { allowed: checked },
              })),
          })}
        </article>
      </>
    );
  }

  function renderModuleSettingsSection() {
    return (
      <>
        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Available Modules</h2>
          <div style={formSectionStyle}>
            {renderCheckboxRow({
              label: 'Personal',
              description:
                'The only live configurable module in this phase. Its Personal sub-page must be saved before Module Settings is treated as configured.',
              checked: moduleState.modules.personal,
              onChange: (checked) =>
                setModuleState((current) => ({
                  modules: { ...current.modules, personal: checked },
                })),
            })}
            {renderCheckboxRow({
              label: 'Documents',
              description: 'Future placeholder module. No CP sub-page in this phase.',
              checked: moduleState.modules.documents,
              onChange: (checked) =>
                setModuleState((current) => ({
                  modules: { ...current.modules, documents: checked },
                })),
            })}
            {renderCheckboxRow({
              label: 'Benefits',
              description: 'Future placeholder module. No CP sub-page in this phase.',
              checked: moduleState.modules.benefits,
              onChange: (checked) =>
                setModuleState((current) => ({
                  modules: { ...current.modules, benefits: checked },
                })),
            })}
            {renderCheckboxRow({
              label: 'Payments',
              description: 'Future placeholder module. No CP sub-page in this phase.',
              checked: moduleState.modules.payments,
              onChange: (checked) =>
                setModuleState((current) => ({
                  modules: { ...current.modules, payments: checked },
                })),
            })}
          </div>
        </article>

        <article style={insetPanelStyle}>
          <strong>Personal CP sub-page</strong>
          <p style={mutedTextStyle}>
            {account.moduleSettings.personalSubpageSaved
              ? 'Personal catalog decisions have already been saved for this account.'
              : 'If Personal remains enabled, the Personal CP sub-page must be explicitly saved before Module Settings becomes configured.'}
          </p>
          {moduleState.modules.personal ? (
            <a href={personalPath} style={inlineLinkStyle}>
              Open Personal CP sub-page →
            </a>
          ) : (
            <p style={helperStyle}>
              Personal is currently disabled, so no Personal save is required.
            </p>
          )}
        </article>
      </>
    );
  }

  function renderIntegrationsSection() {
    return (
      <article style={contentPanelStyle}>
        <h2 style={sectionTitleStyle}>Integrations & Marketplace</h2>
        <div style={formSectionStyle}>
          {account.integrations.integrations.map((integration) => {
            const stateIntegration = integrationsState.integrations.find(
              (item) => item.integrationKey === integration.integrationKey,
            ) as SaveCpIntegrationsInput['integrations'][number];

            return (
              <div key={integration.integrationKey} style={capabilityBoxStyle}>
                {renderCheckboxRow({
                  label: integration.label,
                  description:
                    integration.capabilities.length > 0
                      ? 'Use the child capabilities below when this integration is allowed.'
                      : 'Integration surface only. No child capabilities in this phase.',
                  checked: stateIntegration.isAllowed,
                  onChange: (checked) =>
                    setIntegrationsState((current) => ({
                      integrations: current.integrations.map((item) =>
                        item.integrationKey === integration.integrationKey
                          ? {
                              ...item,
                              isAllowed: checked,
                              capabilities: item.capabilities.map((capability) => ({
                                ...capability,
                                isAllowed: checked ? capability.isAllowed : false,
                              })),
                            }
                          : item,
                      ),
                    })),
                })}

                {integration.capabilities.length > 0 ? (
                  <div style={{ display: 'grid', gap: '10px', paddingLeft: '26px' }}>
                    {integration.capabilities.map((capability) => {
                      const stateCapability = stateIntegration.capabilities.find(
                        (item) => item.capabilityKey === capability.capabilityKey,
                      );

                      return renderCheckboxRow({
                        label: capability.label,
                        description: 'Capability-level CP allowance for this integration.',
                        checked: stateCapability?.isAllowed ?? false,
                        disabled: !stateIntegration.isAllowed,
                        onChange: (checked) =>
                          setIntegrationsState((current) => ({
                            integrations: current.integrations.map((item) =>
                              item.integrationKey === integration.integrationKey
                                ? {
                                    ...item,
                                    capabilities: item.capabilities.map((currentCapability) =>
                                      currentCapability.capabilityKey === capability.capabilityKey
                                        ? { ...currentCapability, isAllowed: checked }
                                        : currentCapability,
                                    ),
                                  }
                                : item,
                            ),
                          })),
                      });
                    })}
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>
      </article>
    );
  }

  return (
    <ControlPlaneShell
      currentPath={currentPath}
      pageTitle={group.title}
      pageDescription="Step 2 group saves now persist real CP allowance truth, configured state, and Step 2 progress."
      footerActions={footerActions}
      account={account}
      step={{ stepNumber: 2, stepName: 'Account Setup' }}
      showStepProgress
    >
      <section style={sectionGridStyle}>
        <div style={infoGridStyle}>
          <article style={infoCardStyle}>
            <p style={labelStyle}>Group status</p>
            <p style={valueStyle}>
              {account.step2Progress.groups.find((item) => item.slug === group.slug)?.configured
                ? 'Configured'
                : 'Needs save'}
            </p>
          </article>

          <article style={infoCardStyle}>
            <p style={labelStyle}>Required</p>
            <p style={valueStyle}>{group.isRequired ? 'Yes' : 'No'}</p>
          </article>

          <article style={infoCardStyle}>
            <p style={labelStyle}>Current revision</p>
            <p style={valueStyle}>{account.cpRevision}</p>
          </article>
        </div>

        <article style={insetPanelStyle}>
          <strong>Group purpose</strong>
          <p style={mutedTextStyle}>{group.description}</p>
        </article>

        {submitError ? <div style={errorBannerStyle}>{submitError}</div> : null}

        {group.slug === 'access-identity-security' && accessWarnings.length > 0 ? (
          <div style={warningBoxStyle}>{accessWarnings.join(' ')}</div>
        ) : null}

        {group.slug === 'integrations-marketplace' && integrationWarnings.length > 0 ? (
          <div style={warningBoxStyle}>{integrationWarnings.join(' ')}</div>
        ) : null}

        {group.slug === 'access-identity-security' ? renderAccessSection() : null}
        {group.slug === 'account-settings' ? renderAccountSettingsSection() : null}
        {group.slug === 'module-settings' ? renderModuleSettingsSection() : null}
        {group.slug === 'integrations-marketplace' ? renderIntegrationsSection() : null}
      </section>
    </ControlPlaneShell>
  );
}
