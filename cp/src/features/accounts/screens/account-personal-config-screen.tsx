'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import type { CSSProperties } from 'react';
import type {
  AccountFlowMode,
  ControlPlaneAccountDetail,
  CpPersonalFamily,
  CpPersonalField,
  FooterAction,
  SaveCpPersonalInput,
} from '../contracts';
import { saveCpPersonal } from '../cp-accounts-client';
import { getCreateSetupGroupPath, getEditSetupGroupPath } from '@/shared/cp/links';
import {
  infoCardStyle,
  infoGridStyle,
  insetPanelStyle,
  labelStyle,
  mutedTextStyle,
  sectionGridStyle,
  sectionTitleStyle,
  tableCellStyle,
  tableStyle,
  valueStyle,
} from '@/shared/cp/styles';
import { ControlPlaneShell } from '@/shared/cp/components/control-plane-shell';

const familyCardStyle: CSSProperties = {
  padding: '18px',
  borderRadius: '16px',
  border: '1px solid #e2e8f0',
  backgroundColor: '#ffffff',
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

const tagStyle = (variant: 'neutral' | 'green' | 'amber'): CSSProperties => ({
  display: 'inline-flex',
  width: 'fit-content',
  padding: '5px 10px',
  borderRadius: '999px',
  fontSize: '12px',
  fontWeight: 700,
  backgroundColor: variant === 'green' ? '#dcfce7' : variant === 'amber' ? '#fef3c7' : '#e2e8f0',
  color: variant === 'green' ? '#166534' : variant === 'amber' ? '#92400e' : '#334155',
});

const helperStyle: CSSProperties = {
  margin: 0,
  fontSize: '13px',
  color: '#64748b',
  lineHeight: 1.6,
};

const errorBannerStyle: CSSProperties = {
  padding: '12px 16px',
  borderRadius: '10px',
  backgroundColor: '#fef2f2',
  border: '1px solid #fecaca',
  color: '#dc2626',
  fontSize: '14px',
};

const tableHeaderCellStyle: CSSProperties = {
  ...tableCellStyle,
  borderTop: 'none',
  fontSize: '12px',
  fontWeight: 700,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: '#64748b',
};

function getModuleSettingsPath(mode: AccountFlowMode, accountKey: string): string {
  return mode === 'edit'
    ? getEditSetupGroupPath(accountKey, 'module-settings')
    : getCreateSetupGroupPath('module-settings', accountKey);
}

function cloneFamilies(families: CpPersonalFamily[]): CpPersonalFamily[] {
  return families.map((family) => ({
    ...family,
    fields: family.fields.map((field) => ({ ...field })),
  }));
}

type AccountPersonalConfigScreenProps = {
  mode: AccountFlowMode;
  account: ControlPlaneAccountDetail;
};

export function AccountPersonalConfigScreen({
  mode,
  account: initialAccount,
}: AccountPersonalConfigScreenProps) {
  const router = useRouter();
  const [account, setAccount] = useState(initialAccount);
  const [families, setFamilies] = useState(() => cloneFamilies(initialAccount.personal.families));
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const moduleSettingsPath = getModuleSettingsPath(mode, account.accountKey);
  const currentPath =
    mode === 'edit'
      ? 'Accounts > Edit Account > Account Setup > Module Settings > Personal'
      : 'Accounts > Create Account > Account Setup > Module Settings > Personal';

  function updateFamily(familyKey: CpPersonalFamily['familyKey'], nextAllowed: boolean) {
    setSubmitError(null);
    setFamilies((currentFamilies) =>
      currentFamilies.map((family) => {
        if (family.familyKey !== familyKey) {
          return family;
        }

        if (family.allowedLocked) {
          return family;
        }

        return {
          ...family,
          isAllowed: nextAllowed,
          fields: family.fields.map((field) => {
            if (field.isSystemManaged || field.allowedLocked) {
              return field;
            }

            return {
              ...field,
              isAllowed: nextAllowed ? field.isAllowed : false,
              defaultSelected: nextAllowed ? field.defaultSelected : false,
            };
          }),
        };
      }),
    );
  }

  function updateField(
    familyKey: CpPersonalFamily['familyKey'],
    fieldKey: CpPersonalField['fieldKey'],
    patch: Partial<Pick<CpPersonalField, 'isAllowed' | 'defaultSelected'>>,
  ) {
    setSubmitError(null);
    setFamilies((currentFamilies) =>
      currentFamilies.map((family) => {
        if (family.familyKey !== familyKey) {
          return family;
        }

        return {
          ...family,
          fields: family.fields.map((field) => {
            if (field.fieldKey !== fieldKey) {
              return field;
            }

            if (field.isSystemManaged || field.allowedLocked) {
              return field;
            }

            const nextAllowed = patch.isAllowed ?? field.isAllowed;
            const nextDefaultSelected = nextAllowed
              ? (patch.defaultSelected ?? field.defaultSelected)
              : false;

            return {
              ...field,
              isAllowed: nextAllowed,
              defaultSelected: nextDefaultSelected,
            };
          }),
        };
      }),
    );
  }

  async function submit(closeAfter: boolean) {
    setIsSubmitting(true);
    setSubmitError(null);

    const payload: SaveCpPersonalInput = {
      families: families.map((family) => ({
        familyKey: family.familyKey,
        isAllowed: family.isAllowed,
      })),
      fields: families
        .flatMap((family) => family.fields)
        .filter((field) => !field.isSystemManaged)
        .map((field) => ({
          fieldKey: field.fieldKey,
          isAllowed: field.isAllowed,
          defaultSelected: field.defaultSelected,
        })),
    };

    try {
      const nextAccount = await saveCpPersonal(account.accountKey, payload);
      setAccount(nextAccount);
      setFamilies(cloneFamilies(nextAccount.personal.families));

      if (closeAfter) {
        router.push(moduleSettingsPath);
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
      href: moduleSettingsPath,
      variant: 'ghost',
    },
    {
      label: isSubmitting ? 'Saving…' : 'Save',
      variant: 'secondary',
      disabled: isSubmitting,
      onClick: () => {
        void submit(false);
      },
    },
    {
      label: 'Save & Close',
      variant: 'primary',
      disabled: isSubmitting,
      onClick: () => {
        void submit(true);
      },
    },
  ];

  return (
    <ControlPlaneShell
      currentPath={currentPath}
      pageTitle="Personal CP field configuration"
      pageDescription="Define the allowed Personal families and allowed/default-selected Personal fields. This explicit save is required before Module Settings is configured when Personal is enabled."
      footerActions={footerActions}
      account={account}
      step={{ stepNumber: 2, stepName: 'Account Setup' }}
      showStepProgress
    >
      <section style={sectionGridStyle}>
        <div style={infoGridStyle}>
          <article style={infoCardStyle}>
            <p style={labelStyle}>Personal save state</p>
            <p style={valueStyle}>{account.personal.saved ? 'Saved' : 'Not yet saved'}</p>
          </article>
          <article style={infoCardStyle}>
            <p style={labelStyle}>Module Settings state</p>
            <p style={valueStyle}>{account.moduleSettings.configured ? 'Configured' : 'Blocked'}</p>
          </article>
          <article style={infoCardStyle}>
            <p style={labelStyle}>Current revision</p>
            <p style={valueStyle}>{account.cpRevision}</p>
          </article>
        </div>

        <article style={insetPanelStyle}>
          <strong>Locked rules</strong>
          <p style={mutedTextStyle}>
            Default Selected is valid only when Allowed is true. Unchecking Allowed clears Default
            Selected. System ID remains auto/system-managed and read-only.
          </p>
        </article>

        {submitError ? <div style={errorBannerStyle}>{submitError}</div> : null}

        {families.map((family) => (
          <article key={family.familyKey} style={familyCardStyle}>
            <div style={{ display: 'grid', gap: '8px' }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                <h2 style={sectionTitleStyle}>{family.label}</h2>
                <span style={tagStyle(family.isAllowed ? 'green' : 'neutral')}>
                  {family.isAllowed ? 'Allowed' : 'Not allowed'}
                </span>
                {family.allowedLocked ? (
                  <span style={tagStyle('amber')}>Locked by baseline</span>
                ) : null}
              </div>

              <label style={rowStyle}>
                <input
                  type="checkbox"
                  checked={family.isAllowed}
                  disabled={family.allowedLocked || isSubmitting}
                  onChange={(event) => updateFamily(family.familyKey, event.target.checked)}
                  style={checkboxStyle}
                />
                <div style={{ display: 'grid', gap: '4px' }}>
                  <span style={valueStyle}>Allow this family</span>
                  <p style={helperStyle}>
                    Family-level allow/deny controls whether non-locked fields in this family may be
                    used.
                  </p>
                </div>
              </label>
            </div>

            <div style={{ overflowX: 'auto' }}>
              <table style={tableStyle}>
                <thead>
                  <tr>
                    <th style={tableHeaderCellStyle}>Field</th>
                    <th style={tableHeaderCellStyle}>Allowed</th>
                    <th style={tableHeaderCellStyle}>Default Selected</th>
                    <th style={tableHeaderCellStyle}>Notes</th>
                  </tr>
                </thead>
                <tbody>
                  {family.fields.map((field) => (
                    <tr key={field.fieldKey}>
                      <td style={tableCellStyle}>
                        <div style={{ display: 'grid', gap: '6px' }}>
                          <span style={valueStyle}>{field.label}</span>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                            {field.minimumRequired === 'required' ? (
                              <span style={tagStyle('amber')}>Required baseline</span>
                            ) : null}
                            {field.isSystemManaged ? (
                              <span style={tagStyle('neutral')}>System managed</span>
                            ) : null}
                          </div>
                        </div>
                      </td>
                      <td style={tableCellStyle}>
                        <input
                          type="checkbox"
                          checked={field.isAllowed}
                          disabled={
                            isSubmitting ||
                            field.isSystemManaged ||
                            field.allowedLocked ||
                            !family.isAllowed
                          }
                          onChange={(event) =>
                            updateField(family.familyKey, field.fieldKey, {
                              isAllowed: event.target.checked,
                            })
                          }
                          style={checkboxStyle}
                        />
                      </td>
                      <td style={tableCellStyle}>
                        <input
                          type="checkbox"
                          checked={field.defaultSelected}
                          disabled={
                            isSubmitting ||
                            field.isSystemManaged ||
                            !field.isAllowed ||
                            !family.isAllowed
                          }
                          onChange={(event) =>
                            updateField(family.familyKey, field.fieldKey, {
                              defaultSelected: event.target.checked,
                            })
                          }
                          style={checkboxStyle}
                        />
                      </td>
                      <td style={tableCellStyle}>{field.notes}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </article>
        ))}
      </section>
    </ControlPlaneShell>
  );
}
