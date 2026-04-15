'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import type { CSSProperties } from 'react';
import type { FooterAction } from '../contracts';
import { createCpAccount } from '../cp-accounts-client';
import { getAccountsListPath, getCreateSetupPath } from '@/shared/cp/links';
import {
  contentPanelStyle,
  insetPanelStyle,
  labelStyle,
  mutedTextStyle,
  sectionGridStyle,
  sectionTitleStyle,
} from '@/shared/cp/styles';
import { ControlPlaneShell } from '@/shared/cp/components/control-plane-shell';

const fieldGroupStyle: CSSProperties = {
  display: 'grid',
  gap: '24px',
};

const fieldStyle: CSSProperties = {
  display: 'grid',
  gap: '6px',
};

const inputStyle: CSSProperties = {
  width: '100%',
  padding: '10px 12px',
  fontSize: '15px',
  fontFamily: 'inherit',
  border: '1px solid #cbd5e1',
  borderRadius: '8px',
  backgroundColor: '#fff',
  color: '#0f172a',
  outline: 'none',
  boxSizing: 'border-box',
};

const inputErrorStyle: CSSProperties = {
  ...inputStyle,
  borderColor: '#ef4444',
};

const inputHintStyle: CSSProperties = {
  fontSize: '12px',
  color: '#64748b',
  marginTop: '2px',
};

const errorTextStyle: CSSProperties = {
  fontSize: '13px',
  color: '#dc2626',
  marginTop: '4px',
};

const errorBannerStyle: CSSProperties = {
  padding: '12px 16px',
  borderRadius: '8px',
  backgroundColor: '#fef2f2',
  border: '1px solid #fecaca',
  color: '#dc2626',
  fontSize: '14px',
};

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
}

const ACCOUNT_KEY_REGEX = /^[a-z0-9-]+$/;

function validateFields(
  name: string,
  key: string,
): { nameError: string | null; keyError: string | null } {
  const nameError = name.trim().length === 0 ? 'Account name is required.' : null;

  let keyError: string | null = null;
  if (key.trim().length === 0) {
    keyError = 'Account key is required.';
  } else if (!ACCOUNT_KEY_REGEX.test(key)) {
    keyError = 'Account key must contain only lowercase letters, digits, and hyphens.';
  } else if (key.length > 100) {
    keyError = 'Account key must be 100 characters or fewer.';
  }

  return { nameError, keyError };
}

export function AccountBasicInfoScreen() {
  const router = useRouter();

  const [name, setName] = useState('');
  const [key, setKey] = useState('');
  const [keyManuallyEdited, setKeyManuallyEdited] = useState(false);
  const [nameError, setNameError] = useState<string | null>(null);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!keyManuallyEdited) {
      setKey(slugify(name));
    }
  }, [name, keyManuallyEdited]);

  async function handleSubmit() {
    const trimmedName = name.trim();
    const trimmedKey = key.trim();

    const { nameError: nextNameError, keyError: nextKeyError } = validateFields(
      trimmedName,
      trimmedKey,
    );

    setNameError(nextNameError);
    setKeyError(nextKeyError);

    if (nextNameError || nextKeyError) {
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      const account = await createCpAccount({
        accountName: trimmedName,
        accountKey: trimmedKey,
      });

      router.push(getCreateSetupPath(account.accountKey));
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Unexpected error. Please try again.';

      if (message.toLowerCase().includes('account key')) {
        setKeyError(message);
      } else {
        setSubmitError(message);
      }
    } finally {
      setIsSubmitting(false);
    }
  }

  const footerActions: FooterAction[] = [
    {
      label: 'Cancel',
      href: getAccountsListPath(),
      variant: 'ghost',
    },
    {
      label: isSubmitting ? 'Creating…' : 'Continue →',
      variant: 'primary',
      disabled: isSubmitting,
      onClick: () => {
        void handleSubmit();
      },
    },
  ];

  return (
    <ControlPlaneShell
      currentPath="Accounts > Create Account"
      pageTitle="Basic Account Info"
      pageDescription="Create the draft account identity first. Step 2 persists the real CP allowance truth and progress state."
      footerActions={footerActions}
      step={{ stepNumber: 1, stepName: 'Basic Account Info' }}
    >
      <section style={sectionGridStyle}>
        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Step 1 of 3 — Basic Account Info</h2>

          {submitError ? <div style={errorBannerStyle}>{submitError}</div> : null}

          <div style={fieldGroupStyle}>
            <div style={fieldStyle}>
              <label htmlFor="accountName" style={labelStyle}>
                Account Name <span style={{ color: '#dc2626' }}>*</span>
              </label>
              <input
                id="accountName"
                type="text"
                value={name}
                onChange={(event) => {
                  setName(event.target.value);
                  setNameError(null);
                  setSubmitError(null);
                }}
                placeholder="e.g. GoodWill CA"
                disabled={isSubmitting}
                style={nameError ? inputErrorStyle : inputStyle}
                autoComplete="off"
                autoFocus
              />
              {nameError ? <p style={errorTextStyle}>{nameError}</p> : null}
            </div>

            <div style={fieldStyle}>
              <label htmlFor="accountKey" style={labelStyle}>
                Account Key <span style={{ color: '#dc2626' }}>*</span>
              </label>
              <input
                id="accountKey"
                type="text"
                value={key}
                onChange={(event) => {
                  setKey(event.target.value);
                  setKeyManuallyEdited(true);
                  setKeyError(null);
                  setSubmitError(null);
                }}
                placeholder="e.g. goodwill-ca"
                disabled={isSubmitting}
                style={keyError ? inputErrorStyle : inputStyle}
                autoComplete="off"
                spellCheck={false}
              />
              {keyError ? (
                <p style={errorTextStyle}>{keyError}</p>
              ) : (
                <p style={inputHintStyle}>
                  Lowercase letters, digits, and hyphens only. The Account Key stays immutable after
                  creation.
                </p>
              )}
            </div>
          </div>
        </article>

        <article style={insetPanelStyle}>
          <strong>Locked identity boundary</strong>
          <p style={mutedTextStyle}>
            Step 1 contains only Account Name and Account Key. Later CP phases may add more operator
            tooling, but identity remains name + key only in the locked model.
          </p>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
