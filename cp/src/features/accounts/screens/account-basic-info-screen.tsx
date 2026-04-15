'use client';

/**
 * cp/src/features/accounts/screens/account-basic-info-screen.tsx
 *
 * WHY:
 * - Step 1 of the locked 3-step CP create flow.
 * - Provides the real account name + account key form.
 * - On submit: POST /api/cp/accounts → navigate to the Account Setup step.
 *
 * RULES:
 * - Client Component ('use client') — form interaction requires browser state.
 * - No hardcoded backend origin. All API calls go through /api/* proxy.
 * - Account key auto-slugs from account name while the operator has not
 *   manually edited the key field. Manual edits lock the key from auto-update.
 * - Locked CP identity: account name + account key only. No other fields.
 * - Edit mode is not a valid surface for this screen (redirected at page level).
 *
 * CP Phase 2 scope:
 * - Create mode: form submission → POST /api/cp/accounts → navigate to setup.
 * - Edit mode: unsupported here; page redirects before rendering this screen.
 */

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import type { CSSProperties } from 'react';
import type { FooterAction } from '../contracts';
import { getAccountsListPath, getEditSetupPath } from '@/shared/cp/links';
import {
  contentPanelStyle,
  insetPanelStyle,
  labelStyle,
  mutedTextStyle,
  sectionGridStyle,
  sectionTitleStyle,
} from '@/shared/cp/styles';
import { ControlPlaneShell } from '@/shared/cp/components/control-plane-shell';

// ─── Styles ──────────────────────────────────────────────────────────────────

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

// ─── Slugify helper ───────────────────────────────────────────────────────────

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// ─── Validation ───────────────────────────────────────────────────────────────

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

// ─── Component ───────────────────────────────────────────────────────────────

export function AccountBasicInfoScreen() {
  const router = useRouter();

  const [name, setName] = useState('');
  const [key, setKey] = useState('');
  const [keyManuallyEdited, setKeyManuallyEdited] = useState(false);

  const [nameError, setNameError] = useState<string | null>(null);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const keyInputRef = useRef<HTMLInputElement>(null);

  // Auto-slug key from name while key has not been manually edited.
  useEffect(() => {
    if (!keyManuallyEdited) {
      setKey(slugify(name));
    }
  }, [name, keyManuallyEdited]);

  function handleNameChange(e: React.ChangeEvent<HTMLInputElement>) {
    setName(e.target.value);
    setNameError(null);
    setSubmitError(null);
  }

  function handleKeyChange(e: React.ChangeEvent<HTMLInputElement>) {
    setKey(e.target.value);
    setKeyManuallyEdited(true);
    setKeyError(null);
    setSubmitError(null);
  }

  async function handleSubmit() {
    const trimmedName = name.trim();
    const trimmedKey = key.trim();

    const { nameError: ne, keyError: ke } = validateFields(trimmedName, trimmedKey);
    setNameError(ne);
    setKeyError(ke);

    if (ne || ke) return;

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      const res = await fetch('/api/cp/accounts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ accountName: trimmedName, accountKey: trimmedKey }),
      });

      if (res.status === 409) {
        const body = (await res.json()) as { message?: string };
        setKeyError(body.message ?? 'Account key is already taken.');
        return;
      }

      if (!res.ok) {
        const body = (await res.json()) as { message?: string };
        setSubmitError(body.message ?? `Unexpected error (${res.status}). Please try again.`);
        return;
      }

      const account = (await res.json()) as { accountKey: string };
      router.push(getEditSetupPath(account.accountKey));
    } catch {
      setSubmitError('Network error. Please check your connection and try again.');
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
      pageDescription="Create the account identity first. Settings and modules are configured next."
      footerActions={footerActions}
      step={{ stepNumber: 1, stepName: 'Basic Account Info' }}
    >
      <section style={sectionGridStyle}>
        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Step 1 of 3 — Basic Account Info</h2>

          {submitError && (
            <div style={{ ...errorBannerStyle, marginBottom: '20px' }}>{submitError}</div>
          )}

          <div style={fieldGroupStyle}>
            <div style={fieldStyle}>
              <label htmlFor="accountName" style={labelStyle}>
                Account Name <span style={{ color: '#dc2626' }}>*</span>
              </label>
              <input
                id="accountName"
                type="text"
                value={name}
                onChange={handleNameChange}
                placeholder="e.g. Goodwill CA"
                disabled={isSubmitting}
                style={nameError ? inputErrorStyle : inputStyle}
                autoComplete="off"
                autoFocus
              />
              {nameError && <p style={errorTextStyle}>{nameError}</p>}
            </div>

            <div style={fieldStyle}>
              <label htmlFor="accountKey" style={labelStyle}>
                Account Key <span style={{ color: '#dc2626' }}>*</span>
              </label>
              <input
                id="accountKey"
                ref={keyInputRef}
                type="text"
                value={key}
                onChange={handleKeyChange}
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
                  Lowercase letters, digits, and hyphens only. Cannot be changed after creation.
                </p>
              )}
            </div>
          </div>
        </article>

        <article style={insetPanelStyle}>
          <strong>Account identity is permanent</strong>
          <p style={mutedTextStyle}>
            Account Name and Account Key are the only identity fields in this step. The Account Key
            cannot be changed after creation. Settings and module configuration happen in Step 2.
          </p>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
