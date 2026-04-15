'use client';

import type { CSSProperties } from 'react';
import { useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import type {
  AccountFlowMode,
  ControlPlaneAccountReview,
  CpStatus,
  FooterAction,
  PublishCpAccountInput,
} from '../contracts';
import { publishCpAccount } from '../cp-accounts-client';
import { getCreateSetupPath, getEditSetupPath } from '@/shared/cp/links';
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

const checklistStyle: CSSProperties = {
  display: 'grid',
  gap: '10px',
};

const checklistRowStyle = (complete: boolean): CSSProperties => ({
  display: 'flex',
  alignItems: 'flex-start',
  gap: '10px',
  color: complete ? '#166534' : '#991b1b',
  fontWeight: 600,
  fontSize: '14px',
});

const checklistDotStyle = (complete: boolean): CSSProperties => ({
  width: '10px',
  height: '10px',
  borderRadius: '999px',
  backgroundColor: complete ? '#22c55e' : '#ef4444',
  flexShrink: 0,
  marginTop: '6px',
});

const sectionBlockStyle: CSSProperties = {
  display: 'grid',
  gap: '14px',
};

const reviewSectionStyle: CSSProperties = {
  border: '1px solid #e2e8f0',
  borderRadius: '16px',
  padding: '16px',
  backgroundColor: '#ffffff',
  display: 'grid',
  gap: '10px',
};

const reviewLinesGridStyle: CSSProperties = {
  display: 'grid',
  gap: '10px',
  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
};

const lineLabelStyle: CSSProperties = {
  margin: 0,
  color: '#64748b',
  fontSize: '12px',
  fontWeight: 700,
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
};

const lineValueStyle: CSSProperties = {
  margin: 0,
  color: '#0f172a',
  fontSize: '14px',
  fontWeight: 600,
};

const statusGridStyle: CSSProperties = {
  display: 'grid',
  gap: '12px',
  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
};

const statusCardStyle = (selected: boolean, disabled: boolean): CSSProperties => ({
  padding: '16px',
  borderRadius: '16px',
  border: `1px solid ${selected ? '#2563eb' : '#e2e8f0'}`,
  backgroundColor: disabled ? '#f8fafc' : '#ffffff',
  display: 'grid',
  gap: '8px',
  cursor: disabled ? 'not-allowed' : 'pointer',
  opacity: disabled ? 0.7 : 1,
  boxShadow: selected ? '0 0 0 2px rgba(37, 99, 235, 0.15)' : 'none',
});

const statusTitleRowStyle: CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  gap: '10px',
};

const badgeStyle = (tone: 'blue' | 'slate' | 'red' | 'green'): CSSProperties => {
  const colorMap: Record<typeof tone, { bg: string; fg: string }> = {
    blue: { bg: '#dbeafe', fg: '#1d4ed8' },
    slate: { bg: '#e2e8f0', fg: '#0f172a' },
    red: { bg: '#fee2e2', fg: '#991b1b' },
    green: { bg: '#dcfce7', fg: '#166534' },
  };

  return {
    display: 'inline-flex',
    padding: '6px 10px',
    borderRadius: '999px',
    backgroundColor: colorMap[tone].bg,
    color: colorMap[tone].fg,
    fontSize: '12px',
    fontWeight: 800,
    letterSpacing: '0.02em',
  };
};

function formatDate(value: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function defaultTargetStatus(cpStatus: CpStatus, isReady: boolean): Exclude<CpStatus, 'Draft'> {
  if (cpStatus === 'Active' || cpStatus === 'Disabled') {
    return cpStatus;
  }

  return isReady ? 'Active' : 'Disabled';
}

export function AccountReviewScreen({
  mode,
  review: initialReview,
}: {
  mode: AccountFlowMode;
  review: ControlPlaneAccountReview;
}) {
  const router = useRouter();
  const [review, setReview] = useState<ControlPlaneAccountReview>(initialReview);
  const [targetStatus, setTargetStatus] = useState<Exclude<CpStatus, 'Draft'>>(() =>
    defaultTargetStatus(review.account.cpStatus, review.activationReadiness.isReady),
  );
  const [isPublishing, setIsPublishing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const account = review.account;
  const isEditMode = mode === 'edit';

  const activeBlocked = !review.activationReadiness.isReady;

  const provisioningBadge = useMemo(() => {
    if (!review.provisioning.isProvisioned) {
      return { label: 'Not provisioned', tone: 'slate' as const };
    }

    return review.provisioning.tenantState === 'ACTIVE'
      ? { label: 'Provisioned: Active', tone: 'green' as const }
      : { label: 'Provisioned: Disabled', tone: 'red' as const };
  }, [review.provisioning]);

  const currentPath = isEditMode
    ? 'Accounts > Edit Account > Review & Publish'
    : 'Accounts > Create Account > Review & Publish';

  const publishDisabled =
    isPublishing || (targetStatus === 'Active' && !review.activationReadiness.isReady);

  async function onPublish() {
    setError(null);

    const payload: PublishCpAccountInput = { targetStatus };

    setIsPublishing(true);
    try {
      const updated = await publishCpAccount(account.accountKey, payload);
      setReview(updated);
      setTargetStatus(
        defaultTargetStatus(updated.account.cpStatus, updated.activationReadiness.isReady),
      );
      router.refresh();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Publish failed.';
      setError(message);
    } finally {
      setIsPublishing(false);
    }
  }

  const footerActions: FooterAction[] = [
    {
      label: 'Back',
      href: isEditMode
        ? getEditSetupPath(account.accountKey)
        : getCreateSetupPath(account.accountKey),
      variant: 'ghost',
    },
    {
      label: isPublishing ? 'Publishing…' : 'Publish',
      variant: 'primary',
      disabled: publishDisabled,
      onClick: () => {
        void onPublish();
      },
    },
  ];

  return (
    <ControlPlaneShell
      currentPath={currentPath}
      pageTitle="Review & Publish"
      pageDescription="Review the read-only account configuration, confirm Activation Ready, then publish the tenant as Active or Disabled."
      footerActions={footerActions}
      account={account}
      step={{ stepNumber: 3, stepName: 'Review & Publish' }}
    >
      <section style={sectionGridStyle}>
        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Provisioning status</h2>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '12px',
            }}
          >
            <div style={{ display: 'grid', gap: '6px' }}>
              <p style={mutedTextStyle}>
                Publish creates or updates a real tenant row for QA use. CP allowance truth remains
                separate from tenant Settings truth.
              </p>
              {error ? (
                <p style={{ ...mutedTextStyle, color: '#991b1b', fontWeight: 700 }}>{error}</p>
              ) : null}
              {review.provisioning.isProvisioned ? (
                <p style={mutedTextStyle}>
                  Last published at <strong>{formatDate(review.provisioning.publishedAt)}</strong>
                </p>
              ) : (
                <p style={mutedTextStyle}>Not published yet.</p>
              )}
            </div>
            <span style={badgeStyle(provisioningBadge.tone)}>{provisioningBadge.label}</span>
          </div>

          {review.provisioning.isProvisioned && review.provisioning.tenantKey ? (
            <div style={{ marginTop: '14px', ...infoGridStyle }}>
              <div style={infoCardStyle}>
                <p style={labelStyle}>Tenant key</p>
                <p style={valueStyle}>{review.provisioning.tenantKey}</p>
              </div>
              <div style={infoCardStyle}>
                <p style={labelStyle}>Tenant state</p>
                <p style={valueStyle}>{review.provisioning.tenantState}</p>
              </div>
              <div style={infoCardStyle}>
                <p style={labelStyle}>Dev tenant URL</p>
                <p style={valueStyle}>{`http://${review.provisioning.tenantKey}.lvh.me:3000`}</p>
              </div>
            </div>
          ) : null}
        </article>

        <article style={insetPanelStyle}>
          <h2 style={sectionTitleStyle}>Activation Ready</h2>
          <p style={mutedTextStyle}>
            Active publish is allowed only when Activation Ready passes. Disabled publish is always
            available.
          </p>
          <div style={{ marginTop: '12px', ...checklistStyle }}>
            {review.activationReadiness.checks.map((item) => (
              <div key={item.code} style={checklistRowStyle(item.passed)}>
                <span style={checklistDotStyle(item.passed)} aria-hidden="true" />
                <div style={{ display: 'grid', gap: '2px' }}>
                  <span>{item.label}</span>
                  <span style={{ ...mutedTextStyle, margin: 0 }}>{item.detail}</span>
                </div>
              </div>
            ))}
          </div>

          {review.activationReadiness.isReady ? (
            <p style={{ marginTop: '12px', ...mutedTextStyle, color: '#166534', fontWeight: 700 }}>
              Activation Ready passed.
            </p>
          ) : (
            <p style={{ marginTop: '12px', ...mutedTextStyle, color: '#991b1b', fontWeight: 700 }}>
              Activation Ready failed — Active publish is blocked.
            </p>
          )}
        </article>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Final status decision</h2>
          <p style={mutedTextStyle}>
            Choose the tenant status to publish. Active is blocked until Activation Ready passes.
          </p>

          <div style={{ marginTop: '12px', ...statusGridStyle }}>
            <div
              role="button"
              tabIndex={0}
              aria-disabled={activeBlocked}
              style={statusCardStyle(targetStatus === 'Active', activeBlocked)}
              onClick={() => {
                if (!activeBlocked) setTargetStatus('Active');
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  if (!activeBlocked) setTargetStatus('Active');
                }
              }}
            >
              <div style={statusTitleRowStyle}>
                <span style={badgeStyle(targetStatus === 'Active' ? 'blue' : 'slate')}>Active</span>
                {activeBlocked ? <span style={badgeStyle('red')}>Blocked</span> : null}
              </div>
              <p style={mutedTextStyle}>
                Published tenants become available for authentication and other runtime flows.
              </p>
              {activeBlocked ? (
                <p style={{ ...mutedTextStyle, color: '#991b1b', fontWeight: 600 }}>
                  Complete the Activation Ready checks to enable Active.
                </p>
              ) : null}
            </div>

            <div
              role="button"
              tabIndex={0}
              style={statusCardStyle(targetStatus === 'Disabled', false)}
              onClick={() => setTargetStatus('Disabled')}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  setTargetStatus('Disabled');
                }
              }}
            >
              <div style={statusTitleRowStyle}>
                <span style={badgeStyle(targetStatus === 'Disabled' ? 'blue' : 'slate')}>
                  Disabled
                </span>
                <span style={badgeStyle('slate')}>Always available</span>
              </div>
              <p style={mutedTextStyle}>
                Disabled tenants are provisioned for QA visibility but are not active for runtime
                entry.
              </p>
            </div>
          </div>

          <p style={{ marginTop: '12px', ...mutedTextStyle }}>
            Publish will set CP Status to the selected value and create/update the provisioned
            tenant record.
          </p>
        </article>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Read-only review summary</h2>

          <div style={sectionBlockStyle}>
            {review.sections.map((section) => (
              <div key={section.key} style={reviewSectionStyle}>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 800, color: '#0f172a' }}>
                  {section.title}
                </h3>
                <div style={reviewLinesGridStyle}>
                  {section.lines.map((line) => (
                    <div
                      key={`${section.key}-${line.label}`}
                      style={{ display: 'grid', gap: '2px' }}
                    >
                      <p style={lineLabelStyle}>{line.label}</p>
                      <p style={lineValueStyle}>{line.value || '—'}</p>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
