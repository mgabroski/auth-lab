'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useMemo, useState, type CSSProperties } from 'react';

import { getApiErrorMessage } from '@/shared/auth/api-errors';
import { SettingsStatusChip } from '@/shared/settings/components/settings-status-chip';
import type {
  AccessSettingsResponse,
  AccessSettingsRowResponse,
} from '@/shared/settings/contracts';
import { acknowledgeAccessSettings } from '@/shared/settings/browser-api';

const pageStackStyle: CSSProperties = {
  display: 'grid',
  gap: '18px',
};

const heroCardStyle: CSSProperties = {
  display: 'grid',
  gap: '12px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -28px rgba(15, 23, 42, 0.35)',
};

const groupCardStyle: CSSProperties = {
  display: 'grid',
  gap: '14px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -28px rgba(15, 23, 42, 0.35)',
};

const rowStyle: CSSProperties = {
  display: 'grid',
  gap: '8px',
  padding: '14px 0',
  borderTop: '1px solid rgba(226, 232, 240, 0.9)',
};

const labelRowStyle: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  gap: '12px',
  flexWrap: 'wrap',
};

const noticeBaseStyle: CSSProperties = {
  display: 'grid',
  gap: '8px',
  padding: '14px 16px',
  borderRadius: '16px',
  border: '1px solid transparent',
};

const blockerNoticeStyle: CSSProperties = {
  ...noticeBaseStyle,
  backgroundColor: '#fef2f2',
  borderColor: '#fecaca',
  color: '#991b1b',
};

const warningNoticeStyle: CSSProperties = {
  ...noticeBaseStyle,
  backgroundColor: '#fff7ed',
  borderColor: '#fed7aa',
  color: '#9a3412',
};

const successNoticeStyle: CSSProperties = {
  ...noticeBaseStyle,
  backgroundColor: '#f0fdf4',
  borderColor: '#bbf7d0',
  color: '#166534',
};

const mutedTextStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#475569',
};

const valueStyle: CSSProperties = {
  margin: 0,
  fontSize: '15px',
  lineHeight: 1.6,
  color: '#0f172a',
  fontWeight: 600,
};

const badgeBaseStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  padding: '4px 10px',
  borderRadius: '999px',
  border: '1px solid transparent',
  fontSize: '12px',
  fontWeight: 700,
  lineHeight: 1,
  whiteSpace: 'nowrap',
};

const rowStatusStyles: Record<AccessSettingsRowResponse['status'], CSSProperties> = {
  READY: {
    color: '#166534',
    backgroundColor: '#dcfce7',
    borderColor: '#86efac',
  },
  WARNING: {
    color: '#b45309',
    backgroundColor: '#fef3c7',
    borderColor: '#fcd34d',
  },
  BLOCKED: {
    color: '#991b1b',
    backgroundColor: '#fee2e2',
    borderColor: '#fca5a5',
  },
};

const managedByStyles: Record<AccessSettingsRowResponse['managedBy'], CSSProperties> = {
  CONTROL_PLANE: {
    color: '#1d4ed8',
    backgroundColor: '#dbeafe',
    borderColor: '#93c5fd',
  },
  PLATFORM: {
    color: '#7c3aed',
    backgroundColor: '#f3e8ff',
    borderColor: '#d8b4fe',
  },
};

const buttonStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  minHeight: '44px',
  padding: '0 18px',
  borderRadius: '14px',
  border: '1px solid #1d4ed8',
  backgroundColor: '#1d4ed8',
  color: '#ffffff',
  fontSize: '14px',
  fontWeight: 700,
  cursor: 'pointer',
};

const disabledButtonStyle: CSSProperties = {
  ...buttonStyle,
  borderColor: '#cbd5e1',
  backgroundColor: '#e2e8f0',
  color: '#64748b',
  cursor: 'not-allowed',
};

function getRowStatusLabel(status: AccessSettingsRowResponse['status']): string {
  switch (status) {
    case 'READY':
      return 'Ready';
    case 'WARNING':
      return 'Warning';
    case 'BLOCKED':
      return 'Blocked';
    default: {
      const exhaustiveCheck: never = status;
      return exhaustiveCheck;
    }
  }
}

function getManagedByLabel(managedBy: AccessSettingsRowResponse['managedBy']): string {
  return managedBy === 'CONTROL_PLANE' ? 'Managed by Control Plane' : 'Managed by platform';
}

type AccessSettingsReviewProps = {
  initialData: AccessSettingsResponse;
};

export function AccessSettingsReview({ initialData }: AccessSettingsReviewProps) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const flattenedRows = useMemo(
    () => initialData.groups.flatMap((group) => group.rows),
    [initialData.groups],
  );

  const submitAcknowledge = async () => {
    try {
      setPending(true);
      setError(null);
      setSuccessMessage(null);

      const result = await acknowledgeAccessSettings({
        expectedVersion: initialData.version,
        expectedCpRevision: initialData.cpRevision,
      });

      if (!result.ok) {
        setError(getApiErrorMessage(result.error, 'Unable to acknowledge Access & Security.'));
        setPending(false);
        return;
      }

      setSuccessMessage(
        'Access & Security was acknowledged. Refreshing the latest workspace state…',
      );
      router.refresh();
    } catch (caughtError) {
      setError(getApiErrorMessage(caughtError, 'Unable to acknowledge Access & Security.'));
      setPending(false);
    }
  };

  return (
    <div style={pageStackStyle}>
      <section style={heroCardStyle}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <h2 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2, color: '#0f172a' }}>
            {initialData.title}
          </h2>
          <SettingsStatusChip status={initialData.status} />
        </div>
        <p style={mutedTextStyle}>{initialData.description}</p>
        <p style={{ ...mutedTextStyle, fontSize: '13px' }}>
          Current version: {initialData.version} · Current cpRevision: {initialData.cpRevision}
        </p>
      </section>

      {initialData.blockers.length > 0 ? (
        <section style={blockerNoticeStyle}>
          <strong>Blocked by platform-owned mismatches</strong>
          <ul style={{ margin: 0, paddingLeft: '18px', display: 'grid', gap: '6px' }}>
            {initialData.blockers.map((blocker) => (
              <li key={blocker}>{blocker}</li>
            ))}
          </ul>
        </section>
      ) : null}

      {initialData.warnings.length > 0 ? (
        <section style={warningNoticeStyle}>
          <strong>Warnings</strong>
          <ul style={{ margin: 0, paddingLeft: '18px', display: 'grid', gap: '6px' }}>
            {initialData.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </section>
      ) : null}

      {successMessage ? (
        <section style={successNoticeStyle}>
          <strong>Review saved</strong>
          <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>{successMessage}</p>
        </section>
      ) : null}

      {error ? (
        <section style={blockerNoticeStyle}>
          <strong>Unable to save your review</strong>
          <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>{error}</p>
        </section>
      ) : null}

      {initialData.groups.map((group) => (
        <section key={group.key} style={groupCardStyle}>
          <div style={{ display: 'grid', gap: '6px' }}>
            <h3 style={{ margin: 0, fontSize: '18px', lineHeight: 1.2, color: '#0f172a' }}>
              {group.title}
            </h3>
            <p style={mutedTextStyle}>{group.description}</p>
          </div>

          <div style={{ display: 'grid' }}>
            {group.rows.map((row, index) => (
              <div
                key={row.key}
                style={{
                  ...rowStyle,
                  borderTop: index === 0 ? 'none' : rowStyle.borderTop,
                }}
              >
                <div style={labelRowStyle}>
                  <div style={{ display: 'grid', gap: '6px' }}>
                    <strong style={{ fontSize: '15px', color: '#0f172a' }}>{row.label}</strong>
                    <p style={valueStyle}>{row.value}</p>
                  </div>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    <span style={{ ...badgeBaseStyle, ...managedByStyles[row.managedBy] }}>
                      {getManagedByLabel(row.managedBy)}
                    </span>
                    <span style={{ ...badgeBaseStyle, ...rowStatusStyles[row.status] }}>
                      {getRowStatusLabel(row.status)}
                    </span>
                  </div>
                </div>

                {row.blocker ? (
                  <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#991b1b' }}>
                    {row.blocker}
                  </p>
                ) : null}

                {row.warning ? (
                  <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#9a3412' }}>
                    {row.warning}{' '}
                    {row.resolutionHref ? (
                      <Link href={row.resolutionHref} style={{ color: 'inherit', fontWeight: 700 }}>
                        Resolve in Integrations →
                      </Link>
                    ) : null}
                  </p>
                ) : null}
              </div>
            ))}
          </div>
        </section>
      ))}

      <section style={heroCardStyle}>
        <div style={{ display: 'grid', gap: '8px' }}>
          <h3 style={{ margin: 0, fontSize: '18px', lineHeight: 1.2, color: '#0f172a' }}>
            Explicit review acknowledgement
          </h3>
          <p style={mutedTextStyle}>
            Access &amp; Security completes only when you explicitly acknowledge the current rules.
            Page visit alone does not complete this section.
          </p>
          {initialData.nextAction ? (
            <p style={{ ...mutedTextStyle, fontSize: '13px' }}>
              Current next action after this section: {initialData.nextAction.label}
            </p>
          ) : null}
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            type="button"
            style={initialData.canAcknowledge && !pending ? buttonStyle : disabledButtonStyle}
            disabled={!initialData.canAcknowledge || pending}
            onClick={() => {
              void submitAcknowledge();
            }}
          >
            {pending ? 'Saving review…' : initialData.acknowledgeLabel}
          </button>
          {!initialData.canAcknowledge ? (
            <span style={{ fontSize: '13px', lineHeight: 1.6, color: '#991b1b' }}>
              Resolve blockers above before acknowledging this section.
            </span>
          ) : null}
          <span style={{ fontSize: '13px', lineHeight: 1.6, color: '#64748b' }}>
            {flattenedRows.length} read-only items are currently visible in this workspace.
          </span>
        </div>
      </section>
    </div>
  );
}
