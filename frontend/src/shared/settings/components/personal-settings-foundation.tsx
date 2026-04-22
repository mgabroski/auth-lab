import Link from 'next/link';
import type { CSSProperties } from 'react';

import type { PersonalSettingsResponse } from '@/shared/settings/contracts';
import { SettingsStatusChip } from './settings-status-chip';

const cardStyle: CSSProperties = {
  display: 'grid',
  gap: '14px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -28px rgba(15, 23, 42, 0.35)',
};

const panelStyle: CSSProperties = {
  display: 'grid',
  gap: '12px',
  padding: '18px',
  borderRadius: '18px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#f8fafc',
};

const actionLinkStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: '6px',
  color: '#1d4ed8',
  fontSize: '14px',
  fontWeight: 600,
  textDecoration: 'none',
};

type PersonalSettingsFoundationProps = {
  data: PersonalSettingsResponse;
};

export function PersonalSettingsFoundation({ data }: PersonalSettingsFoundationProps) {
  return (
    <div style={{ display: 'grid', gap: '16px' }}>
      <section style={cardStyle}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <h2 style={{ margin: 0, fontSize: '22px', lineHeight: 1.2, color: '#0f172a' }}>
            {data.title}
          </h2>
          <SettingsStatusChip status={data.status} />
        </div>
        <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
          {data.description}
        </p>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <span
            style={{
              display: 'inline-flex',
              padding: '4px 10px',
              borderRadius: '999px',
              border: '1px solid #cbd5e1',
              fontSize: '12px',
              fontWeight: 700,
              color: '#475569',
              backgroundColor: '#f8fafc',
            }}
          >
            Section version {data.version}
          </span>
          <span
            style={{
              display: 'inline-flex',
              padding: '4px 10px',
              borderRadius: '999px',
              border: '1px solid #cbd5e1',
              fontSize: '12px',
              fontWeight: 700,
              color: '#475569',
              backgroundColor: '#f8fafc',
            }}
          >
            CP revision {data.cpRevision}
          </span>
        </div>
        {data.nextAction ? (
          <Link href={data.nextAction.href} style={actionLinkStyle}>
            → {data.nextAction.label}
          </Link>
        ) : null}
        {data.warnings.length > 0 ? (
          <ul
            style={{
              margin: 0,
              paddingLeft: '18px',
              display: 'grid',
              gap: '6px',
              color: '#9a3412',
              fontSize: '13px',
              lineHeight: 1.6,
            }}
          >
            {data.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        ) : null}
      </section>

      <section style={panelStyle}>
        <div style={{ display: 'grid', gap: '6px' }}>
          <h3 style={{ margin: 0, fontSize: '18px', lineHeight: 1.2, color: '#0f172a' }}>
            {data.familyReview.title}
          </h3>
          <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
            {data.familyReview.description}
          </p>
          <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#64748b' }}>
            {data.familyReview.summary}
          </p>
        </div>

        <div style={{ display: 'grid', gap: '12px' }}>
          {data.familyReview.families.map((family) => (
            <article
              key={family.familyKey}
              style={{
                display: 'grid',
                gap: '8px',
                padding: '16px',
                borderRadius: '16px',
                border: '1px solid rgba(148, 163, 184, 0.25)',
                backgroundColor: '#ffffff',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <h4 style={{ margin: 0, fontSize: '16px', lineHeight: 1.2, color: '#0f172a' }}>
                  {family.label}
                </h4>
                <span
                  style={{
                    display: 'inline-flex',
                    padding: '4px 10px',
                    borderRadius: '999px',
                    border: '1px solid #cbd5e1',
                    fontSize: '12px',
                    fontWeight: 700,
                    color: '#475569',
                    backgroundColor: '#f8fafc',
                  }}
                >
                  {family.reviewDecision.toLowerCase()}
                </span>
                {!family.canExclude ? (
                  <span
                    style={{
                      display: 'inline-flex',
                      padding: '4px 10px',
                      borderRadius: '999px',
                      border: '1px solid #fcd34d',
                      fontSize: '12px',
                      fontWeight: 700,
                      color: '#b45309',
                      backgroundColor: '#fef3c7',
                    }}
                  >
                    Exclusion locked
                  </span>
                ) : null}
              </div>
              <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#475569' }}>
                {family.allowedFieldCount} allowed fields · {family.defaultSelectedFieldCount} CP
                defaults
              </p>
              {family.requiredFieldKeys.length > 0 ? (
                <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#475569' }}>
                  Required baseline: {family.requiredFieldKeys.join(', ')}
                </p>
              ) : null}
              {family.systemManagedFieldKeys.length > 0 ? (
                <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#475569' }}>
                  System-managed: {family.systemManagedFieldKeys.join(', ')}
                </p>
              ) : null}
              <ul
                style={{
                  margin: 0,
                  paddingLeft: '18px',
                  display: 'grid',
                  gap: '6px',
                  fontSize: '13px',
                  lineHeight: 1.6,
                  color: '#64748b',
                }}
              >
                {family.notes.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </section>

      {[data.fieldConfiguration, data.sectionBuilder].map((panel) => (
        <section key={panel.key} style={panelStyle}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <h3 style={{ margin: 0, fontSize: '18px', lineHeight: 1.2, color: '#0f172a' }}>
              {panel.title}
            </h3>
            <span
              style={{
                display: 'inline-flex',
                padding: '4px 10px',
                borderRadius: '999px',
                border: '1px solid #d8b4fe',
                fontSize: '12px',
                fontWeight: 700,
                color: '#7c3aed',
                backgroundColor: '#f3e8ff',
              }}
            >
              Future phase
            </span>
          </div>
          <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
            {panel.description}
          </p>
          <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#64748b' }}>
            {panel.summary}
          </p>
        </section>
      ))}
    </div>
  );
}
