import Link from 'next/link';
import type { CSSProperties } from 'react';

import type { ModulesHubResponse } from '@/shared/settings/contracts';
import { SettingsStatusChip } from './settings-status-chip';

const gridStyle: CSSProperties = {
  display: 'grid',
  gap: '16px',
  gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
};

const cardStyle: CSSProperties = {
  display: 'grid',
  gap: '12px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -28px rgba(15, 23, 42, 0.35)',
};

const eyebrowStyle: CSSProperties = {
  margin: 0,
  fontSize: '12px',
  fontWeight: 700,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: '#64748b',
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

const mutedTextStyle: CSSProperties = {
  margin: 0,
  fontSize: '13px',
  lineHeight: 1.7,
  color: '#64748b',
};

type ModulesHubProps = {
  data: ModulesHubResponse;
};

export function ModulesHub({ data }: ModulesHubProps) {
  return (
    <div style={{ display: 'grid', gap: '16px' }}>
      {data.nextAction ? (
        <section
          style={{
            display: 'grid',
            gap: '8px',
            padding: '18px 20px',
            borderRadius: '20px',
            border: '1px solid #bfdbfe',
            backgroundColor: '#eff6ff',
          }}
        >
          <h2 style={{ margin: 0, fontSize: '18px', lineHeight: 1.2, color: '#1d4ed8' }}>
            Next recommended action
          </h2>
          <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#1d4ed8' }}>
            Settings still treats Personal as the only live module boundary in v1.
          </p>
          <Link href={data.nextAction.href} style={actionLinkStyle}>
            → {data.nextAction.label}
          </Link>
        </section>
      ) : null}

      {data.cards.length > 0 ? (
        <div style={gridStyle}>
          {data.cards.map((card) => (
            <article key={card.key} style={cardStyle}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px' }}>
                <p style={eyebrowStyle}>
                  {card.classification === 'LIVE' ? 'Live module' : 'Placeholder module'}
                </p>
                <SettingsStatusChip status={card.status} />
              </div>
              <div style={{ display: 'grid', gap: '8px' }}>
                <h3 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2, color: '#0f172a' }}>
                  {card.title}
                </h3>
                <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
                  {card.description}
                </p>
              </div>
              {card.warnings.length > 0 ? (
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
                  {card.warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              ) : null}
              {card.href && card.ctaLabel ? (
                <Link href={card.href} style={actionLinkStyle}>
                  {card.ctaLabel} →
                </Link>
              ) : (
                <p style={mutedTextStyle}>No route or configuration flow is available in v1.</p>
              )}
            </article>
          ))}
        </div>
      ) : (
        <section style={cardStyle}>
          <h2 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2, color: '#0f172a' }}>
            No modules are currently visible
          </h2>
          <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
            Hidden modules remain hidden when Control Plane does not allow them.
          </p>
        </section>
      )}
    </div>
  );
}
