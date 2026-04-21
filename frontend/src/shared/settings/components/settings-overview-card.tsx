import Link from 'next/link';
import type { CSSProperties } from 'react';

import type { SettingsOverviewCardResponse } from '@/shared/settings/contracts';
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

const eyebrowRowStyle: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  gap: '12px',
  flexWrap: 'wrap',
};

const eyebrowStyle: CSSProperties = {
  margin: 0,
  fontSize: '12px',
  fontWeight: 700,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: '#64748b',
};

const titleStyle: CSSProperties = {
  margin: 0,
  fontSize: '20px',
  lineHeight: 1.2,
  color: '#0f172a',
};

const descriptionStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#475569',
};

const warningListStyle: CSSProperties = {
  margin: 0,
  paddingLeft: '18px',
  display: 'grid',
  gap: '6px',
  color: '#9a3412',
  fontSize: '13px',
  lineHeight: 1.6,
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

function getClassificationLabel(card: SettingsOverviewCardResponse): string {
  if (card.isRequired) {
    return 'Required section';
  }

  if (card.classification === 'PLACEHOLDER_ONLY') {
    return 'Placeholder surface';
  }

  if (card.classification === 'NAVIGATION_ONLY') {
    return 'Navigation hub';
  }

  return 'Optional section';
}

function getActionLabel(card: SettingsOverviewCardResponse): string | null {
  if (!card.href) {
    return null;
  }

  if (card.classification === 'PLACEHOLDER_ONLY') {
    return 'Open placeholder';
  }

  if (card.status === 'NEEDS_REVIEW') {
    return 'Review changes';
  }

  if (card.key === 'modules' && card.status !== 'COMPLETE') {
    return 'Continue setup';
  }

  return 'Open section';
}

type SettingsOverviewCardProps = {
  card: SettingsOverviewCardResponse;
};

export function SettingsOverviewCard({ card }: SettingsOverviewCardProps) {
  const actionLabel = getActionLabel(card);

  return (
    <article style={cardStyle}>
      <div style={eyebrowRowStyle}>
        <p style={eyebrowStyle}>{getClassificationLabel(card)}</p>
        <SettingsStatusChip status={card.status} />
      </div>

      <div style={{ display: 'grid', gap: '8px' }}>
        <h3 style={titleStyle}>{card.title}</h3>
        <p style={descriptionStyle}>{card.description}</p>
      </div>

      {card.warnings.length > 0 ? (
        <ul style={warningListStyle}>
          {card.warnings.map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      ) : null}

      {actionLabel ? (
        <Link href={card.href!} style={actionLinkStyle}>
          {actionLabel} →
        </Link>
      ) : null}
    </article>
  );
}
