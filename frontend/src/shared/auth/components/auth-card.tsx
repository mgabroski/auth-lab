/**
 * frontend/src/shared/auth/components/auth-card.tsx
 *
 * WHY:
 * - Reusable auth surface for forms, continuation states, and public bootstrap cards.
 * - Keeps auth pages from re-implementing spacing, border, and action layout.
 */

import type { CSSProperties, ReactNode } from 'react';

type AuthCardTone = 'default' | 'muted' | 'danger';

type AuthCardProps = {
  title?: string;
  description?: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
  tone?: AuthCardTone;
};

const toneStyles: Record<AuthCardTone, CSSProperties> = {
  default: {
    border: '1px solid rgba(148, 163, 184, 0.28)',
    backgroundColor: '#ffffff',
  },
  muted: {
    border: '1px solid rgba(148, 163, 184, 0.22)',
    backgroundColor: 'rgba(255, 255, 255, 0.82)',
  },
  danger: {
    border: '1px solid rgba(239, 68, 68, 0.22)',
    backgroundColor: '#ffffff',
  },
};

const cardStyle: CSSProperties = {
  borderRadius: '20px',
  padding: '24px',
  boxShadow: '0 12px 30px rgba(15, 23, 42, 0.08)',
  display: 'grid',
  gap: '18px',
};

const titleStyle: CSSProperties = {
  margin: 0,
  fontSize: '22px',
  lineHeight: 1.2,
  fontWeight: 700,
};

const descriptionStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.6,
  color: '#475569',
};

const bodyStyle: CSSProperties = {
  display: 'grid',
  gap: '16px',
};

const actionsStyle: CSSProperties = {
  display: 'grid',
  gap: '12px',
};

export function AuthCard({
  title,
  description,
  children,
  actions,
  tone = 'default',
}: AuthCardProps) {
  return (
    <section style={{ ...cardStyle, ...toneStyles[tone] }}>
      {title || description ? (
        <header style={bodyStyle}>
          {title ? <h2 style={titleStyle}>{title}</h2> : null}
          {description ? <div style={descriptionStyle}>{description}</div> : null}
        </header>
      ) : null}

      <div style={bodyStyle}>{children}</div>

      {actions ? <div style={actionsStyle}>{actions}</div> : null}
    </section>
  );
}
