/**
 * frontend/src/shared/auth/components/authenticated-shell.tsx
 *
 * WHY:
 * - Provides a minimal but real authenticated shell for member/admin landing routes.
 * - Keeps authenticated pages consistent without pretending broader product modules already exist.
 * - Hosts the real logout button in a shared place.
 */

import type { CSSProperties, ReactNode } from 'react';
import type { MeResponse } from '@/shared/auth/contracts';
import { LogoutButton } from './logout-button';

const pageStyle: CSSProperties = {
  minHeight: '100vh',
  backgroundColor: '#f8fafc',
  color: '#0f172a',
  fontFamily:
    'Geist, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
};

const innerStyle: CSSProperties = {
  width: '100%',
  maxWidth: '1120px',
  margin: '0 auto',
  padding: '32px 20px 56px',
  display: 'grid',
  gap: '24px',
};

const headerStyle: CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'flex-start',
  gap: '20px',
  flexWrap: 'wrap',
};

const eyebrowStyle: CSSProperties = {
  margin: 0,
  fontSize: '12px',
  fontWeight: 700,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: '#475569',
};

const titleStyle: CSSProperties = {
  margin: '6px 0 0',
  fontSize: '34px',
  lineHeight: 1.1,
  fontWeight: 750,
};

const subtitleStyle: CSSProperties = {
  margin: '12px 0 0',
  maxWidth: '720px',
  fontSize: '15px',
  lineHeight: 1.7,
  color: '#475569',
};

const gridStyle: CSSProperties = {
  display: 'grid',
  gap: '16px',
  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
};

const cardStyle: CSSProperties = {
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  padding: '20px',
  boxShadow: '0 12px 24px rgba(15, 23, 42, 0.05)',
  display: 'grid',
  gap: '10px',
};

const labelStyle: CSSProperties = {
  margin: 0,
  fontSize: '12px',
  fontWeight: 700,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: '#64748b',
};

const valueStyle: CSSProperties = {
  margin: 0,
  fontSize: '15px',
  lineHeight: 1.6,
  color: '#0f172a',
  wordBreak: 'break-word',
};

const contentCardStyle: CSSProperties = {
  ...cardStyle,
  gap: '16px',
};

type AuthenticatedShellProps = {
  eyebrow: string;
  title: string;
  subtitle: string;
  me: MeResponse;
  children: ReactNode;
};

function booleanLabel(value: boolean): string {
  return value ? 'Yes' : 'No';
}

export function AuthenticatedShell({
  eyebrow,
  title,
  subtitle,
  me,
  children,
}: AuthenticatedShellProps) {
  return (
    <main style={pageStyle}>
      <div style={innerStyle}>
        <header style={headerStyle}>
          <div>
            <p style={eyebrowStyle}>{eyebrow}</p>
            <h1 style={titleStyle}>{title}</h1>
            <p style={subtitleStyle}>{subtitle}</p>
          </div>

          <LogoutButton />
        </header>

        <section style={gridStyle} aria-label="Current workspace session">
          <article style={cardStyle}>
            <p style={labelStyle}>Workspace</p>
            <p style={valueStyle}>{me.tenant.name}</p>
          </article>

          <article style={cardStyle}>
            <p style={labelStyle}>Role</p>
            <p style={valueStyle}>{me.membership.role}</p>
          </article>

          <article style={cardStyle}>
            <p style={labelStyle}>Signed in as</p>
            <p style={valueStyle}>{me.user.email}</p>
          </article>

          <article style={cardStyle}>
            <p style={labelStyle}>MFA verified</p>
            <p style={valueStyle}>{booleanLabel(me.session.mfaVerified)}</p>
          </article>
        </section>

        <section style={contentCardStyle}>{children}</section>
      </div>
    </main>
  );
}
