/**
 * frontend/src/shared/auth/components/auth-shell.tsx
 *
 * WHY:
 * - Gives auth routes one reusable page shell instead of repeating layout markup.
 * - Keeps auth pages visually consistent while remaining simple and framework-light.
 * - Works in both Server and Client Components.
 */

import type { CSSProperties, ReactNode } from 'react';

type AuthShellProps = {
  eyebrow?: string;
  title: string;
  subtitle?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
};

const pageStyle: CSSProperties = {
  minHeight: '100vh',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  padding: '32px 16px',
  background:
    'linear-gradient(180deg, rgba(248,250,252,1) 0%, rgba(241,245,249,1) 55%, rgba(226,232,240,1) 100%)',
  color: '#0f172a',
  fontFamily:
    'Geist, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
};

const innerStyle: CSSProperties = {
  width: '100%',
  maxWidth: '520px',
  display: 'grid',
  gap: '20px',
};

const headerStyle: CSSProperties = {
  display: 'grid',
  gap: '10px',
  textAlign: 'center',
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
  margin: 0,
  fontSize: '32px',
  lineHeight: 1.1,
  fontWeight: 700,
};

const subtitleStyle: CSSProperties = {
  margin: 0,
  fontSize: '15px',
  lineHeight: 1.6,
  color: '#475569',
};

const footerStyle: CSSProperties = {
  fontSize: '14px',
  lineHeight: 1.6,
  color: '#475569',
  textAlign: 'center',
};

export function AuthShell({ eyebrow, title, subtitle, children, footer }: AuthShellProps) {
  return (
    <main style={pageStyle}>
      <div style={innerStyle}>
        <header style={headerStyle}>
          {eyebrow ? <p style={eyebrowStyle}>{eyebrow}</p> : null}
          <h1 style={titleStyle}>{title}</h1>
          {subtitle ? <div style={subtitleStyle}>{subtitle}</div> : null}
        </header>

        {children}

        {footer ? <footer style={footerStyle}>{footer}</footer> : null}
      </div>
    </main>
  );
}
