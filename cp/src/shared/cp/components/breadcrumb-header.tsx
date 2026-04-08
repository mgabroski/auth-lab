import type { CSSProperties } from 'react';
import { CONTROL_PLANE_TITLE } from '../links';

const eyebrowStyle: CSSProperties = {
  margin: 0,
  fontSize: '12px',
  fontWeight: 700,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: '#475569',
};

const pathStyle: CSSProperties = {
  margin: '6px 0 0',
  fontSize: '28px',
  lineHeight: 1.15,
  fontWeight: 750,
  color: '#0f172a',
};

type BreadcrumbHeaderProps = {
  currentPath: string;
};

export function BreadcrumbHeader({ currentPath }: BreadcrumbHeaderProps) {
  return (
    <header style={{ display: 'grid', gap: '2px' }}>
      <p style={eyebrowStyle}>{CONTROL_PLANE_TITLE}</p>
      <p style={pathStyle}>{currentPath}</p>
    </header>
  );
}
