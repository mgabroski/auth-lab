import type { CSSProperties } from 'react';

export const appFontFamily =
  'Geist, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';

export const appPageStyle: CSSProperties = {
  minHeight: '100vh',
  backgroundColor: '#f8fafc',
  color: '#0f172a',
  fontFamily: appFontFamily,
};

export const appInnerStyle: CSSProperties = {
  width: '100%',
  maxWidth: '1180px',
  margin: '0 auto',
  padding: '32px 20px 56px',
  display: 'grid',
  gap: '20px',
};

export const panelStyle: CSSProperties = {
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 12px 24px rgba(15, 23, 42, 0.05)',
};

export const contentPanelStyle: CSSProperties = {
  ...panelStyle,
  padding: '24px',
  display: 'grid',
  gap: '18px',
};

export const mutedTextStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#475569',
};

export const labelStyle: CSSProperties = {
  margin: 0,
  fontSize: '12px',
  fontWeight: 700,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: '#64748b',
};

export const valueStyle: CSSProperties = {
  margin: 0,
  fontSize: '15px',
  lineHeight: 1.6,
  color: '#0f172a',
};

export const bodyHeadingStyle: CSSProperties = {
  margin: 0,
  fontSize: '28px',
  lineHeight: 1.15,
  fontWeight: 750,
};

export const sectionTitleStyle: CSSProperties = {
  margin: 0,
  fontSize: '18px',
  lineHeight: 1.3,
  fontWeight: 700,
};

export const sectionGridStyle: CSSProperties = {
  display: 'grid',
  gap: '16px',
};

export const infoGridStyle: CSSProperties = {
  display: 'grid',
  gap: '16px',
  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
};

export const infoCardStyle: CSSProperties = {
  padding: '18px',
  borderRadius: '16px',
  border: '1px solid rgba(148, 163, 184, 0.22)',
  backgroundColor: '#f8fafc',
  display: 'grid',
  gap: '8px',
};

export const insetPanelStyle: CSSProperties = {
  padding: '18px',
  borderRadius: '16px',
  border: '1px solid #e2e8f0',
  backgroundColor: '#f8fafc',
  display: 'grid',
  gap: '10px',
};

export const tableStyle: CSSProperties = {
  width: '100%',
  borderCollapse: 'collapse',
};

export const tableCellStyle: CSSProperties = {
  padding: '14px 12px',
  borderTop: '1px solid #e2e8f0',
  fontSize: '14px',
  lineHeight: 1.6,
  color: '#334155',
  verticalAlign: 'middle',
  textAlign: 'left',
};
