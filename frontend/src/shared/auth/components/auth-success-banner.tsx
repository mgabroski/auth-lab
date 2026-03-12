/**
 * frontend/src/shared/auth/components/auth-success-banner.tsx
 *
 * WHY:
 * - Shared success treatment for auth pages that receive backend-safe success messages.
 * - Keeps forgot/reset flows consistent with the existing error banner pattern.
 */

import type { CSSProperties, ReactNode } from 'react';

type AuthSuccessBannerProps = {
  title?: string;
  message?: ReactNode;
};

const bannerStyle: CSSProperties = {
  borderRadius: '14px',
  border: '1px solid rgba(16, 185, 129, 0.24)',
  backgroundColor: 'rgba(236, 253, 245, 0.98)',
  color: '#065f46',
  padding: '14px 16px',
  display: 'grid',
  gap: '6px',
};

const titleStyle: CSSProperties = {
  fontSize: '14px',
  fontWeight: 700,
};

const messageStyle: CSSProperties = {
  fontSize: '14px',
  lineHeight: 1.6,
};

export function AuthSuccessBanner({ title = 'Success', message }: AuthSuccessBannerProps) {
  if (!message) {
    return null;
  }

  return (
    <div role="status" aria-live="polite" style={bannerStyle}>
      <div style={titleStyle}>{title}</div>
      <div style={messageStyle}>{message}</div>
    </div>
  );
}
