/**
 * frontend/src/shared/auth/components/auth-error-banner.tsx
 *
 * WHY:
 * - Shared visual treatment for backend-driven auth errors.
 * - Lets pages and forms render structured API failures consistently.
 */

import type { CSSProperties } from 'react';
import { getApiErrorMessage } from '../api-errors';

type AuthErrorBannerProps = {
  error?: unknown;
  title?: string;
  fallbackMessage?: string;
};

const bannerStyle: CSSProperties = {
  borderRadius: '14px',
  border: '1px solid rgba(239, 68, 68, 0.26)',
  backgroundColor: 'rgba(254, 242, 242, 0.95)',
  color: '#991b1b',
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

export function AuthErrorBanner({
  error,
  title = 'Something went wrong',
  fallbackMessage,
}: AuthErrorBannerProps) {
  if (!error) {
    return null;
  }

  return (
    <div role="alert" aria-live="polite" style={bannerStyle}>
      <div style={titleStyle}>{title}</div>
      <div style={messageStyle}>{getApiErrorMessage(error, fallbackMessage)}</div>
    </div>
  );
}
