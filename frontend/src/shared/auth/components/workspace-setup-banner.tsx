'use client';

/**
 * frontend/src/shared/auth/components/workspace-setup-banner.tsx
 *
 * WHY:
 * - Renders the non-blocking admin-dashboard CTA once `/admin` starts reading
 *   Settings-native bootstrap truth from `GET /settings/bootstrap`.
 * - Keeps the banner generic: `/admin` may only signal that workspace setup
 *   still needs attention and link to `/admin/settings`.
 * - Avoids leaking detailed progress resolution into the landing page.
 *
 * RULES:
 * - Client component only — uses a Link for navigation.
 * - Receives `showSetupBanner` from the Settings bootstrap DTO.
 * - Returns null when the backend says no banner should render.
 * - Does not fetch or write any data itself.
 */

import Link from 'next/link';
import type { CSSProperties } from 'react';
import { ADMIN_SETTINGS_PATH } from '@/shared/auth/redirects';

const bannerStyle: CSSProperties = {
  display: 'flex',
  alignItems: 'flex-start',
  justifyContent: 'space-between',
  gap: '16px',
  flexWrap: 'wrap',
  padding: '16px 20px',
  borderRadius: '16px',
  border: '1px solid #bfdbfe',
  backgroundColor: '#eff6ff',
};

const textBlockStyle: CSSProperties = {
  display: 'grid',
  gap: '4px',
};

const titleStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  fontWeight: 700,
  color: '#1e40af',
};

const bodyStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.6,
  color: '#1d4ed8',
};

const ctaStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: '6px',
  padding: '8px 16px',
  borderRadius: '10px',
  backgroundColor: '#1d4ed8',
  color: '#ffffff',
  fontSize: '14px',
  fontWeight: 600,
  textDecoration: 'none',
  whiteSpace: 'nowrap',
  flexShrink: 0,
};

type WorkspaceSetupBannerProps = {
  showSetupBanner: boolean;
};

export function WorkspaceSetupBanner({ showSetupBanner }: WorkspaceSetupBannerProps) {
  if (!showSetupBanner) {
    return null;
  }

  return (
    <div role="alert" aria-label="Workspace setup requires attention" style={bannerStyle}>
      <div style={textBlockStyle}>
        <p style={titleStyle}>⚙ Workspace setup requires attention</p>
        <p style={bodyStyle}>
          Review required workspace settings and continue setup from the Settings area. Any admin
          can open it; the banner stays until the required setup work is complete.
        </p>
      </div>
      <Link href={ADMIN_SETTINGS_PATH} style={ctaStyle}>
        Open workspace settings →
      </Link>
    </div>
  );
}
