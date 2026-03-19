'use client';

/**
 * frontend/src/shared/auth/components/workspace-setup-banner.tsx
 *
 * WHY:
 * - Phase 9 (ADR 0003): surfaces the workspace setup call to action on the
 *   admin dashboard without blocking normal admin usage.
 * - Any admin can dismiss it by visiting /admin/settings.
 * - Once dismissed (POST /auth/workspace-setup-ack is called), the banner
 *   disappears for all admins in the workspace because setup_completed_at
 *   is tenant-level state, not per-user state.
 *
 * RULES:
 * - Client component only — uses a Link for navigation.
 * - Receives setupCompleted as a prop derived from ConfigResponse.tenant.setupCompleted.
 * - Returns null when setupCompleted is true — renders nothing.
 * - Does not fetch or write any data itself; ack is called by /admin/settings SSR.
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
  setupCompleted: boolean;
};

export function WorkspaceSetupBanner({ setupCompleted }: WorkspaceSetupBannerProps) {
  if (setupCompleted) {
    return null;
  }

  return (
    <div role="alert" aria-label="Workspace setup incomplete" style={bannerStyle}>
      <div style={textBlockStyle}>
        <p style={titleStyle}>⚙ Workspace setup incomplete</p>
        <p style={bodyStyle}>
          Configure SSO, invite policy, and MFA requirements before inviting your team. Any admin
          can complete this — it only needs to be done once.
        </p>
      </div>
      <Link href={ADMIN_SETTINGS_PATH} style={ctaStyle}>
        Open workspace settings →
      </Link>
    </div>
  );
}
