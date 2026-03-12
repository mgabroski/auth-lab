/**
 * frontend/src/shared/auth/components/tenant-unavailable-state.tsx
 *
 * WHY:
 * - Shared anti-enumeration-safe tenant unavailable state for auth bootstrap routes.
 * - Keeps the generic copy in one place so pages do not drift.
 */

import type { CSSProperties, ReactNode } from 'react';
import { AuthCard } from './auth-card';

type TenantUnavailableStateProps = {
  details?: ReactNode;
};

const bodyTextStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#475569',
};

export function TenantUnavailableState({ details }: TenantUnavailableStateProps) {
  return (
    <AuthCard
      title="This workspace is not available"
      description="Hubins intentionally uses the same public bootstrap state for unknown and inactive tenants."
      tone="muted"
    >
      <p style={bodyTextStyle}>
        Check the workspace URL or contact your administrator if you believe this workspace should
        be active.
      </p>
      {details ? <div style={bodyTextStyle}>{details}</div> : null}
    </AuthCard>
  );
}
