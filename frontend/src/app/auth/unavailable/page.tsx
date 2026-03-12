/**
 * frontend/src/app/auth/unavailable/page.tsx
 *
 * WHY:
 * - Dedicated route for unknown/inactive tenant bootstrap state.
 * - Uses the shared tenant unavailable component so the copy stays anti-enumeration-safe.
 */

import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthCard } from '@/shared/auth/components/auth-card';
import { AuthErrorBanner } from '@/shared/auth/components/auth-error-banner';
import { AuthShell } from '@/shared/auth/components/auth-shell';
import { TenantUnavailableState } from '@/shared/auth/components/tenant-unavailable-state';
import { getRouteStateRedirectPath, TOPOLOGY_CHECK_PATH } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

export default async function TenantUnavailablePage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Tenant unavailable"
        subtitle="The tenant unavailable route could not complete bootstrap."
        footer={
          <>
            Use <Link href={TOPOLOGY_CHECK_PATH}>Topology Check</Link> to verify the foundation.
          </>
        }
      >
        <AuthCard tone="danger">
          <AuthErrorBanner error={bootstrap.error} fallbackMessage="Unable to load tenant state." />
        </AuthCard>
      </AuthShell>
    );
  }

  if (bootstrap.routeState.kind !== 'TENANT_UNAVAILABLE') {
    redirect(getRouteStateRedirectPath(bootstrap.routeState));
  }

  return (
    <AuthShell
      eyebrow="Hubins"
      title="Workspace unavailable"
      subtitle="This state is intentionally generic to preserve backend anti-enumeration behavior."
    >
      <TenantUnavailableState />
    </AuthShell>
  );
}
