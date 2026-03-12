/**
 * frontend/src/app/admin/page.tsx
 *
 * WHY:
 * - Minimal but real authenticated landing route for workspace admins.
 * - Only renders when backend bootstrap truth resolves to a fully-authenticated ADMIN session.
 */

import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import { ADMIN_INVITES_PATH, getRouteStateRedirectPath } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

const actionLinkStyle = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  minHeight: '44px',
  borderRadius: '12px',
  border: '1px solid rgba(148, 163, 184, 0.3)',
  backgroundColor: '#ffffff',
  color: '#0f172a',
  padding: '0 16px',
  fontSize: '14px',
  fontWeight: 700,
  textDecoration: 'none',
} as const;

export default async function AdminPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Admin</h1>
        <p>Bootstrap failed while loading the admin landing route.</p>
        <p>
          <strong>Error:</strong> {bootstrap.error.message}
        </p>
      </main>
    );
  }

  const routeState = bootstrap.routeState;

  if (routeState.kind !== 'AUTHENTICATED_ADMIN') {
    redirect(getRouteStateRedirectPath(routeState));
  }

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title="Admin dashboard"
      subtitle="This is the minimal authenticated landing page for workspace admins after the root bootstrap gate and any required continuation are complete."
      me={routeState.me}
    >
      <div style={{ display: 'grid', gap: '12px' }}>
        <h2 style={{ margin: 0, fontSize: '22px', lineHeight: 1.2 }}>Admin landing ready</h2>
        <p style={{ margin: 0, fontSize: '15px', lineHeight: 1.7, color: '#475569' }}>
          Admin users are separated from members at the route-state layer so the root gate lands
          them in <code>/admin</code> instead of the member app. This page stays intentionally
          minimal while still using the real backend session and exposing the first real admin
          provisioning surface.
        </p>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <Link href={ADMIN_INVITES_PATH} style={actionLinkStyle}>
            Manage invites
          </Link>
        </div>
      </div>
    </AuthenticatedShell>
  );
}
