/**
 * frontend/src/app/admin/invites/page.tsx
 *
 * WHY:
 * - Admin-only Phase 7 page for workspace invite management.
 * - Uses SSR bootstrap truth to gate access before any client-side admin tooling renders.
 * - Hands interactive invite operations to a dedicated client component that uses same-origin `/api/*` requests.
 */

import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import { AdminInviteManagement } from '@/shared/auth/components/admin-invite-management';
import { AUTHENTICATED_ADMIN_ENTRY_PATH, getRouteStateRedirectPath } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

const backLinkStyle = {
  color: '#0f172a',
  fontSize: '14px',
  fontWeight: 600,
  textDecoration: 'none',
} as const;

export default async function AdminInvitesPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Admin invites</h1>
        <p>Bootstrap failed while loading the admin invite management route.</p>
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
      title="Invite management"
      subtitle="Create tenant-scoped invitations, review invite history, resend pending invites, and cancel them through the real admin backend contracts."
      me={routeState.me}
    >
      <div style={{ display: 'grid', gap: '20px' }}>
        <div style={{ display: 'grid', gap: '10px' }}>
          <Link href={AUTHENTICATED_ADMIN_ENTRY_PATH} style={backLinkStyle}>
            ← Back to admin landing
          </Link>
          <p style={{ margin: 0, fontSize: '15px', lineHeight: 1.7, color: '#475569' }}>
            This page is intentionally focused on invite operations only. Access gating still comes
            from SSR bootstrap truth, while the create/list/resend/cancel actions use same-origin
            browser requests to the existing admin invite endpoints.
          </p>
        </div>

        <AdminInviteManagement />
      </div>
    </AuthenticatedShell>
  );
}
