/**
 * frontend/src/app/admin/settings/page.tsx
 *
 * WHY:
 * - Phase 9 (ADR 0003): creates the real /admin/settings SSR route.
 * - All admins can reach this page at any time via the WorkspaceSetupBanner
 *   on /admin or directly by URL.
 * - When config.tenant.setupCompleted is false (workspace has never been
 *   configured), this page calls POST /auth/workspace-setup-ack on SSR load.
 *   The ack sets setup_completed_at on the tenant row. All admins in the
 *   workspace stop seeing the setup banner on their next page load.
 * - Content is intentionally minimal at this phase. The route must exist,
 *   be SSR-gated correctly, and correctly call the ack endpoint. Settings
 *   configuration content belongs to later product phases.
 *
 * RULES:
 * - Server Component only — no 'use client'.
 * - Access gate: AUTHENTICATED_ADMIN only. Any other route state redirects.
 * - The ack call is only fired when setupCompleted is false — idempotent
 *   at the DB level (WHERE setup_completed_at IS NULL) but we skip the
 *   network call entirely when already completed.
 * - Ack failure is swallowed (best-effort). The banner simply remains
 *   visible on /admin until the next successful visit.
 */

import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import {
  AUTHENTICATED_ADMIN_ENTRY_PATH,
  ADMIN_INVITES_PATH,
  getRouteStateRedirectPath,
} from '@/shared/auth/redirects';
import { ssrFetch } from '@/shared/ssr-api-client';

export const dynamic = 'force-dynamic';

/**
 * Calls POST /auth/workspace-setup-ack via the SSR fetch path.
 * Tenant-scoped and idempotent — safe to call multiple times.
 * Errors are swallowed: ack failure is non-fatal. The banner on /admin
 * will remain until the next successful visit.
 */
async function callWorkspaceSetupAck(): Promise<void> {
  try {
    await ssrFetch('/auth/workspace-setup-ack', { method: 'POST' });
  } catch {
    // Intentionally swallowed — ack failure must not block page render.
  }
}

const navLinkStyle = {
  color: '#0f172a',
  fontSize: '14px',
  fontWeight: 600,
  textDecoration: 'none',
} as const;

const sectionStyle = {
  display: 'grid',
  gap: '16px',
} as const;

const infoCardStyle = {
  display: 'grid',
  gap: '8px',
  padding: '16px',
  borderRadius: '12px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#f8fafc',
} as const;

const labelStyle = {
  margin: 0,
  fontSize: '12px',
  fontWeight: 700,
  letterSpacing: '0.08em',
  textTransform: 'uppercase' as const,
  color: '#64748b',
} as const;

const valueStyle = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.6,
  color: '#475569',
} as const;

const placeholderStyle = {
  padding: '16px 20px',
  borderRadius: '12px',
  border: '1px solid #e2e8f0',
  backgroundColor: '#f8fafc',
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#64748b',
} as const;

export default async function AdminSettingsPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Workspace settings</h1>
        <p>Bootstrap failed while loading the settings route.</p>
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

  // Phase 9: acknowledge workspace setup when visiting for the first time.
  // This sets setup_completed_at on the tenant row so the banner on /admin
  // disappears for all admins. Only fires when not yet acknowledged.
  const isFirstSetupVisit = !routeState.config.tenant.setupCompleted;
  if (isFirstSetupVisit) {
    await callWorkspaceSetupAck();
  }

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title="Workspace settings"
      subtitle="Configure workspace behaviour, security policies, and onboarding options for this tenant."
      me={routeState.me}
    >
      <div style={sectionStyle}>
        <div style={{ display: 'grid', gap: '10px' }}>
          <Link href={AUTHENTICATED_ADMIN_ENTRY_PATH} style={navLinkStyle}>
            ← Back to admin dashboard
          </Link>
          <Link href={ADMIN_INVITES_PATH} style={navLinkStyle}>
            → Manage invites
          </Link>
        </div>

        <div
          style={{
            display: 'grid',
            gap: '12px',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          }}
        >
          <div style={infoCardStyle}>
            <p style={labelStyle}>Workspace name</p>
            <p style={valueStyle}>{routeState.me.tenant.name}</p>
          </div>
          <div style={infoCardStyle}>
            <p style={labelStyle}>Workspace key</p>
            <p style={valueStyle}>
              <code>{routeState.me.tenant.key}</code>
            </p>
          </div>
          <div style={infoCardStyle}>
            <p style={labelStyle}>Setup</p>
            <p style={valueStyle}>
              {isFirstSetupVisit ? 'Marked complete on this visit' : 'Already completed'}
            </p>
          </div>
        </div>

        <div style={placeholderStyle}>
          <strong>Settings configuration — coming in later phases.</strong> This route is correctly
          SSR-gated for admin sessions and calls the workspace-setup-ack endpoint on first visit.
          Workspace configuration content (SSO, invite policy, MFA rules) belongs to later product
          phases once the auth module is fully locked.
        </div>
      </div>
    </AuthenticatedShell>
  );
}
