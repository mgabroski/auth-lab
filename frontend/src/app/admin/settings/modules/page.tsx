/**
 * frontend/src/app/admin/settings/modules/page.tsx
 *
 * WHY:
 * - Ships the real v1 Modules hub page instead of the old shell route.
 * - Uses the backend-owned Modules hub DTO and keeps the page navigation-only.
 * - Preserves the locked treatment: Personal is the only live actionable entry;
 *   future modules remain placeholder-only and non-interactive.
 */

import React from 'react';
import Link from 'next/link';
import { redirect } from 'next/navigation';

import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import {
  ADMIN_SETTINGS_PATH,
  AUTHENTICATED_ADMIN_ENTRY_PATH,
  getRouteStateRedirectPath,
} from '@/shared/auth/redirects';
import { ModulesHub } from '@/shared/settings/components/modules-hub';
import { loadModulesHub } from '@/shared/settings/loaders';

const navLinkStyle = {
  color: '#0f172a',
  fontSize: '14px',
  fontWeight: 600,
  textDecoration: 'none',
} as const;

const errorCardStyle = {
  display: 'grid',
  gap: '8px',
  padding: '18px 20px',
  borderRadius: '20px',
  border: '1px solid #fecaca',
  backgroundColor: '#fef2f2',
  color: '#991b1b',
} as const;

export const dynamic = 'force-dynamic';

export default async function AdminSettingsModulesPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Modules</h1>
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

  const modules = await loadModulesHub();

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title="Modules"
      subtitle="Open the navigation-only modules hub. Personal is the only live actionable module route in v1."
      me={routeState.me}
    >
      <div style={{ display: 'grid', gap: '16px' }}>
        <div style={{ display: 'grid', gap: '10px' }}>
          <Link href={ADMIN_SETTINGS_PATH} style={navLinkStyle}>
            ← Back to workspace settings
          </Link>
          <Link href={AUTHENTICATED_ADMIN_ENTRY_PATH} style={navLinkStyle}>
            ← Back to admin dashboard
          </Link>
        </div>

        {modules.ok ? (
          <ModulesHub data={modules.data} />
        ) : (
          <section style={errorCardStyle}>
            <h2 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2 }}>Modules is unavailable</h2>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>
              The frontend could not load <code>GET /settings/modules</code>, so it is not rendering
              placeholder shell copy here.
            </p>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>{modules.error.message}</p>
          </section>
        )}
      </div>
    </AuthenticatedShell>
  );
}
