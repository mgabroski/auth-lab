/**
 * frontend/src/app/admin/settings/integrations/page.tsx
 *
 * WHY:
 * - Wires the v1 Integrations Settings page to the real backend-owned
 *   `GET /settings/integrations` DTO.
 * - Keeps Integrations informational only: SSO status visibility plus deferred
 *   HRIS/Stripe treatment, with no tenant credential or connection flow UI.
 *
 * RULES:
 * - SSR-gated admin route.
 * - No local fallback truth.
 * - No save buttons, provider setup wizards, or fake connected state.
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
import { IntegrationsSettingsView } from '@/shared/settings/components/integrations-settings-view';
import { loadIntegrationsSettings } from '@/shared/settings/loaders';

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

export default async function AdminSettingsIntegrationsPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Integrations</h1>
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

  const integrations = await loadIntegrationsSettings();

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title="Integrations"
      subtitle="View SSO readiness truth and deferred tenant-configured integrations without creating credential entry or fake connection flows."
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

        {integrations.ok ? (
          <IntegrationsSettingsView data={integrations.data} />
        ) : (
          <section style={errorCardStyle}>
            <h2 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2 }}>
              Integrations are unavailable
            </h2>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>
              The frontend could not load <code>GET /settings/integrations</code>, so it is not
              rendering placeholder or fallback readiness truth.
            </p>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>
              {integrations.error.message}
            </p>
          </section>
        )}
      </div>
    </AuthenticatedShell>
  );
}
