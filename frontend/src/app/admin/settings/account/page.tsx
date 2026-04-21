/**
 * frontend/src/app/admin/settings/account/page.tsx
 *
 * WHY:
 * - Ships the real v1 Account Settings page in the tenant admin surface.
 * - Uses the backend-owned Account DTO and explicit per-card save boundaries instead of the old shell route.
 * - Preserves the locked contract that Account is live but non-gating in v1.
 */

import React from 'react';
import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';

import { isApiHttpError } from '@/shared/auth/api-errors';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import {
  ADMIN_SETTINGS_PATH,
  AUTHENTICATED_ADMIN_ENTRY_PATH,
  getRouteStateRedirectPath,
} from '@/shared/auth/redirects';
import { AccountSettingsForm } from '@/shared/settings/components/account-settings-form';
import { loadAccountSettings } from '@/shared/settings/loaders';

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

export default async function AdminSettingsAccountPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Account Settings</h1>
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

  const account = await loadAccountSettings();

  if (!account.ok && isApiHttpError(account.error) && account.error.status === 404) {
    notFound();
  }

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title="Account Settings"
      subtitle="Configure the allowed branding, organization structure, and company calendar values for this workspace."
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

        {account.ok ? (
          <AccountSettingsForm initialData={account.data} />
        ) : (
          <section style={errorCardStyle}>
            <h2 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2 }}>
              Account Settings is unavailable
            </h2>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>
              The frontend could not load <code>GET /settings/account</code>, so it is not rendering
              placeholder or fallback truth.
            </p>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>{account.error.message}</p>
          </section>
        )}
      </div>
    </AuthenticatedShell>
  );
}
