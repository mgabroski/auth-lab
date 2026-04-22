/**
 * frontend/src/app/admin/settings/modules/personal/page.tsx
 *
 * WHY:
 * - Ships the real Personal field-configuration foundation page.
 * - Uses the backend-owned Personal foundation DTO instead of the old shell route.
 * - Keeps the current repo honest: this page now shows family review plus
 *   field-rule foundations without pretending the later Personal save flows
 *   already exist.
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
import { PersonalSettingsFoundation } from '@/shared/settings/components/personal-settings-foundation';
import { loadPersonalSettings } from '@/shared/settings/loaders';

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

export default async function AdminSettingsPersonalPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Personal settings</h1>
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

  const personal = await loadPersonalSettings();

  if (!personal.ok && isApiHttpError(personal.error) && personal.error.status === 404) {
    notFound();
  }

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title="Personal settings"
      subtitle="Review the Personal foundations. Family review and field-rule guidance are now visible; the section builder and final save contract remain later-phase work."
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

        {personal.ok ? (
          <PersonalSettingsFoundation data={personal.data} />
        ) : (
          <section style={errorCardStyle}>
            <h2 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2 }}>
              Personal settings is unavailable
            </h2>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>
              The frontend could not load <code>GET /settings/modules/personal</code>, so it is not
              rendering placeholder shell copy here.
            </p>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>{personal.error.message}</p>
          </section>
        )}
      </div>
    </AuthenticatedShell>
  );
}
