/**
 * frontend/src/app/admin/settings/operational-access/page.tsx
 *
 * WHY:
 * - Provides the safe Operational Access admin shell gated by backend Settings
 *   overview capability truth.
 * - Keeps /admin/settings/access unchanged as Access & Security while giving
 *   capability-enabled tenants a future OA landing surface with no grants,
 *   coverage, resolver behavior, or runtime Agent visibility.
 *
 * RULES:
 * - Admin-only via auth bootstrap route state.
 * - Hidden/404 unless the backend Settings overview includes the
 *   operationalAccess card.
 * - Do not compute effective access in the frontend.
 * - Do not add configuration forms or mutation behavior in this step.
 */

import React, { type CSSProperties } from 'react';
import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';

import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import {
  ADMIN_SETTINGS_PATH,
  AUTHENTICATED_ADMIN_ENTRY_PATH,
  getRouteStateRedirectPath,
} from '@/shared/auth/redirects';
import { SettingsStatusChip } from '@/shared/settings/components/settings-status-chip';
import { loadSettingsOverview } from '@/shared/settings/loaders';

const navLinkStyle: CSSProperties = {
  color: '#0f172a',
  fontSize: '14px',
  fontWeight: 600,
  textDecoration: 'none',
};

const shellCardStyle: CSSProperties = {
  display: 'grid',
  gap: '14px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -28px rgba(15, 23, 42, 0.35)',
};

const mutedTextStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#475569',
};

const bulletListStyle: CSSProperties = {
  margin: 0,
  paddingLeft: '18px',
  display: 'grid',
  gap: '8px',
  color: '#475569',
  fontSize: '13px',
  lineHeight: 1.6,
};

const errorTextStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#991b1b',
};

export default async function OperationalAccessSettingsPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Operational Access</h1>
        <p>Bootstrap failed while loading the Operational Access shell.</p>
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

  const overview = await loadSettingsOverview();

  if (!overview.ok) {
    return (
      <AuthenticatedShell
        eyebrow="Hubins admin workspace"
        title="Operational Access"
        subtitle="The backend capability read could not be loaded, so this route is not rendering a local fallback."
        me={routeState.me}
      >
        <section style={shellCardStyle}>
          <p style={errorTextStyle}>
            <code>GET /settings/overview</code> failed while checking the Operational Access
            capability boundary.
          </p>
          <p style={errorTextStyle}>{overview.error.message}</p>
        </section>
      </AuthenticatedShell>
    );
  }

  const card = overview.data.cards.find((candidate) => candidate.key === 'operationalAccess');

  if (!card) {
    notFound();
  }

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title="Operational Access"
      subtitle="Safe shell only. Future Agent grants and coverage are not configured here yet."
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

        <section style={shellCardStyle}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            <h2 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2, color: '#0f172a' }}>
              Capability enabled — configuration not shipped
            </h2>
            <SettingsStatusChip status={card.status} />
          </div>

          <p style={mutedTextStyle}>{card.description}</p>
          <p style={mutedTextStyle}>
            This page exists only to prove the tenant capability boundary and route guard. It does
            not create runtime access.
          </p>

          <ul style={bulletListStyle}>
            <li>Agent group membership remains provisioning-only.</li>
            <li>No Operational Access grants are available in this step.</li>
            <li>
              No Assigned Areas, Responsible For, Oversight, Temporary Coverage, or Special Access
              is shipped.
            </li>
            <li>No Effective Access Resolver or runtime visibility changes are shipped.</li>
            <li>/admin/settings/access remains Access &amp; Security.</li>
          </ul>
        </section>
      </div>
    </AuthenticatedShell>
  );
}
