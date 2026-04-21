/**
 * frontend/src/app/admin/settings/page.tsx
 *
 * WHY:
 * - Replaces the old auth-scaffold placeholder with the first real Settings
 *   overview consumer.
 * - Uses auth bootstrap only for SSR route gating and `GET /settings/overview`
 *   for all setup progress, card treatment, and next-action truth.
 * - Preserves the locked v1 overview contract: required vs optional grouping,
 *   placeholder-only cards, and absent Permissions treatment.
 */
import React from 'react';
import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import {
  AUTHENTICATED_ADMIN_ENTRY_PATH,
  ADMIN_INVITES_PATH,
  getRouteStateRedirectPath,
} from '@/shared/auth/redirects';
import { SettingsOverviewCard } from '@/shared/settings/components/settings-overview-card';
import { SettingsStatusChip } from '@/shared/settings/components/settings-status-chip';
import { loadSettingsOverview } from '@/shared/settings/loaders';

export const dynamic = 'force-dynamic';

const navLinkStyle = {
  color: '#0f172a',
  fontSize: '14px',
  fontWeight: 600,
  textDecoration: 'none',
} as const;

const calloutBaseStyle = {
  display: 'grid',
  gap: '8px',
  padding: '18px 20px',
  borderRadius: '20px',
  border: '1px solid transparent',
} as const;

const inProgressCalloutStyle = {
  ...calloutBaseStyle,
  backgroundColor: '#eff6ff',
  borderColor: '#bfdbfe',
  color: '#1d4ed8',
} as const;

const completeCalloutStyle = {
  ...calloutBaseStyle,
  backgroundColor: '#f0fdf4',
  borderColor: '#bbf7d0',
  color: '#166534',
} as const;

const errorCalloutStyle = {
  ...calloutBaseStyle,
  backgroundColor: '#fef2f2',
  borderColor: '#fecaca',
  color: '#991b1b',
} as const;

const sectionHeadingStyle = {
  margin: 0,
  fontSize: '22px',
  lineHeight: 1.2,
  color: '#0f172a',
} as const;

const sectionCaptionStyle = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#475569',
} as const;

const cardGridStyle = {
  display: 'grid',
  gap: '16px',
  gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
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

  const overview = await loadSettingsOverview();

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title="Workspace settings"
      subtitle="Review required setup progress, open section routes, and track which tenant surfaces are live, optional, or placeholder-only."
      me={routeState.me}
    >
      <div style={{ display: 'grid', gap: '20px' }}>
        <div style={{ display: 'grid', gap: '10px' }}>
          <Link href={AUTHENTICATED_ADMIN_ENTRY_PATH} style={navLinkStyle}>
            ← Back to admin dashboard
          </Link>
          <Link href={ADMIN_INVITES_PATH} style={navLinkStyle}>
            → Manage invites
          </Link>
        </div>

        {overview.ok ? (
          <>
            <section
              style={
                overview.data.overallStatus === 'COMPLETE'
                  ? completeCalloutStyle
                  : inProgressCalloutStyle
              }
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
                <h2 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2 }}>
                  {overview.data.overallStatus === 'COMPLETE'
                    ? 'Your workspace is fully configured'
                    : 'Continue workspace setup'}
                </h2>
                <SettingsStatusChip status={overview.data.overallStatus} />
              </div>
              <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>
                {overview.data.overallStatus === 'COMPLETE'
                  ? 'Required setup work is complete. Optional and placeholder-only settings still remain available from this overview.'
                  : 'Settings owns the detailed progress model. Use the next action or open any section card below to continue.'}
              </p>
              {overview.data.nextAction ? (
                <Link href={overview.data.nextAction.href} style={navLinkStyle}>
                  → {overview.data.nextAction.label}
                </Link>
              ) : null}
            </section>

            <section style={{ display: 'grid', gap: '14px' }}>
              <div style={{ display: 'grid', gap: '4px' }}>
                <h2 style={sectionHeadingStyle}>Required sections</h2>
                <p style={sectionCaptionStyle}>
                  These sections gate overall setup completion in the current repo.
                </p>
              </div>
              <div style={cardGridStyle}>
                {overview.data.cards
                  .filter((card) => card.isRequired)
                  .map((card) => (
                    <SettingsOverviewCard key={card.key} card={card} />
                  ))}
              </div>
            </section>

            <section style={{ display: 'grid', gap: '14px' }}>
              <div style={{ display: 'grid', gap: '4px' }}>
                <h2 style={sectionHeadingStyle}>Optional sections</h2>
                <p style={sectionCaptionStyle}>
                  Non-gating, navigation-only, and placeholder-only surfaces remain grouped here.
                </p>
              </div>
              <div style={cardGridStyle}>
                {overview.data.cards
                  .filter((card) => !card.isRequired)
                  .map((card) => (
                    <SettingsOverviewCard key={card.key} card={card} />
                  ))}
              </div>
            </section>
          </>
        ) : (
          <section style={errorCalloutStyle}>
            <h2 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2 }}>
              Workspace settings overview is unavailable
            </h2>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>
              The frontend could not load <code>GET /settings/overview</code>, so it is not
              rendering a fallback or reusing auth scaffold truth.
            </p>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>{overview.error.message}</p>
          </section>
        )}
      </div>
    </AuthenticatedShell>
  );
}
