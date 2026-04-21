/**
 * frontend/src/app/admin/settings/[...slug]/page.tsx
 *
 * WHY:
 * - Keeps the locked v1 Settings route family honest after wiring the real
 *   overview page, without pretending that later section implementations are
 *   already interactive.
 * - Provides SSR-gated route shells for the remaining live v1 paths and the
 *   Communications placeholder route. Access now has a dedicated page.
 * - Preserves absent treatment for Permissions by returning 404.
 *
 * RULES:
 * - Auth bootstrap still owns route gating.
 * - Settings overview remains the only read source used here.
 * - No write flows, fake save buttons, or section-specific completion logic.
 * - Access and Account are intentionally excluded because they now have
 *   dedicated real pages.
 */
import React from 'react';
import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import {
  AUTHENTICATED_ADMIN_ENTRY_PATH,
  ADMIN_SETTINGS_PATH,
  getRouteStateRedirectPath,
} from '@/shared/auth/redirects';
import { SettingsStatusChip } from '@/shared/settings/components/settings-status-chip';
import type { SettingsOverviewCardKey } from '@/shared/settings/contracts';
import { loadSettingsOverview } from '@/shared/settings/loaders';

type SettingsRouteDefinition = {
  slugPath: string;
  title: string;
  overviewCardKey: SettingsOverviewCardKey;
  description: string;
  placeholderOnly?: boolean;
};

const ROUTES: Record<string, SettingsRouteDefinition> = {
  modules: {
    slugPath: 'modules',
    title: 'Modules',
    overviewCardKey: 'modules',
    description:
      'This route acts as the modules hub shell. Personal remains the only live actionable child in v1, but the detailed modules UX is not yet interactive in the current repo.',
  },
  'modules/personal': {
    slugPath: 'modules/personal',
    title: 'Personal settings',
    overviewCardKey: 'modules',
    description:
      'Personal is the only live actionable module child in v1. This route now resolves honestly, but the full family review, field configuration, and section-builder flow is still deferred.',
  },
  integrations: {
    slugPath: 'integrations',
    title: 'Integrations',
    overviewCardKey: 'integrations',
    description:
      'This route is the current shell for informational SSO readiness and deferred integrations. The detailed cards are not yet interactive in the current repo.',
  },
  communications: {
    slugPath: 'communications',
    title: 'Communications',
    overviewCardKey: 'communications',
    description:
      'Communications lets you manage email templates and notification rules for your workspace. This area is coming soon.',
    placeholderOnly: true,
  },
};

const navLinkStyle = {
  color: '#0f172a',
  fontSize: '14px',
  fontWeight: 600,
  textDecoration: 'none',
} as const;

const shellCardStyle = {
  display: 'grid',
  gap: '12px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -28px rgba(15, 23, 42, 0.35)',
} as const;

type SettingsRouteShellPageProps = {
  params: Promise<{
    slug: string[];
  }>;
};

export default async function SettingsRouteShellPage({ params }: SettingsRouteShellPageProps) {
  const { slug } = await params;
  const route = ROUTES[slug.join('/')];

  if (!route) {
    notFound();
  }

  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Settings section</h1>
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

  if (!overview.ok) {
    return (
      <AuthenticatedShell
        eyebrow="Hubins admin workspace"
        title={route.title}
        subtitle="Settings overview data could not be loaded for this route."
        me={routeState.me}
      >
        <div style={shellCardStyle}>
          <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#991b1b' }}>
            <code>GET /settings/overview</code> failed, so this route is not inventing a local
            fallback.
          </p>
          <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#991b1b' }}>
            {overview.error.message}
          </p>
        </div>
      </AuthenticatedShell>
    );
  }

  const card = overview.data.cards.find((candidate) => candidate.key === route.overviewCardKey);

  if (!card) {
    notFound();
  }

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title={route.title}
      subtitle={card.description}
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
              {route.title}
            </h2>
            <SettingsStatusChip status={card.status} />
          </div>
          <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
            {route.description}
          </p>
          {card.warnings.length > 0 ? (
            <ul
              style={{
                margin: 0,
                paddingLeft: '18px',
                display: 'grid',
                gap: '6px',
                color: '#9a3412',
                fontSize: '13px',
                lineHeight: 1.6,
              }}
            >
              {card.warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          ) : null}
          <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#64748b' }}>
            {route.placeholderOnly
              ? 'This route is intentionally placeholder-only in the current repo.'
              : 'This route now resolves honestly, but its detailed interactive implementation belongs to later Settings work.'}
          </p>
        </section>
      </div>
    </AuthenticatedShell>
  );
}
