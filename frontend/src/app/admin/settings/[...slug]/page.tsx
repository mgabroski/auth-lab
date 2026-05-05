/**
 * frontend/src/app/admin/settings/[...slug]/page.tsx
 *
 * WHY:
 * - Keeps the locked v1 Settings route family honest after wiring the real
 *   overview page, Modules hub, Personal builder, and Integrations page.
 * - Provides the SSR-gated shell only for the Communications placeholder route.
 * - Preserves absent treatment for Permissions, Workspace Experience, and
 *   unsupported child routes by returning 404.
 *
 * RULES:
 * - Auth bootstrap still owns route gating.
 * - Communications reads its minimal placeholder DTO from Settings, not local
 *   frontend copy or overview-derived fallback truth.
 * - No write flows, fake save buttons, or section-specific completion logic.
 * - Access, Account, Modules, Personal, and Integrations are intentionally
 *   excluded because they have dedicated real pages.
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
import { loadCommunicationsPlaceholder } from '@/shared/settings/loaders';

type SettingsRouteDefinition = {
  slugPath: string;
  title: string;
  loader: typeof loadCommunicationsPlaceholder;
};

const ROUTES: Record<string, SettingsRouteDefinition> = {
  communications: {
    slugPath: 'communications',
    title: 'Communications',
    loader: loadCommunicationsPlaceholder,
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

const mutedTextStyle = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#475569',
} as const;

const errorTextStyle = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#991b1b',
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

  const placeholder = await route.loader();

  if (!placeholder.ok) {
    return (
      <AuthenticatedShell
        eyebrow="Hubins admin workspace"
        title={route.title}
        subtitle="The Settings placeholder DTO could not be loaded for this route."
        me={routeState.me}
      >
        <div style={shellCardStyle}>
          <p style={errorTextStyle}>
            <code>GET /settings/{route.slugPath}</code> failed, so this route is not inventing a
            local fallback.
          </p>
          <p style={errorTextStyle}>{placeholder.error.message}</p>
        </div>
      </AuthenticatedShell>
    );
  }

  const data = placeholder.data;

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title={data.title}
      subtitle={data.description}
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
              {data.title}
            </h2>
            <SettingsStatusChip status={data.status} />
          </div>
          <p style={mutedTextStyle}>{data.description}</p>
          <ul
            style={{
              margin: 0,
              paddingLeft: '18px',
              display: 'grid',
              gap: '6px',
              color: '#475569',
              fontSize: '13px',
              lineHeight: 1.6,
            }}
          >
            {data.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
          <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#64748b' }}>
            Live configuration available: {data.liveConfigurationAvailable ? 'yes' : 'no'} ·
            Mutation endpoints available: {data.mutationEndpointsAvailable ? 'yes' : 'no'}
          </p>
        </section>
      </div>
    </AuthenticatedShell>
  );
}
