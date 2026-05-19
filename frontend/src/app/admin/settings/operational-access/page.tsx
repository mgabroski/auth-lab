/**
 * frontend/src/app/admin/settings/operational-access/page.tsx
 *
 * WHY:
 * - Provides the capability-gated Operational Access admin configuration shell.
 * - Renders backend-owned Step 3 configuration read models: product-defined
 *   actions, Primary Where, Which Records, active Agent groups, and Responsible For readiness.
 *
 * RULES:
 * - Admin-only via auth bootstrap route state.
 * - Hidden/404 unless the backend Settings overview includes the operationalAccess card.
 * - Do not compute effective access in the frontend.
 * - Do not claim runtime Agent visibility, resolver behavior, Assigned Areas,
 *   Oversight, Temporary Coverage, or Special Access is shipped.
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
import { loadOperationalAccessFoundation } from '@/shared/operational-access/loaders';
import { SettingsStatusChip } from '@/shared/settings/components/settings-status-chip';
import { loadSettingsOverview } from '@/shared/settings/loaders';

const navLinkStyle: CSSProperties = {
  color: '#0f172a',
  fontSize: '14px',
  fontWeight: 600,
  textDecoration: 'none',
};

const cardStyle: CSSProperties = {
  display: 'grid',
  gap: '14px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -28px rgba(15, 23, 42, 0.35)',
};

const gridStyle: CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
  gap: '12px',
};

const mutedTextStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#475569',
};

const smallTextStyle: CSSProperties = {
  margin: 0,
  fontSize: '13px',
  lineHeight: 1.6,
  color: '#475569',
};

const labelStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  width: 'fit-content',
  padding: '4px 9px',
  borderRadius: '999px',
  backgroundColor: '#eff6ff',
  color: '#1d4ed8',
  fontSize: '12px',
  fontWeight: 700,
};

const warningStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#92400e',
};

const errorTextStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#991b1b',
};

const listStyle: CSSProperties = {
  margin: 0,
  paddingLeft: '18px',
  display: 'grid',
  gap: '8px',
  color: '#475569',
  fontSize: '13px',
  lineHeight: 1.6,
};

export const dynamic = 'force-dynamic';

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
        subtitle="The backend capability read could not be loaded, so this route is not rendering local fallback truth."
        me={routeState.me}
      >
        <section style={cardStyle}>
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

  const foundation = await loadOperationalAccessFoundation();

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title="Operational Access"
      subtitle="Configure Agent group toolboxes and base coverage. Runtime Agent visibility is still not active."
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

        <section style={cardStyle}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            <h2 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2, color: '#0f172a' }}>
              Operational Access configuration foundation
            </h2>
            <SettingsStatusChip status={card.status} />
          </div>
          <p style={mutedTextStyle}>{card.description}</p>
          <ul style={listStyle}>
            <li>What this group can do is selected from product-defined actions.</li>
            <li>Where this group normally works is stored separately as Primary Where.</li>
            <li>
              Which records is stored separately as a product-defined work queue or record choice.
            </li>
            <li>
              Responsible For uses exact active tenant people. Assigned Areas waits for stable area
              IDs.
            </li>
            <li>No runtime visibility changes are shipped.</li>
            <li>/admin/settings/access remains Access &amp; Security.</li>
          </ul>
        </section>

        {foundation.ok ? (
          <>
            <section style={cardStyle}>
              <h2 style={{ margin: 0, fontSize: '18px', color: '#0f172a' }}>Active Agent groups</h2>
              {foundation.data.groups.length === 0 ? (
                <p style={mutedTextStyle}>
                  No active Agent groups exist yet. Create an Agent group in People &amp; Teams
                  before configuring Operational Access.
                </p>
              ) : (
                <div style={gridStyle}>
                  {foundation.data.groups.map((group) => (
                    <article key={group.id} style={{ ...cardStyle, boxShadow: 'none' }}>
                      <span style={labelStyle}>Agent group</span>
                      <h3 style={{ margin: 0, fontSize: '16px', color: '#0f172a' }}>
                        {group.name}
                      </h3>
                      {group.description ? <p style={smallTextStyle}>{group.description}</p> : null}
                      <p style={smallTextStyle}>{group.memberCount} members</p>
                      <p style={smallTextStyle}>{group.grantCount} configured actions</p>
                      <p style={smallTextStyle}>
                        {group.responsibleForAssignmentCount} Responsible For assignments
                      </p>
                    </article>
                  ))}
                </div>
              )}
            </section>

            <section style={cardStyle}>
              <h2 style={{ margin: 0, fontSize: '18px', color: '#0f172a' }}>
                What this group can do
              </h2>
              <div style={gridStyle}>
                {foundation.data.catalog.actions.map((action) => (
                  <article key={action.key} style={{ ...cardStyle, boxShadow: 'none' }}>
                    <span style={labelStyle}>{action.category}</span>
                    <h3 style={{ margin: 0, fontSize: '16px', color: '#0f172a' }}>
                      {action.label}
                    </h3>
                    <p style={smallTextStyle}>{action.description}</p>
                  </article>
                ))}
              </div>
            </section>

            <section style={cardStyle}>
              <h2 style={{ margin: 0, fontSize: '18px', color: '#0f172a' }}>
                Where this group normally works
              </h2>
              <div style={gridStyle}>
                {foundation.data.catalog.primaryWhere.map((where) => (
                  <article key={where.key} style={{ ...cardStyle, boxShadow: 'none' }}>
                    <h3 style={{ margin: 0, fontSize: '16px', color: '#0f172a' }}>{where.label}</h3>
                    <p style={smallTextStyle}>{where.description}</p>
                  </article>
                ))}
              </div>
            </section>

            <section style={cardStyle}>
              <h2 style={{ margin: 0, fontSize: '18px', color: '#0f172a' }}>Which records</h2>
              <div style={gridStyle}>
                {foundation.data.catalog.whichRecords.map((choice) => (
                  <article key={choice.key} style={{ ...cardStyle, boxShadow: 'none' }}>
                    <span style={labelStyle}>{choice.category}</span>
                    <h3 style={{ margin: 0, fontSize: '16px', color: '#0f172a' }}>
                      {choice.label}
                    </h3>
                    <p style={smallTextStyle}>{choice.description}</p>
                  </article>
                ))}
              </div>
            </section>

            <section style={cardStyle}>
              <h2 style={{ margin: 0, fontSize: '18px', color: '#0f172a' }}>Coverage foundation</h2>
              <p style={mutedTextStyle}>{foundation.data.catalog.coverage.responsibleFor.reason}</p>
              <p style={warningStyle}>{foundation.data.catalog.coverage.assignedAreas.reason}</p>
              <ul style={listStyle}>
                {foundation.data.catalog.deferred.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </section>
          </>
        ) : (
          <section style={cardStyle}>
            <h2 style={{ margin: 0, fontSize: '18px', color: '#991b1b' }}>
              Operational Access configuration is unavailable
            </h2>
            <p style={errorTextStyle}>
              The frontend could not load the backend Operational Access configuration read model,
              so it is not rendering fallback group, action, Primary Where, Which Records, or
              coverage truth.
            </p>
            <p style={errorTextStyle}>{foundation.error.message}</p>
          </section>
        )}
      </div>
    </AuthenticatedShell>
  );
}
