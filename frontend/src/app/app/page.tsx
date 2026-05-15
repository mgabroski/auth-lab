/**
 * frontend/src/app/app/page.tsx
 *
 * WHY:
 * - Minimal but real authenticated workspace landing route for non-admin sessions.
 * - Only renders when backend bootstrap truth resolves to a fully-authenticated
 *   AGENT or USER session.
 * - AGENT and USER share this shell today, but future operational modules must
 *   use backend-resolved access to distinguish Agent operational scope from User
 *   own/self-service behavior.
 */

import React, { type CSSProperties } from 'react';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import type { MembershipRole } from '@/shared/auth/contracts';
import { getRouteStateRedirectPath } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

const bodyStyle: CSSProperties = {
  display: 'grid',
  gap: '12px',
};

const headingStyle: CSSProperties = {
  margin: 0,
  fontSize: '22px',
  lineHeight: 1.2,
};

const textStyle: CSSProperties = {
  margin: 0,
  fontSize: '15px',
  lineHeight: 1.7,
  color: '#475569',
};

function workspaceBodyForRole(role: MembershipRole) {
  switch (role) {
    case 'AGENT':
      return {
        heading: 'No operational areas available',
        body: 'You do not currently have access to operational areas. Contact your administrator.',
        support:
          'This shared shell is intentionally neutral. Future work areas must use backend-resolved access before showing scoped data or actions.',
      };
    case 'USER':
      return {
        heading: 'Welcome',
        body: 'Your self-service workspace is available. This page confirms authenticated handoff without exposing admin settings or tenant management tools.',
        support:
          'User sessions remain own/self-service by default. Cross-person operational data is not rendered from this shell.',
      };
    case 'ADMIN':
      return {
        heading: 'Admin handoff required',
        body: 'Admin sessions are routed to the admin dashboard instead of this workspace shell.',
        support:
          'This branch is defensive because the page redirects admin route states before rendering.',
      };
    default: {
      const exhaustiveCheck: never = role;
      return {
        heading: 'Workspace',
        body: `Unsupported role: ${String(exhaustiveCheck)}`,
        support: 'The route guard should prevent unsupported role rendering.',
      };
    }
  }
}

export default async function WorkspaceAppPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Workspace</h1>
        <p>Bootstrap failed while loading the authenticated workspace route.</p>
        <p>
          <strong>Error:</strong> {bootstrap.error.message}
        </p>
      </main>
    );
  }

  const routeState = bootstrap.routeState;

  if (routeState.kind !== 'AUTHENTICATED_WORKSPACE') {
    redirect(getRouteStateRedirectPath(routeState));
  }

  const body = workspaceBodyForRole(routeState.me.membership.role);

  return (
    <AuthenticatedShell
      eyebrow="Hubins workspace"
      title="Workspace"
      subtitle="Authenticated handoff complete. Authenticated workspace shell for User and Agent sessions."
      me={routeState.me}
    >
      <div style={bodyStyle}>
        <h2 style={headingStyle}>{body.heading}</h2>
        <p style={textStyle}>{body.body}</p>
        <p style={textStyle}>{body.support}</p>
      </div>
    </AuthenticatedShell>
  );
}
