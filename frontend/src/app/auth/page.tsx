/**
 * frontend/src/app/auth/page.tsx
 *
 * WHY:
 * - Public auth/bootstrap entry route.
 * - Uses the shared auth shell/card primitives so the next route pages can stay thin.
 *
 * RULES:
 * - Server Component only.
 * - Redirects away when backend truth says the user belongs in continuation or app flow.
 * - This is still a validation wrapper, not the final real auth form screen.
 */

import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthCard } from '@/shared/auth/components/auth-card';
import { AuthErrorBanner } from '@/shared/auth/components/auth-error-banner';
import { AuthShell } from '@/shared/auth/components/auth-shell';
import { SsoButtons } from '@/shared/auth/components/sso-buttons';
import {
  getRouteStateRedirectPath,
  TOPOLOGY_CHECK_PATH,
  AUTH_TENANT_UNAVAILABLE_PATH,
} from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

export default async function AuthEntryPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Auth bootstrap failed"
        subtitle="The public auth entry could not load backend bootstrap truth for this request."
        footer={
          <>
            Verify FE/BE wiring with <Link href={TOPOLOGY_CHECK_PATH}>Topology Check</Link>.
          </>
        }
      >
        <AuthCard tone="danger">
          <AuthErrorBanner
            error={bootstrap.error}
            fallbackMessage="Unable to load auth bootstrap."
          />
        </AuthCard>
      </AuthShell>
    );
  }

  if (bootstrap.routeState.kind === 'TENANT_UNAVAILABLE') {
    redirect(AUTH_TENANT_UNAVAILABLE_PATH);
  }

  if (bootstrap.routeState.kind !== 'PUBLIC_ENTRY') {
    redirect(getRouteStateRedirectPath(bootstrap.routeState));
  }

  const { tenant } = bootstrap.config;
  const title = tenant.name ? `Sign in to ${tenant.name}` : 'Sign in to Hubins';

  return (
    <AuthShell
      eyebrow="Hubins"
      title={title}
      subtitle="This Phase 2 wrapper validates the shared auth UI layer without hardcoding tenant or SSO truth in the page itself."
      footer={
        <>
          Password, signup, reset, invite, and continuation forms land in the next route-page phase.
        </>
      }
    >
      <AuthCard
        title="Workspace access"
        description="Public auth/bootstrap state comes directly from GET /auth/config for the current host-derived tenant."
      >
        <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
          Public signup is <strong>{tenant.publicSignupEnabled ? 'enabled' : 'disabled'}</strong>{' '}
          for this workspace.
        </p>

        <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
          Available SSO providers:{' '}
          {tenant.allowedSso.length ? tenant.allowedSso.join(', ') : 'none'}.
        </p>

        <SsoButtons providers={tenant.allowedSso} returnTo="/dashboard" />
      </AuthCard>
    </AuthShell>
  );
}
