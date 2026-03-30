/**
 * frontend/src/app/auth/login/page.tsx
 *
 * WHY:
 * - Real public login screen for the current tenant.
 * - Uses SSR bootstrap for tenant-aware rendering and a client form for same-origin login.
 * - Also serves invite-continuation sign-in after POST /auth/invites/accept returns SIGN_IN.
 *
 * SIGNUP LINK GATING:
 * - Passes tenant.signupAllowed (not publicSignupEnabled) to <LoginForm>.
 *   signupAllowed = publicSignupEnabled && !adminInviteRequired.
 *   Using publicSignupEnabled alone would show a "Create account" link that
 *   the backend would reject when adminInviteRequired=true.
 *
 * RETURN-TO RULE:
 * - Only pass through a real safe returnTo from the URL.
 * - Do NOT default to '/' here. Plain login with no returnTo must let the
 *   post-auth redirect logic choose the correct role landing (/app or /admin).
 */

import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthCard } from '@/shared/auth/components/auth-card';
import { AuthErrorBanner } from '@/shared/auth/components/auth-error-banner';
import { AuthShell } from '@/shared/auth/components/auth-shell';
import { AuthNote } from '@/shared/auth/components/auth-form-ui';
import { LoginForm } from '@/shared/auth/components/login-form';
import { getRouteStateRedirectPath } from '@/shared/auth/redirects';
import { getReturnToPath, readQueryParam, type SearchParamsRecord } from '@/shared/auth/url-tokens';

export const dynamic = 'force-dynamic';

type PageProps = {
  searchParams: Promise<SearchParamsRecord>;
};

function getInviteContinuationNotice(inviteParam: string | null): string | null {
  if (inviteParam === 'accepted') {
    return 'Your invitation has been accepted. Sign in with your existing account to continue into this workspace.';
  }

  if (inviteParam === 'admin-mfa-setup') {
    return 'Your invitation has been accepted. Sign in to continue. Because this invite grants admin access, MFA setup will be required after sign-in.';
  }

  return null;
}

export default async function LoginPage({ searchParams }: PageProps) {
  const resolvedSearchParams = await searchParams;
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Sign in"
        subtitle="The login page could not load backend bootstrap truth for this request."
      >
        <AuthCard tone="danger">
          <AuthErrorBanner error={bootstrap.error} fallbackMessage="Unable to load login state." />
        </AuthCard>
      </AuthShell>
    );
  }

  if (bootstrap.routeState.kind !== 'PUBLIC_ENTRY') {
    redirect(getRouteStateRedirectPath(bootstrap.routeState));
  }

  const { tenant } = bootstrap.config;
  const returnTo = getReturnToPath(resolvedSearchParams);
  const inviteNotice = getInviteContinuationNotice(readQueryParam(resolvedSearchParams, 'invite'));

  return (
    <AuthShell
      eyebrow="Hubins"
      title={tenant.name ? `Sign in to ${tenant.name}` : 'Sign in'}
      subtitle="Use your workspace credentials or an allowed single sign-on provider."
    >
      <AuthCard
        title="Workspace access"
        description="Tenant availability, public signup visibility, and SSO options are all rendered from GET /auth/config for the current host-derived tenant."
      >
        {inviteNotice ? <AuthNote>{inviteNotice}</AuthNote> : null}
        <LoginForm
          ssoProviders={tenant.allowedSso}
          publicSignupEnabled={tenant.signupAllowed}
          returnTo={returnTo}
        />
      </AuthCard>
    </AuthShell>
  );
}
