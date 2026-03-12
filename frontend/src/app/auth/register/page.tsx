/**
 * frontend/src/app/auth/register/page.tsx
 *
 * WHY:
 * - Real invite-driven registration/set-password continuation route.
 * - Consumes the accepted invite token from the URL and calls POST /auth/register.
 * - Distinct from public signup because the backend requires an already-accepted invite.
 */

import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthCard } from '@/shared/auth/components/auth-card';
import { AuthErrorBanner } from '@/shared/auth/components/auth-error-banner';
import { InviteRegisterForm } from '@/shared/auth/components/invite-register-form';
import { AuthShell } from '@/shared/auth/components/auth-shell';
import { AuthNote } from '@/shared/auth/components/auth-form-ui';
import {
  AUTH_ACCEPT_INVITE_PATH,
  AUTH_LOGIN_PATH,
  AUTH_TENANT_UNAVAILABLE_PATH,
  getRouteStateRedirectPath,
} from '@/shared/auth/redirects';
import {
  getInviteToken,
  getReturnToPath,
  normalizeReturnToPath,
  type SearchParamsRecord,
} from '@/shared/auth/url-tokens';

export const dynamic = 'force-dynamic';

type PageProps = {
  searchParams: Promise<SearchParamsRecord>;
};

export default async function RegisterPage({ searchParams }: PageProps) {
  const resolvedSearchParams = await searchParams;
  const token = getInviteToken(resolvedSearchParams);
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Set your password"
        subtitle="The invite registration page could not load backend bootstrap truth for this request."
      >
        <AuthCard tone="danger">
          <AuthErrorBanner
            error={bootstrap.error}
            fallbackMessage="Unable to load invite registration state."
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
  const returnTo = normalizeReturnToPath(getReturnToPath(resolvedSearchParams), '/');
  const acceptInviteHref = token
    ? `${AUTH_ACCEPT_INVITE_PATH}?token=${encodeURIComponent(token)}`
    : AUTH_ACCEPT_INVITE_PATH;

  return (
    <AuthShell
      eyebrow="Hubins"
      title={tenant.name ? `Finish setting up ${tenant.name}` : 'Set your password'}
      subtitle="This route uses the accepted invite token from the URL and calls the real invite registration endpoint to create the first authenticated session."
      footer={<Link href={AUTH_LOGIN_PATH}>Back to sign in</Link>}
    >
      <AuthCard
        title="Invite-based account setup"
        description="Use the same email address that received the invite. The backend will only accept registration when the invite token has already been accepted for this workspace."
      >
        {token ? (
          <InviteRegisterForm token={token} returnTo={returnTo} />
        ) : (
          <>
            <AuthNote>
              This page is missing the invite token. Reopen the invitation email and accept the
              invite first so the backend can mark it ready for registration.
            </AuthNote>
            <Link href={acceptInviteHref}>Go back to invite acceptance</Link>
          </>
        )}
      </AuthCard>
    </AuthShell>
  );
}
