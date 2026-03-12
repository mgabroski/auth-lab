/**
 * frontend/src/app/accept-invite/page.tsx
 *
 * WHY:
 * - Invite email links land here (`/accept-invite?token=...`).
 * - The page reads the token from the URL and drives the real backend invite-accept contract.
 * - It is intentionally separate from public signup because invite onboarding is a distinct provisioning path.
 */

import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthCard } from '@/shared/auth/components/auth-card';
import { AcceptInviteFlow } from '@/shared/auth/components/accept-invite-flow';
import { AuthErrorBanner } from '@/shared/auth/components/auth-error-banner';
import { AuthShell } from '@/shared/auth/components/auth-shell';
import {
  AUTH_LOGIN_PATH,
  AUTH_REGISTER_PATH,
  AUTH_TENANT_UNAVAILABLE_PATH,
} from '@/shared/auth/redirects';
import { getInviteToken, type SearchParamsRecord } from '@/shared/auth/url-tokens';

export const dynamic = 'force-dynamic';

type PageProps = {
  searchParams: Promise<SearchParamsRecord>;
};

export default async function AcceptInvitePage({ searchParams }: PageProps) {
  const resolvedSearchParams = await searchParams;
  const token = getInviteToken(resolvedSearchParams);
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Accept invitation"
        subtitle="The invite acceptance page could not load backend bootstrap truth for this request."
      >
        <AuthCard tone="danger">
          <AuthErrorBanner
            error={bootstrap.error}
            fallbackMessage="Unable to load invite acceptance state."
          />
        </AuthCard>
      </AuthShell>
    );
  }

  if (bootstrap.routeState.kind === 'TENANT_UNAVAILABLE') {
    redirect(AUTH_TENANT_UNAVAILABLE_PATH);
  }

  const tenantName = bootstrap.config.tenant.name;
  const registerHref = token
    ? `${AUTH_REGISTER_PATH}?token=${encodeURIComponent(token)}`
    : AUTH_REGISTER_PATH;

  return (
    <AuthShell
      eyebrow="Hubins"
      title={tenantName ? `Join ${tenantName}` : 'Accept invitation'}
      subtitle="This page submits the invite token from the URL to the real backend accept-invite endpoint and then routes into the correct provisioning continuation."
    >
      <AuthCard
        title="Workspace invitation"
        description="Invite acceptance does not assume a session. The backend decides whether the next truthful step is set-password registration or sign-in."
      >
        <AcceptInviteFlow
          token={token}
          registerHref={registerHref}
          signInHref={`${AUTH_LOGIN_PATH}?invite=accepted`}
          adminSignInHref={`${AUTH_LOGIN_PATH}?invite=admin-mfa-setup`}
        />
      </AuthCard>
    </AuthShell>
  );
}
