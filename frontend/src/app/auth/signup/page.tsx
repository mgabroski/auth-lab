/**
 * frontend/src/app/auth/signup/page.tsx
 *
 * WHY:
 * - Public signup screen for tenants that enable self-service registration.
 * - Still respects SSR bootstrap truth before rendering any form UI.
 */

import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthCard } from '@/shared/auth/components/auth-card';
import { AuthErrorBanner } from '@/shared/auth/components/auth-error-banner';
import { AuthShell } from '@/shared/auth/components/auth-shell';
import { AuthNote } from '@/shared/auth/components/auth-form-ui';
import { SignupForm } from '@/shared/auth/components/signup-form';
import { AUTH_LOGIN_PATH, getRouteStateRedirectPath } from '@/shared/auth/redirects';
import {
  getReturnToPath,
  normalizeReturnToPath,
  type SearchParamsRecord,
} from '@/shared/auth/url-tokens';

export const dynamic = 'force-dynamic';

type PageProps = {
  searchParams: Promise<SearchParamsRecord>;
};

export default async function SignupPage({ searchParams }: PageProps) {
  const resolvedSearchParams = await searchParams;
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Create your account"
        subtitle="The signup page could not load backend bootstrap truth for this request."
      >
        <AuthCard tone="danger">
          <AuthErrorBanner error={bootstrap.error} fallbackMessage="Unable to load signup state." />
        </AuthCard>
      </AuthShell>
    );
  }

  if (bootstrap.routeState.kind !== 'PUBLIC_ENTRY') {
    redirect(getRouteStateRedirectPath(bootstrap.routeState));
  }

  const { tenant } = bootstrap.config;
  const returnTo = normalizeReturnToPath(getReturnToPath(resolvedSearchParams), '/dashboard');
  const loginHref = `${AUTH_LOGIN_PATH}?returnTo=${encodeURIComponent(returnTo)}`;

  return (
    <AuthShell
      eyebrow="Hubins"
      title={tenant.name ? `Create your ${tenant.name} account` : 'Create your account'}
      subtitle="This page only renders the real public signup form when the current tenant allows self-service registration."
    >
      <AuthCard
        title="Public signup"
        description="Signup availability is driven by GET /auth/config. The frontend does not guess or hardcode tenant policy."
      >
        {tenant.publicSignupEnabled ? (
          <SignupForm returnTo={returnTo} />
        ) : (
          <AuthNote>
            Sign up is disabled for this workspace. Ask an admin for an invite or go back to{' '}
            <Link href={loginHref}>sign in</Link>.
          </AuthNote>
        )}
      </AuthCard>
    </AuthShell>
  );
}
