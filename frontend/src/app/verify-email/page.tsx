/**
 * frontend/src/app/verify-email/page.tsx
 *
 * WHY:
 * - Matches the backend email link contract (`/verify-email?token=...`).
 * - Supports both authenticated verification continuation and truthful unauthenticated recovery.
 * - Keeps email verification outside the generic continuation placeholder route.
 */

import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthCard } from '@/shared/auth/components/auth-card';
import { AuthErrorBanner } from '@/shared/auth/components/auth-error-banner';
import { AuthShell } from '@/shared/auth/components/auth-shell';
import { VerifyEmailFlow } from '@/shared/auth/components/verify-email-flow';
import {
  AUTHENTICATED_APP_ENTRY_PATH,
  AUTH_LOGIN_PATH,
  AUTH_TENANT_UNAVAILABLE_PATH,
} from '@/shared/auth/redirects';
import {
  getVerificationToken,
  normalizeReturnToPath,
  type SearchParamsRecord,
} from '@/shared/auth/url-tokens';

export const dynamic = 'force-dynamic';

type PageProps = {
  searchParams: Promise<SearchParamsRecord>;
};

export default async function VerifyEmailPage({ searchParams }: PageProps) {
  const resolvedSearchParams = await searchParams;
  const token = getVerificationToken(resolvedSearchParams);
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Verify your email"
        subtitle="The verification page could not confirm backend auth state for this request."
      >
        <AuthCard tone="danger">
          <AuthErrorBanner
            error={bootstrap.error}
            fallbackMessage="Unable to load email verification state."
          />
        </AuthCard>
      </AuthShell>
    );
  }

  if (bootstrap.routeState.kind === 'TENANT_UNAVAILABLE') {
    redirect(AUTH_TENANT_UNAVAILABLE_PATH);
  }

  const routeState = bootstrap.routeState;
  const hasAuthenticatedSession = routeState.kind !== 'PUBLIC_ENTRY';
  const requiresEmailVerification = routeState.kind === 'EMAIL_VERIFICATION_REQUIRED';
  const userEmail = hasAuthenticatedSession ? (routeState.me?.user.email ?? null) : null;
  const tenantName = bootstrap.config.tenant.name;
  const safeReturnTo = normalizeReturnToPath(
    token ? `/verify-email?token=${encodeURIComponent(token)}` : '/verify-email',
    '/verify-email',
  );
  const signInHref = `${AUTH_LOGIN_PATH}?returnTo=${encodeURIComponent(safeReturnTo)}`;

  return (
    <AuthShell
      eyebrow="Hubins"
      title={tenantName ? `Verify your ${tenantName} email` : 'Verify your email'}
      subtitle="The backend owns whether verification is still required. This page only submits the token from the URL and reacts to current session truth."
      footer={
        hasAuthenticatedSession ? (
          <Link href={AUTHENTICATED_APP_ENTRY_PATH}>Back to workspace</Link>
        ) : (
          <Link href={AUTH_LOGIN_PATH}>Back to sign in</Link>
        )
      }
    >
      <AuthCard
        title="Email verification"
        description="Verification is session-bound in this system. When no session exists yet, the truthful recovery path is to sign in first and then reopen the link."
      >
        <VerifyEmailFlow
          token={token}
          hasAuthenticatedSession={hasAuthenticatedSession}
          requiresEmailVerification={requiresEmailVerification}
          userEmail={userEmail}
          signInHref={signInHref}
        />
      </AuthCard>
    </AuthShell>
  );
}
