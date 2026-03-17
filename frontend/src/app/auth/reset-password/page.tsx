/**
 * frontend/src/app/auth/reset-password/page.tsx
 *
 * WHY:
 * - Real password-reset completion page for links sent by the backend SMTP adapter.
 * - Supports opening a reset link directly in the browser without requiring a session.
 * - Keeps reset-password distinct from forgot-password so the browser can truthfully
 *   react to missing, expired, or already-used reset tokens.
 */

import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthCard } from '@/shared/auth/components/auth-card';
import { AuthErrorBanner } from '@/shared/auth/components/auth-error-banner';
import { AuthShell } from '@/shared/auth/components/auth-shell';
import { AuthNote } from '@/shared/auth/components/auth-form-ui';
import { ResetPasswordForm } from '@/shared/auth/components/reset-password-form';
import {
  AUTHENTICATED_APP_ENTRY_PATH,
  AUTH_FORGOT_PASSWORD_PATH,
  AUTH_LOGIN_PATH,
  AUTH_TENANT_UNAVAILABLE_PATH,
} from '@/shared/auth/redirects';
import { getResetPasswordToken, type SearchParamsRecord } from '@/shared/auth/url-tokens';

export const dynamic = 'force-dynamic';

type PageProps = {
  searchParams: Promise<SearchParamsRecord>;
};

export default async function ResetPasswordPage({ searchParams }: PageProps) {
  const resolvedSearchParams = await searchParams;
  const token = getResetPasswordToken(resolvedSearchParams);
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Reset your password"
        subtitle="The password reset page could not load backend bootstrap truth for this request."
      >
        <AuthCard tone="danger">
          <AuthErrorBanner
            error={bootstrap.error}
            fallbackMessage="Unable to load password reset state."
          />
        </AuthCard>
      </AuthShell>
    );
  }

  if (bootstrap.routeState.kind === 'TENANT_UNAVAILABLE') {
    redirect(AUTH_TENANT_UNAVAILABLE_PATH);
  }

  const tenantName = bootstrap.config.tenant.name;
  const hasAuthenticatedSession = bootstrap.routeState.kind !== 'PUBLIC_ENTRY';

  return (
    <AuthShell
      eyebrow="Hubins"
      title={tenantName ? `Reset your ${tenantName} password` : 'Reset your password'}
      subtitle="Password reset does not require an existing session. The backend decides whether the reset token from the URL is still valid."
      footer={
        hasAuthenticatedSession ? (
          <Link href={AUTHENTICATED_APP_ENTRY_PATH}>Back to workspace</Link>
        ) : (
          <Link href={AUTH_LOGIN_PATH}>Back to sign in</Link>
        )
      }
    >
      <AuthCard
        title="Choose a new password"
        description="This page submits the reset token from the URL directly to POST /auth/reset-password and surfaces backend truth for expired or already-used links."
      >
        {token ? (
          <ResetPasswordForm token={token} />
        ) : (
          <>
            <AuthNote>
              This page is missing a reset token. Request a fresh password reset email, then reopen
              the newest link from your inbox.
            </AuthNote>
            <Link href={AUTH_FORGOT_PASSWORD_PATH}>Request a new reset link</Link>
          </>
        )}
      </AuthCard>
    </AuthShell>
  );
}
