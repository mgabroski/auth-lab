/**
 * frontend/src/app/auth/reset-password/page.tsx
 *
 * WHY:
 * - Public reset-password screen that consumes the token from the URL.
 * - Handles missing/invalid/expired-link states without inventing frontend-only success logic.
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
  AUTH_FORGOT_PASSWORD_PATH,
  AUTH_LOGIN_PATH,
  getRouteStateRedirectPath,
} from '@/shared/auth/redirects';
import { getResetPasswordToken, type SearchParamsRecord } from '@/shared/auth/url-tokens';

export const dynamic = 'force-dynamic';

type PageProps = {
  searchParams: Promise<SearchParamsRecord>;
};

export default async function ResetPasswordPage({ searchParams }: PageProps) {
  const resolvedSearchParams = await searchParams;
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Reset password"
        subtitle="The reset-password page could not load backend bootstrap truth for this request."
      >
        <AuthCard tone="danger">
          <AuthErrorBanner error={bootstrap.error} fallbackMessage="Unable to load reset state." />
        </AuthCard>
      </AuthShell>
    );
  }

  if (bootstrap.routeState.kind !== 'PUBLIC_ENTRY') {
    redirect(getRouteStateRedirectPath(bootstrap.routeState));
  }

  const token = getResetPasswordToken(resolvedSearchParams);
  const { tenant } = bootstrap.config;

  return (
    <AuthShell
      eyebrow="Hubins"
      title={tenant.name ? `Choose a new ${tenant.name} password` : 'Choose a new password'}
      subtitle="Reset links are one-time use. When a link is missing or invalid, the safest recovery path is to request a new one."
    >
      <AuthCard
        title="Update password"
        description="This page submits the token from the URL directly to POST /auth/reset-password."
      >
        {token ? (
          <ResetPasswordForm token={token} />
        ) : (
          <AuthNote>
            This password reset link is missing a token. Request a new link from{' '}
            <Link href={AUTH_FORGOT_PASSWORD_PATH}>forgot password</Link> or return to{' '}
            <Link href={AUTH_LOGIN_PATH}>sign in</Link>.
          </AuthNote>
        )}
      </AuthCard>
    </AuthShell>
  );
}
