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
import { ssrFetch } from '@/shared/ssr-api-client';
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

  let tokenError: string | null = null;
  let tokenIsValid = false;

  if (token) {
    const response = await ssrFetch('/auth/reset-password/validate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ token }),
    });

    if (response.ok) {
      tokenIsValid = true;
    } else {
      let message =
        'This password reset link is invalid or has expired. Please request a new one.';

      try {
        const payload = (await response.json()) as {
          error?: { message?: string };
        };

        if (payload?.error?.message) {
          message = payload.error.message;
        }
      } catch {
        // keep fallback message
      }

      tokenError = message;
    }
  }

  const tenantName = bootstrap.config.tenant.name;
  const hasAuthenticatedSession = bootstrap.routeState.kind !== 'PUBLIC_ENTRY';

  return (
    <AuthShell
      eyebrow="Hubins"
      title={tenantName ? `Reset your ${tenantName} password` : 'Reset your password'}
      subtitle="Password reset does not require an existing session. This page validates the reset link before showing the password form."
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
        description="Expired, invalid, or already-used links are rejected before password entry. Valid links can be used to choose a new password."
      >
        {token ? (
          tokenIsValid ? (
            <ResetPasswordForm token={token} />
          ) : (
            <>
              <AuthErrorBanner
                error={tokenError ? { message: tokenError } : null}
                fallbackMessage="This password reset link is invalid or has expired. Please request a new one."
              />
              <Link href={AUTH_FORGOT_PASSWORD_PATH}>Request a new reset link</Link>
            </>
          )
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
