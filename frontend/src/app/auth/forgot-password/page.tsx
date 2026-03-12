/**
 * frontend/src/app/auth/forgot-password/page.tsx
 *
 * WHY:
 * - Public forgot-password screen with backend-safe messaging.
 * - Uses SSR bootstrap only for tenant-aware gating; the form posts from the browser.
 */

import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthCard } from '@/shared/auth/components/auth-card';
import { AuthErrorBanner } from '@/shared/auth/components/auth-error-banner';
import { AuthShell } from '@/shared/auth/components/auth-shell';
import { ForgotPasswordForm } from '@/shared/auth/components/forgot-password-form';
import { getRouteStateRedirectPath } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

export default async function ForgotPasswordPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Forgot password"
        subtitle="The forgot-password page could not load backend bootstrap truth for this request."
      >
        <AuthCard tone="danger">
          <AuthErrorBanner
            error={bootstrap.error}
            fallbackMessage="Unable to load forgot-password state."
          />
        </AuthCard>
      </AuthShell>
    );
  }

  if (bootstrap.routeState.kind !== 'PUBLIC_ENTRY') {
    redirect(getRouteStateRedirectPath(bootstrap.routeState));
  }

  const { tenant } = bootstrap.config;

  return (
    <AuthShell
      eyebrow="Hubins"
      title={tenant.name ? `Reset your ${tenant.name} password` : 'Reset your password'}
      subtitle="For privacy, this flow always renders the same success copy whether or not the email can receive a password reset link."
    >
      <AuthCard
        title="Request a reset link"
        description="Use the same email you normally use for password-based sign-in to this workspace."
      >
        <ForgotPasswordForm />
      </AuthCard>
    </AuthShell>
  );
}
