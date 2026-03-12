/**
 * frontend/src/app/auth/mfa/setup/page.tsx
 *
 * WHY:
 * - Real MFA setup continuation page.
 * - Only renders when backend truth says the current session must configure MFA.
 */

import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthCard } from '@/shared/auth/components/auth-card';
import { AuthErrorBanner } from '@/shared/auth/components/auth-error-banner';
import { AuthShell } from '@/shared/auth/components/auth-shell';
import { MfaSetupFlow } from '@/shared/auth/components/mfa-setup-flow';
import { getRouteStateRedirectPath } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

export default async function MfaSetupPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Set up multi-factor authentication"
        subtitle="The MFA setup page could not confirm backend continuation state for this request."
      >
        <AuthCard tone="danger">
          <AuthErrorBanner error={bootstrap.error} fallbackMessage="Unable to load MFA setup." />
        </AuthCard>
      </AuthShell>
    );
  }

  const routeState = bootstrap.routeState;

  if (routeState.kind !== 'MFA_SETUP_REQUIRED') {
    redirect(getRouteStateRedirectPath(routeState));
  }

  return (
    <AuthShell
      eyebrow="Hubins"
      title="Set up multi-factor authentication"
      subtitle="This page uses the real backend MFA setup route, then finishes setup through the backend verify-setup contract."
    >
      <AuthCard
        title="Authenticator app required"
        description="Admin access is not complete until the backend confirms MFA setup for this session."
      >
        <MfaSetupFlow userEmail={routeState.me.user.email} />
      </AuthCard>
    </AuthShell>
  );
}
