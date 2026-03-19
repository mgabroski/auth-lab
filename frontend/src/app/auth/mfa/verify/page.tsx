/**
 * frontend/src/app/auth/mfa/verify/page.tsx
 *
 * WHY:
 * - Real MFA verification continuation page.
 * - Only renders when backend truth says the current session still needs MFA verification.
 */

import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthCard } from '@/shared/auth/components/auth-card';
import { AuthErrorBanner } from '@/shared/auth/components/auth-error-banner';
import { AuthShell } from '@/shared/auth/components/auth-shell';
import { MfaVerifyFlow } from '@/shared/auth/components/mfa-verify-flow';
import { getRouteStateRedirectPath } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

export default async function MfaVerifyPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Verify multi-factor authentication"
        subtitle="The MFA verification page could not confirm backend continuation state for this request."
      >
        <AuthCard tone="danger">
          <AuthErrorBanner
            error={bootstrap.error}
            fallbackMessage="Unable to load MFA verification state."
          />
        </AuthCard>
      </AuthShell>
    );
  }

  const routeState = bootstrap.routeState;

  if (routeState.kind !== 'MFA_REQUIRED') {
    redirect(getRouteStateRedirectPath(routeState));
  }

  return (
    <AuthShell
      eyebrow="Hubins"
      title="Verify multi-factor authentication"
      subtitle="Use your authenticator app or a saved recovery code to complete sign-in for this workspace."
    >
      <AuthCard
        title="MFA verification required"
        description="The backend already established the session, but `nextAction` still requires MFA verification before the app can continue."
      >
        <MfaVerifyFlow userEmail={routeState.me.user.email} role={routeState.me.membership.role} />
      </AuthCard>
    </AuthShell>
  );
}
