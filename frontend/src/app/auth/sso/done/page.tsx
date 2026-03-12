/**
 * frontend/src/app/auth/sso/done/page.tsx
 *
 * WHY:
 * - Backend SSO callback currently redirects here after setting the session cookie.
 * - This page immediately resolves backend bootstrap truth again and forwards the
 *   user into dashboard or continuation state.
 *
 * NOTE:
 * - The backend may include `?nextAction=...` on this URL, but frontend routing
 *   still trusts fresh `/auth/me` truth instead of the query string.
 */

import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthCard } from '@/shared/auth/components/auth-card';
import { AuthErrorBanner } from '@/shared/auth/components/auth-error-banner';
import { AuthShell } from '@/shared/auth/components/auth-shell';
import { getRouteStateRedirectPath } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

export default async function AuthSsoDonePage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Completing sign-in"
        subtitle="The SSO callback finished, but the frontend could not confirm the current auth state."
      >
        <AuthCard tone="danger">
          <AuthErrorBanner
            error={bootstrap.error}
            fallbackMessage="Unable to complete SSO sign-in. Please try again."
          />
        </AuthCard>
      </AuthShell>
    );
  }

  redirect(getRouteStateRedirectPath(bootstrap.routeState));
}
