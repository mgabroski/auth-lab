/**
 * frontend/src/app/auth/sso/done/page.tsx
 *
 * WHY:
 * - Backend SSO callback redirects here after setting the session cookie.
 * - This page consumes the backend-provided `nextAction` query as context, but still
 *   trusts fresh `/auth/me` truth before routing the user onward.
 */

import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthCard } from '@/shared/auth/components/auth-card';
import { AuthErrorBanner } from '@/shared/auth/components/auth-error-banner';
import { AuthShell } from '@/shared/auth/components/auth-shell';
import { getPathForNextAction, getRouteStateRedirectPath } from '@/shared/auth/redirects';
import type { AuthNextAction } from '@/shared/auth/contracts';
import { readQueryParam, type SearchParamsRecord } from '@/shared/auth/url-tokens';

export const dynamic = 'force-dynamic';

type PageProps = {
  searchParams: Promise<SearchParamsRecord>;
};

function parseNextAction(value: string | null): AuthNextAction | null {
  if (
    value === 'NONE' ||
    value === 'EMAIL_VERIFICATION_REQUIRED' ||
    value === 'MFA_SETUP_REQUIRED' ||
    value === 'MFA_REQUIRED'
  ) {
    return value;
  }

  return null;
}

export default async function AuthSsoDonePage({ searchParams }: PageProps) {
  const resolvedSearchParams = await searchParams;
  const hintedNextAction = parseNextAction(readQueryParam(resolvedSearchParams, 'nextAction'));
  const hintedPath = hintedNextAction ? getPathForNextAction(hintedNextAction) : null;
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Completing sign-in"
        subtitle={
          hintedNextAction
            ? `The SSO callback completed and indicated ${hintedNextAction}, but the frontend could not confirm current session state.`
            : 'The SSO callback finished, but the frontend could not confirm the current auth state.'
        }
      >
        <AuthCard tone="danger">
          <AuthErrorBanner
            error={bootstrap.error}
            fallbackMessage="Unable to complete SSO sign-in. Please try again."
          />
          {hintedPath ? (
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.6, color: '#475569' }}>
              Backend callback hint: <strong>{hintedNextAction}</strong> → <code>{hintedPath}</code>
            </p>
          ) : null}
        </AuthCard>
      </AuthShell>
    );
  }

  redirect(getRouteStateRedirectPath(bootstrap.routeState));
}
