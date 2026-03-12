/**
 * frontend/src/app/auth/continue/[action]/page.tsx
 *
 * WHY:
 * - Minimal continuation route target driven by backend `nextAction`.
 * - Uses shared auth layout primitives so the real continuation forms can slot in later.
 *
 * RULES:
 * - Server Component only.
 * - The route param must agree with backend `nextAction` truth.
 */

import { notFound, redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthCard } from '@/shared/auth/components/auth-card';
import { AuthErrorBanner } from '@/shared/auth/components/auth-error-banner';
import { AuthShell } from '@/shared/auth/components/auth-shell';
import {
  AUTH_EMAIL_VERIFICATION_PATH,
  AUTH_MFA_SETUP_PATH,
  AUTH_MFA_VERIFY_PATH,
  getRouteStateRedirectPath,
} from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

type ContinuationAction = 'email-verification' | 'mfa-setup' | 'mfa-verify';

type ResolvedContinuationState = Extract<
  Awaited<ReturnType<typeof loadAuthBootstrap>>,
  { ok: true }
>['routeState'] & {
  kind: 'EMAIL_VERIFICATION_REQUIRED' | 'MFA_SETUP_REQUIRED' | 'MFA_REQUIRED';
};

type PageProps = {
  params: Promise<{
    action: string;
  }>;
};

function parseContinuationAction(value: string): ContinuationAction | null {
  if (value === 'email-verification' || value === 'mfa-setup' || value === 'mfa-verify') {
    return value;
  }

  return null;
}

function resolveContinuationState(
  state: Awaited<ReturnType<typeof loadAuthBootstrap>> extends infer T
    ? T extends { ok: true; routeState: infer R }
      ? R
      : never
    : never,
): ResolvedContinuationState | null {
  if (
    state.kind === 'EMAIL_VERIFICATION_REQUIRED' ||
    state.kind === 'MFA_SETUP_REQUIRED' ||
    state.kind === 'MFA_REQUIRED'
  ) {
    return state;
  }

  return null;
}

function expectedPathForAction(action: ContinuationAction): string {
  switch (action) {
    case 'email-verification':
      return AUTH_EMAIL_VERIFICATION_PATH;
    case 'mfa-setup':
      return AUTH_MFA_SETUP_PATH;
    case 'mfa-verify':
      return AUTH_MFA_VERIFY_PATH;
    default: {
      const exhaustiveCheck: never = action;
      throw new Error(`Unhandled continuation action: ${String(exhaustiveCheck)}`);
    }
  }
}

function contentForAction(action: ContinuationAction): { title: string; description: string } {
  switch (action) {
    case 'email-verification':
      return {
        title: 'Verify your email',
        description:
          'The current session exists, but backend truth still requires email verification before app access.',
      };
    case 'mfa-setup':
      return {
        title: 'Set up multi-factor authentication',
        description:
          'The current session belongs to a user who must complete MFA setup before continuing.',
      };
    case 'mfa-verify':
      return {
        title: 'Verify your MFA code',
        description:
          'The session is authenticated, but backend truth still requires MFA verification for this visit.',
      };
    default: {
      const exhaustiveCheck: never = action;
      throw new Error(`Unhandled continuation action: ${String(exhaustiveCheck)}`);
    }
  }
}

export default async function AuthContinuationPage({ params }: PageProps) {
  const { action } = await params;
  const continuationAction = parseContinuationAction(action);

  if (!continuationAction) {
    notFound();
  }
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <AuthShell
        eyebrow="Hubins"
        title="Continuation bootstrap failed"
        subtitle="The continuation route could not resolve backend auth state for this request."
      >
        <AuthCard tone="danger">
          <AuthErrorBanner
            error={bootstrap.error}
            fallbackMessage="Unable to load continuation state."
          />
        </AuthCard>
      </AuthShell>
    );
  }

  const expectedPath = expectedPathForAction(continuationAction);
  const actualPath = getRouteStateRedirectPath(bootstrap.routeState);

  if (actualPath !== expectedPath) {
    redirect(actualPath);
  }

  const continuationState = resolveContinuationState(bootstrap.routeState);

  if (!continuationState) {
    redirect(getRouteStateRedirectPath(bootstrap.routeState));
  }

  const content = contentForAction(continuationAction);

  return (
    <AuthShell
      eyebrow="Hubins"
      title={content.title}
      subtitle="This Phase 2 wrapper keeps continuation route logic thin while future forms move into shared browser helpers."
    >
      <AuthCard title="Backend-owned continuation state" description={content.description}>
        <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
          Resolved user: <strong>{continuationState.me.user.email}</strong>
        </p>
        <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
          Resolved tenant: <strong>{continuationState.me.tenant.name}</strong>
        </p>
        <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
          The real form/action UI for this continuation state is intentionally deferred to the next
          frontend page phase.
        </p>
      </AuthCard>
    </AuthShell>
  );
}
