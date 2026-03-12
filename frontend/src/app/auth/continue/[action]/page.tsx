/**
 * frontend/src/app/auth/continue/[action]/page.tsx
 *
 * WHY:
 * - Minimal continuation route target for the new root gate.
 * - Lets Phase 1 route-state redirects land somewhere real without prematurely
 *   implementing the full continuation forms/UI.
 *
 * RULES:
 * - Server Component only.
 * - The route param must agree with backend `nextAction` truth.
 */

import { notFound, redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import {
  AUTH_EMAIL_VERIFICATION_PATH,
  AUTH_MFA_SETUP_PATH,
  AUTH_MFA_VERIFY_PATH,
  getRouteStateRedirectPath,
} from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

type ContinuationAction = 'email-verification' | 'mfa-setup' | 'mfa-verify';

type PageProps = {
  params: Promise<{
    action: string;
  }>;
};

function isContinuationAction(value: string): value is ContinuationAction {
  return value === 'email-verification' || value === 'mfa-setup' || value === 'mfa-verify';
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

function headingForAction(action: ContinuationAction): string {
  switch (action) {
    case 'email-verification':
      return 'Email verification required';
    case 'mfa-setup':
      return 'MFA setup required';
    case 'mfa-verify':
      return 'MFA verification required';
    default: {
      const exhaustiveCheck: never = action;
      throw new Error(`Unhandled continuation action: ${String(exhaustiveCheck)}`);
    }
  }
}

export default async function AuthContinuationPage({ params }: PageProps) {
  const { action } = await params;

  if (!isContinuationAction(action)) {
    notFound();
  }

  const continuationAction: ContinuationAction = action;
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Continuation</h1>
        <p>Bootstrap failed while resolving the continuation route.</p>
        <p>
          <strong>Error:</strong> {bootstrap.error.message}
        </p>
      </main>
    );
  }

  const expectedPath = expectedPathForAction(continuationAction);
  const actualPath = getRouteStateRedirectPath(bootstrap.routeState);

  if (actualPath !== expectedPath) {
    redirect(actualPath);
  }

  if (
    bootstrap.routeState.kind !== 'EMAIL_VERIFICATION_REQUIRED' &&
    bootstrap.routeState.kind !== 'MFA_SETUP_REQUIRED' &&
    bootstrap.routeState.kind !== 'MFA_REQUIRED'
  ) {
    redirect(getRouteStateRedirectPath(bootstrap.routeState));
  }

  const continuationState = bootstrap.routeState;

  return (
    <main>
      <h1>Hubins — {headingForAction(continuationAction)}</h1>
      <p>This is a Phase 1 continuation placeholder route driven by backend `nextAction`.</p>

      <h2>Resolved user</h2>
      <pre>{JSON.stringify(continuationState.me.user, null, 2)}</pre>

      <h2>Resolved tenant</h2>
      <pre>{JSON.stringify(continuationState.me.tenant, null, 2)}</pre>

      <h2>Next phase</h2>
      <p>
        The full continuation screen for this state will be implemented in the next frontend phase.
      </p>
    </main>
  );
}
