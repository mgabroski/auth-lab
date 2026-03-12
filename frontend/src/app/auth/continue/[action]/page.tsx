/**
 * frontend/src/app/auth/continue/[action]/page.tsx
 *
 * WHY:
 * - Preserves legacy continuation URLs from earlier frontend phases.
 * - Redirects old placeholder routes to the explicit Phase 4 continuation pages.
 *
 * RULES:
 * - Server Component only.
 * - This file is compatibility-only and owns no continuation UI.
 */

import { notFound, redirect } from 'next/navigation';
import {
  AUTH_EMAIL_VERIFICATION_PATH,
  AUTH_MFA_SETUP_PATH,
  AUTH_MFA_VERIFY_PATH,
} from '@/shared/auth/redirects';

type ContinuationAction = 'email-verification' | 'mfa-setup' | 'mfa-verify';

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

function getRedirectPath(action: ContinuationAction): string {
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

export const dynamic = 'force-dynamic';

export default async function LegacyAuthContinuationPage({ params }: PageProps) {
  const { action } = await params;
  const continuationAction = parseContinuationAction(action);

  if (!continuationAction) {
    notFound();
  }

  const resolvedAction: ContinuationAction = continuationAction;
  redirect(getRedirectPath(resolvedAction));
}
