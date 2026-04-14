'use client';

/**
 * frontend/src/shared/auth/components/verify-email-flow.tsx
 *
 * WHY:
 * - Implements the real email-verification continuation behavior.
 * - Supports the backend truth that verification requires an authenticated session.
 * - Preserves the token from the URL when a user must sign in before verifying.
 */

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';
import { getAuthMe, resendVerification, verifyEmail } from '@/shared/auth/browser-api';
import {
  AUTHENTICATED_APP_ENTRY_PATH,
  AUTH_LOGIN_PATH,
  getPathForNextAction,
} from '@/shared/auth/redirects';
import { AuthErrorBanner } from './auth-error-banner';
import { AuthSuccessBanner } from './auth-success-banner';
import { AuthLinkGroup, AuthNote, FormStack, SecondaryButton } from './auth-form-ui';

type VerifyEmailFlowProps = {
  token: string | null;
  hasAuthenticatedSession: boolean;
  requiresEmailVerification: boolean;
  userEmail: string | null;
  signInHref: string;
};

async function resolvePostVerificationPath(): Promise<string> {
  const meResult = await getAuthMe();

  if (meResult.ok) {
    return getPathForNextAction(meResult.data.nextAction, meResult.data.membership.role);
  }

  return AUTHENTICATED_APP_ENTRY_PATH;
}

export function VerifyEmailFlow({
  token,
  hasAuthenticatedSession,
  requiresEmailVerification,
  userEmail,
  signInHref,
}: VerifyEmailFlowProps) {
  const router = useRouter();
  const autoAttemptedRef = useRef(false);
  const [pendingVerify, setPendingVerify] = useState(false);
  const [pendingResend, setPendingResend] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const submitVerification = async (): Promise<void> => {
    if (!token || !hasAuthenticatedSession) {
      return;
    }

    setPendingVerify(true);
    setError(null);
    setSuccessMessage(null);

    const result = await verifyEmail({ token });

    if (!result.ok) {
      setError(result.error);
      setPendingVerify(false);
      return;
    }

    setSuccessMessage('Your email has been verified. Redirecting to the next required step…');

    await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds

    const nextPath = await resolvePostVerificationPath();
    router.replace(nextPath);
    router.refresh();
  };

  const submitResend = async (): Promise<void> => {
    if (!hasAuthenticatedSession) {
      return;
    }

    setPendingResend(true);
    setError(null);
    setSuccessMessage(null);

    const result = await resendVerification();

    if (!result.ok) {
      setError(result.error);
      setPendingResend(false);
      return;
    }

    setSuccessMessage(result.data.message);
    setPendingResend(false);
  };

  useEffect(() => {
    router.refresh();
    if (!token || !hasAuthenticatedSession || autoAttemptedRef.current) {
      return;
    }

    autoAttemptedRef.current = true;
    void submitVerification();
  }, [hasAuthenticatedSession, token]);

  if (!hasAuthenticatedSession) {
    return (
      <FormStack>
        <AuthErrorBanner error={error} fallbackMessage="Unable to verify this email link." />

        <AuthNote>
          Email verification is tied to an authenticated workspace session. Sign in to this
          workspace first, then reopen this link so the backend can verify the token for the correct
          user.
        </AuthNote>

        <AuthLinkGroup>
          <Link href={signInHref}>Sign in to continue</Link>
          <Link href={AUTH_LOGIN_PATH}>Go to sign in</Link>
        </AuthLinkGroup>
      </FormStack>
    );
  }

  return (
    <FormStack>
      <AuthSuccessBanner title="Email verification" message={successMessage} />
      <AuthErrorBanner error={error} fallbackMessage="Unable to verify this email link." />

      {requiresEmailVerification ? (
        <AuthNote>
          {userEmail ? (
            <>
              Signed in as <strong>{userEmail}</strong>. This session still requires email
              verification before the app can continue.
            </>
          ) : (
            'This session still requires email verification before the app can continue.'
          )}
        </AuthNote>
      ) : (
        <AuthNote>
          This session is already authenticated. If this verification link still belongs to your
          current user, the backend will treat verification idempotently.
        </AuthNote>
      )}

      {token ? (
        <AuthNote>
          The verification token from the URL is submitted directly to{' '}
          <code>POST /auth/verify-email</code>. If the automatic attempt fails, you can retry or ask
          the backend to send a fresh link.
        </AuthNote>
      ) : (
        <AuthNote>
          This page is missing a verification token. Ask the backend to send a fresh verification
          email for this signed-in session.
        </AuthNote>
      )}

      {token ? (
        <SecondaryButton
          disabled={pendingVerify || pendingResend}
          onClick={() => void submitVerification()}
        >
          {pendingVerify ? 'Verifying email…' : 'Verify email now'}
        </SecondaryButton>
      ) : null}

      <SecondaryButton
        disabled={pendingVerify || pendingResend}
        onClick={() => void submitResend()}
      >
        {pendingResend ? 'Sending verification email…' : 'Resend verification email'}
      </SecondaryButton>
    </FormStack>
  );
}
