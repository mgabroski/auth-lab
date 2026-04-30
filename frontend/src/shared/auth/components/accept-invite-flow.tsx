'use client';

/**
 * frontend/src/shared/auth/components/accept-invite-flow.tsx
 *
 * WHY:
 * - Executes the real invite acceptance request from the landing page token.
 * - Branches cleanly into invite-driven registration or sign-in based on backend truth.
 * - Handles invalid / expired / already-used invite states without pretending a session exists.
 */

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';
import { acceptInvite } from '@/shared/auth/browser-api';
import { isApiHttpError } from '@/shared/auth/api-errors';
import { AuthErrorBanner } from './auth-error-banner';
import { AuthSuccessBanner } from './auth-success-banner';
import { AuthLinkGroup, AuthNote, FormStack, SecondaryButton } from './auth-form-ui';
import { saveInviteEmail } from '@/shared/auth/invite-email-cache';

type AcceptInviteFlowProps = {
  token: string | null;
  registerHref: string;
  signInHref: string;
  adminSignInHref: string;
};

type InviteFailureState = {
  title: string;
  description: string;
  showRegisterLink: boolean;
  showSignInLink: boolean;
  canRetry: boolean;
};

function getInviteFailureState(error: unknown): InviteFailureState {
  if (isApiHttpError(error)) {
    const message = error.message.toLowerCase();

    if (error.status === 404) {
      return {
        title: 'This invitation link is invalid',
        description:
          'The link may be malformed, may belong to a different workspace, or may have been replaced by a newer invite email.',
        showRegisterLink: false,
        showSignInLink: false,
        canRetry: false,
      };
    }

    if (error.status === 409 && message.includes('expired')) {
      return {
        title: 'This invitation link has expired',
        description:
          'Invite links are one-time onboarding links with an expiry window. Ask a workspace admin to send you a fresh invitation.',
        showRegisterLink: false,
        showSignInLink: false,
        canRetry: false,
      };
    }

    if (error.status === 409 && message.includes('already accepted')) {
      return {
        title: 'This invitation has already been accepted',
        description:
          'If you are still finishing onboarding, continue to the invite registration step with the same token. If you already have credentials for this workspace, sign in instead.',
        showRegisterLink: true,
        showSignInLink: true,
        canRetry: false,
      };
    }

    if (error.status === 409) {
      return {
        title: 'This invitation is no longer valid',
        description:
          'The backend rejected this invite in its current state. A workspace admin may need to resend or recreate it.',
        showRegisterLink: false,
        showSignInLink: true,
        canRetry: false,
      };
    }
  }

  return {
    title: 'Unable to accept this invitation right now',
    description:
      'The request did not finish cleanly. You can try the same invite link again or return to sign-in if you already have credentials.',
    showRegisterLink: false,
    showSignInLink: true,
    canRetry: true,
  };
}

export function AcceptInviteFlow({
  token,
  registerHref,
  signInHref,
  adminSignInHref,
}: AcceptInviteFlowProps) {
  const router = useRouter();
  const autoSubmittedRef = useRef(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const submitAcceptInvite = async (): Promise<void> => {
    if (!token) {
      return;
    }

    setPending(true);
    setError(null);
    setSuccessMessage(null);

    const result = await acceptInvite({ token });

    if (!result.ok) {
      setError(result.error);
      setPending(false);
      return;
    }

    switch (result.data.nextAction) {
      case 'SET_PASSWORD':
        saveInviteEmail(token, result.data.email);
        setSuccessMessage('Invitation accepted. Redirecting you to finish account setup…');
        router.replace(registerHref);
        router.refresh();
        return;
      case 'SIGN_IN':
        setSuccessMessage('Invitation accepted. Redirecting you to sign in…');
        router.replace(signInHref);
        router.refresh();
        return;
      case 'MFA_SETUP_REQUIRED':
        setSuccessMessage('Invitation accepted. Redirecting you to sign in…');
        router.replace(adminSignInHref);
        router.refresh();
        return;
      default: {
        const exhaustiveCheck: never = result.data.nextAction;
        throw new Error(`Unhandled invite nextAction: ${String(exhaustiveCheck)}`);
      }
    }
  };

  useEffect(() => {
    if (!token || autoSubmittedRef.current) {
      return;
    }

    autoSubmittedRef.current = true;
    void submitAcceptInvite();
  }, [token]);

  if (!token) {
    return (
      <FormStack>
        <AuthNote>
          This invite link is missing its token. Reopen the invitation email and use the full link,
          or ask your workspace admin to send a fresh invite.
        </AuthNote>

        <AuthLinkGroup>
          <Link href={signInHref}>Go to sign in</Link>
        </AuthLinkGroup>
      </FormStack>
    );
  }

  const failureState = error ? getInviteFailureState(error) : null;

  return (
    <FormStack>
      <AuthSuccessBanner title="Invitation" message={successMessage} />
      <AuthErrorBanner error={error} fallbackMessage="Unable to accept this invitation." />

      {failureState ? (
        <>
          <AuthNote>
            <strong>{failureState.title}</strong>
            <br />
            {failureState.description}
          </AuthNote>

          {failureState.canRetry ? (
            <SecondaryButton disabled={pending} onClick={() => void submitAcceptInvite()}>
              {pending ? 'Trying invitation again…' : 'Try invite again'}
            </SecondaryButton>
          ) : null}

          <AuthLinkGroup>
            {failureState.showRegisterLink ? (
              <Link href={registerHref}>Continue account setup</Link>
            ) : null}
            {failureState.showSignInLink ? <Link href={signInHref}>Go to sign in</Link> : null}
          </AuthLinkGroup>
        </>
      ) : (
        <>
          <AuthNote>
            The invite token from this URL is being submitted to{' '}
            <code>POST /auth/invites/accept</code>. The backend decides whether you should set a
            password or sign in with an existing account.
          </AuthNote>

          <SecondaryButton disabled={pending} onClick={() => void submitAcceptInvite()}>
            {pending ? 'Accepting invitation…' : 'Accept invitation again'}
          </SecondaryButton>
        </>
      )}
    </FormStack>
  );
}
