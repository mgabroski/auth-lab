'use client';

/**
 * frontend/src/shared/auth/components/mfa-verify-flow.tsx
 *
 * WHY:
 * - Implements the real MFA verification continuation flow.
 * - Supports both TOTP verification and recovery-code verification.
 * - Uses the backend as source of truth for success/error outcomes.
 */

import { useRouter } from 'next/navigation';
import { useState, type ChangeEvent, type FormEvent } from 'react';
import { recoverMfa, verifyMfa } from '@/shared/auth/browser-api';
import { getPostAuthRedirectPath } from '@/shared/auth/redirects';
import { AuthErrorBanner } from './auth-error-banner';
import { AuthSuccessBanner } from './auth-success-banner';
import {
  AuthNote,
  FormDivider,
  FormField,
  FormStack,
  SubmitButton,
  TextInput,
} from './auth-form-ui';

type MfaVerifyFlowProps = {
  userEmail: string;
};

export function MfaVerifyFlow({ userEmail }: MfaVerifyFlowProps) {
  const router = useRouter();
  const [code, setCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [pendingMode, setPendingMode] = useState<'code' | 'recovery' | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const finishAuth = (nextAction: 'NONE') => {
    router.replace(getPostAuthRedirectPath(nextAction, null));
    router.refresh();
  };

  const submitCodeVerification = async (): Promise<void> => {
    setPendingMode('code');
    setError(null);
    setSuccessMessage(null);

    const result = await verifyMfa({ code });

    if (!result.ok) {
      setError(result.error);
      setPendingMode(null);
      return;
    }

    setSuccessMessage('MFA verified. Redirecting to your workspace…');
    finishAuth(result.data.nextAction);
  };

  const submitRecoveryVerification = async (): Promise<void> => {
    setPendingMode('recovery');
    setError(null);
    setSuccessMessage(null);

    const result = await recoverMfa({ recoveryCode });

    if (!result.ok) {
      setError(result.error);
      setPendingMode(null);
      return;
    }

    setSuccessMessage('Recovery code accepted. Redirecting to your workspace…');
    finishAuth(result.data.nextAction);
  };

  const handleCodeSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitCodeVerification();
  };

  const handleRecoverySubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitRecoveryVerification();
  };

  return (
    <FormStack>
      <AuthSuccessBanner title="MFA verification" message={successMessage} />
      <AuthErrorBanner error={error} fallbackMessage="Unable to verify MFA for this session." />

      <AuthNote>
        Signed in as <strong>{userEmail}</strong>. The backend still requires MFA verification for
        this session before the app shell can load.
      </AuthNote>

      <form onSubmit={handleCodeSubmit}>
        <FormStack>
          <FormField
            label="Authenticator code"
            htmlFor="mfa-verify-code"
            hint="Enter the current 6-digit code from your authenticator app."
          >
            <TextInput
              id="mfa-verify-code"
              name="code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              disabled={pendingMode !== null}
              onChange={(event: ChangeEvent<HTMLInputElement>) => setCode(event.target.value)}
              placeholder="123456"
              required
            />
          </FormField>

          <SubmitButton disabled={pendingMode !== null}>
            {pendingMode === 'code' ? 'Verifying MFA…' : 'Verify code'}
          </SubmitButton>
        </FormStack>
      </form>

      <FormDivider label="or use a recovery code" />

      <form onSubmit={handleRecoverySubmit}>
        <FormStack>
          <FormField
            label="Recovery code"
            htmlFor="mfa-recovery-code"
            hint="Use one of the one-time recovery codes saved during MFA setup."
          >
            <TextInput
              id="mfa-recovery-code"
              name="recoveryCode"
              type="text"
              autoComplete="off"
              value={recoveryCode}
              disabled={pendingMode !== null}
              onChange={(event: ChangeEvent<HTMLInputElement>) =>
                setRecoveryCode(event.target.value)
              }
              placeholder="Enter a recovery code"
              required
            />
          </FormField>

          <SubmitButton disabled={pendingMode !== null}>
            {pendingMode === 'recovery' ? 'Checking recovery code…' : 'Use recovery code'}
          </SubmitButton>
        </FormStack>
      </form>
    </FormStack>
  );
}
