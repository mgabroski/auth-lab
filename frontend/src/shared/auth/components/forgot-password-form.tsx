'use client';

/**
 * frontend/src/shared/auth/components/forgot-password-form.tsx
 *
 * WHY:
 * - Real forgot-password form with backend-safe generic success messaging.
 * - Preserves anti-enumeration behavior by rendering only the backend message.
 */

import Link from 'next/link';
import { useState, type ChangeEvent, type FormEvent } from 'react';
import { requestPasswordReset } from '@/shared/auth/browser-api';
import { AUTH_LOGIN_PATH } from '@/shared/auth/redirects';
import { AuthErrorBanner } from './auth-error-banner';
import { AuthSuccessBanner } from './auth-success-banner';
import { AuthLinkGroup, FormField, FormStack, SubmitButton, TextInput } from './auth-form-ui';

export function ForgotPasswordForm() {
  const [email, setEmail] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const submitForgotPassword = async (): Promise<void> => {
    setPending(true);
    setError(null);
    setSuccessMessage(null);

    const result = await requestPasswordReset({ email });

    if (!result.ok) {
      setError(result.error);
      setPending(false);
      return;
    }

    setSuccessMessage(result.data.message);
    setPending(false);
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitForgotPassword();
  };

  return (
    <form onSubmit={handleSubmit}>
      <FormStack>
        <AuthSuccessBanner title="Check your email" message={successMessage} />
        <AuthErrorBanner error={error} fallbackMessage="Unable to request a reset link." />

        <FormField
          label="Email"
          htmlFor="forgot-password-email"
          hint="We will only send a reset link if this email can use password sign-in for this workspace."
        >
          <TextInput
            id="forgot-password-email"
            name="email"
            type="email"
            autoComplete="email"
            inputMode="email"
            value={email}
            disabled={pending}
            onChange={(event: ChangeEvent<HTMLInputElement>) => setEmail(event.target.value)}
            placeholder="you@company.com"
            required
          />
        </FormField>

        <SubmitButton disabled={pending}>{pending ? 'Sending…' : 'Send reset link'}</SubmitButton>

        <AuthLinkGroup>
          <Link href={AUTH_LOGIN_PATH}>Back to sign in</Link>
        </AuthLinkGroup>
      </FormStack>
    </form>
  );
}
