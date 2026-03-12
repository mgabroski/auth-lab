'use client';

/**
 * frontend/src/shared/auth/components/reset-password-form.tsx
 *
 * WHY:
 * - Consumes the reset token from the URL and submits the real backend reset endpoint.
 * - Surfaces invalid/expired token errors directly from backend truth.
 */

import Link from 'next/link';
import { useState, type ChangeEvent, type FormEvent } from 'react';
import { resetPassword } from '@/shared/auth/browser-api';
import { AUTH_LOGIN_PATH } from '@/shared/auth/redirects';
import { AuthErrorBanner } from './auth-error-banner';
import { AuthSuccessBanner } from './auth-success-banner';
import { AuthLinkGroup, FormField, FormStack, SubmitButton, TextInput } from './auth-form-ui';

type ResetPasswordFormProps = {
  token: string;
};

export function ResetPasswordForm({ token }: ResetPasswordFormProps) {
  const [newPassword, setNewPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const submitResetPassword = async (): Promise<void> => {
    setPending(true);
    setError(null);
    setSuccessMessage(null);

    const result = await resetPassword({ token, newPassword });

    if (!result.ok) {
      setError(result.error);
      setPending(false);
      return;
    }

    setSuccessMessage(result.data.message);
    setPending(false);
    setNewPassword('');
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitResetPassword();
  };

  return (
    <form onSubmit={handleSubmit}>
      <FormStack>
        <AuthSuccessBanner title="Password updated" message={successMessage} />
        <AuthErrorBanner error={error} fallbackMessage="Unable to update your password." />

        <FormField
          label="New password"
          htmlFor="reset-password"
          hint="Use at least 8 characters. Reset links are one-time use and can expire."
        >
          <TextInput
            id="reset-password"
            name="newPassword"
            type="password"
            autoComplete="new-password"
            value={newPassword}
            disabled={pending || Boolean(successMessage)}
            onChange={(event: ChangeEvent<HTMLInputElement>) => setNewPassword(event.target.value)}
            placeholder="Create a new password"
            required
          />
        </FormField>

        <SubmitButton disabled={pending || Boolean(successMessage)}>
          {pending ? 'Updating password…' : 'Update password'}
        </SubmitButton>

        <AuthLinkGroup>
          <Link href={AUTH_LOGIN_PATH}>Go to sign in</Link>
        </AuthLinkGroup>
      </FormStack>
    </form>
  );
}
