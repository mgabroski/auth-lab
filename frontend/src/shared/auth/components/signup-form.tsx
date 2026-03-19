'use client';

/**
 * frontend/src/shared/auth/components/signup-form.tsx
 *
 * WHY:
 * - Real public signup form for tenants that enable self-service registration.
 * - Redirects strictly from backend `nextAction` truth after successful signup.
 */

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type ChangeEvent, type FormEvent } from 'react';
import { signup } from '@/shared/auth/browser-api';
import { AUTH_LOGIN_PATH, getPostAuthRedirectPath } from '@/shared/auth/redirects';
import { AuthErrorBanner } from './auth-error-banner';
import { AuthLinkGroup, FormField, FormStack, SubmitButton, TextInput } from './auth-form-ui';

type SignupFormProps = {
  returnTo?: string | null;
};

export function SignupForm({ returnTo }: SignupFormProps) {
  const router = useRouter();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const loginHref = returnTo
    ? `${AUTH_LOGIN_PATH}?returnTo=${encodeURIComponent(returnTo)}`
    : AUTH_LOGIN_PATH;

  const submitSignup = async (): Promise<void> => {
    try {
      setPending(true);
      setError(null);

      const result = await signup({ name, email, password });

      if (!result.ok) {
        setError(result.error);
        setPending(false);
        return;
      }

      router.replace(
        getPostAuthRedirectPath(result.data.nextAction, result.data.membership.role, returnTo),
      );
    } catch (caughtError) {
      setError(caughtError);
      setPending(false);
    }
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitSignup();
  };

  return (
    <form onSubmit={handleSubmit}>
      <FormStack>
        <AuthErrorBanner error={error} fallbackMessage="Unable to create your account." />

        <FormField label="Full name" htmlFor="signup-name">
          <TextInput
            id="signup-name"
            name="name"
            type="text"
            autoComplete="name"
            value={name}
            disabled={pending}
            onChange={(event: ChangeEvent<HTMLInputElement>) => setName(event.target.value)}
            placeholder="Jane Doe"
            required
          />
        </FormField>

        <FormField label="Email" htmlFor="signup-email">
          <TextInput
            id="signup-email"
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

        <FormField label="Password" htmlFor="signup-password" hint="Use at least 8 characters.">
          <TextInput
            id="signup-password"
            name="password"
            type="password"
            autoComplete="new-password"
            value={password}
            disabled={pending}
            onChange={(event: ChangeEvent<HTMLInputElement>) => setPassword(event.target.value)}
            placeholder="Create a password"
            required
          />
        </FormField>

        <SubmitButton disabled={pending}>
          {pending ? 'Creating account…' : 'Create account'}
        </SubmitButton>

        <AuthLinkGroup>
          <span>Already have an account?</span>
          <Link href={loginHref}>Sign in</Link>
        </AuthLinkGroup>
      </FormStack>
    </form>
  );
}
