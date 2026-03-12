'use client';

/**
 * frontend/src/shared/auth/components/login-form.tsx
 *
 * WHY:
 * - Real password login form for the Phase 3 public auth entry flow.
 * - Uses the shared browser auth client so browser requests stay same-origin.
 * - Redirects strictly from backend `nextAction` truth.
 */

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type ChangeEvent, type FormEvent } from 'react';
import { login } from '@/shared/auth/browser-api';
import type { PublicSsoProvider } from '@/shared/auth/contracts';
import {
  AUTH_FORGOT_PASSWORD_PATH,
  AUTH_SIGNUP_PATH,
  getPostAuthRedirectPath,
} from '@/shared/auth/redirects';
import { AuthErrorBanner } from './auth-error-banner';
import {
  AuthInlineLink,
  AuthLinkGroup,
  FormDivider,
  FormField,
  FormRow,
  FormStack,
  SubmitButton,
  TextInput,
} from './auth-form-ui';
import { SsoButtons } from './sso-buttons';

type LoginFormProps = {
  ssoProviders: PublicSsoProvider[];
  publicSignupEnabled: boolean;
  returnTo?: string | null;
};

export function LoginForm({ ssoProviders, publicSignupEnabled, returnTo }: LoginFormProps) {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const forgotHref = returnTo
    ? `${AUTH_FORGOT_PASSWORD_PATH}?returnTo=${encodeURIComponent(returnTo)}`
    : AUTH_FORGOT_PASSWORD_PATH;
  const signupHref = returnTo
    ? `${AUTH_SIGNUP_PATH}?returnTo=${encodeURIComponent(returnTo)}`
    : AUTH_SIGNUP_PATH;

  const submitLogin = async (): Promise<void> => {
    setPending(true);
    setError(null);

    const result = await login({ email, password });

    if (!result.ok) {
      setError(result.error);
      setPending(false);
      return;
    }

    router.replace(getPostAuthRedirectPath(result.data.nextAction, returnTo));
    router.refresh();
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitLogin();
  };

  return (
    <form onSubmit={handleSubmit}>
      <FormStack>
        <AuthErrorBanner error={error} fallbackMessage="Unable to sign in." />

        <FormField label="Email" htmlFor="login-email">
          <TextInput
            id="login-email"
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

        <FormField label="Password" htmlFor="login-password">
          <TextInput
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            disabled={pending}
            onChange={(event: ChangeEvent<HTMLInputElement>) => setPassword(event.target.value)}
            placeholder="Enter your password"
            required
          />
        </FormField>

        <FormRow right={<AuthInlineLink href={forgotHref}>Forgot your password?</AuthInlineLink>} />

        <SubmitButton disabled={pending}>{pending ? 'Signing in…' : 'Sign in'}</SubmitButton>

        {ssoProviders.length ? (
          <>
            <FormDivider label="or continue with" />
            <SsoButtons providers={ssoProviders} returnTo={returnTo} disabled={pending} />
          </>
        ) : null}

        <AuthLinkGroup>
          {publicSignupEnabled ? (
            <>
              <span>Need an account?</span>
              <Link href={signupHref}>Create one</Link>
            </>
          ) : (
            <span>Need access? Ask a workspace admin to send you an invite.</span>
          )}
        </AuthLinkGroup>
      </FormStack>
    </form>
  );
}
