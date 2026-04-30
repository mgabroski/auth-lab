'use client';

/**
 * frontend/src/shared/auth/components/invite-register-form.tsx
 *
 * WHY:
 * - Implements the invite-driven register/set-password continuation.
 * - Uses POST /auth/register with the accepted invite token from the URL.
 * - Keeps the page thin while letting backend `nextAction` drive the post-register route.
 */

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useEffect, useState, type ChangeEvent, type FormEvent } from 'react';
import { loadInviteEmail } from '@/shared/auth/invite-email-cache';
import { registerWithInvite } from '@/shared/auth/browser-api';
import { AUTH_LOGIN_PATH, getPostAuthRedirectPath } from '@/shared/auth/redirects';
import { AuthErrorBanner } from './auth-error-banner';

import {
  AuthLinkGroup,
  AuthNote,
  FormField,
  FormStack,
  SubmitButton,
  TextInput,
} from './auth-form-ui';

type InviteRegisterFormProps = {
  token: string;
  returnTo?: string | null;
};

export function InviteRegisterForm({ token, returnTo }: InviteRegisterFormProps) {
  const router = useRouter();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [emailPrefilled, setEmailPrefilled] = useState(false);

  useEffect(() => {
    const invitedEmail = loadInviteEmail(token);

    if (invitedEmail) {
      setEmail(invitedEmail);
      setEmailPrefilled(true);
    }
  }, [token]);

  const loginHref = returnTo
    ? `${AUTH_LOGIN_PATH}?returnTo=${encodeURIComponent(returnTo)}`
    : AUTH_LOGIN_PATH;

  const submitRegister = async (): Promise<void> => {
    setPending(true);
    setError(null);

    const result = await registerWithInvite({
      name,
      email,
      password,
      inviteToken: token,
    });

    if (!result.ok) {
      setError(result.error);
      setPending(false);
      return;
    }

    router.replace(
      getPostAuthRedirectPath(result.data.nextAction, result.data.membership.role, returnTo),
    );
    router.refresh();
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitRegister();
  };

  return (
    <form onSubmit={handleSubmit}>
      <FormStack>
        <AuthErrorBanner error={error} fallbackMessage="Unable to finish invite registration." />

        <AuthNote>
          Use the email address that received the invitation. After registration succeeds, the
          backend establishes the session and the frontend routes from the returned{' '}
          <code>nextAction</code>.
        </AuthNote>

        <FormField label="Full name" htmlFor="invite-register-name">
          <TextInput
            id="invite-register-name"
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

        <FormField
          label="Email"
          htmlFor="invite-register-email"
          hint="This must match the email address that received the workspace invitation."
        >
          <TextInput
            id="invite-register-email"
            name="email"
            type="email"
            autoComplete="email"
            inputMode="email"
            value={email}
            readOnly={emailPrefilled}
            disabled={pending}
            onChange={(event: ChangeEvent<HTMLInputElement>) => setEmail(event.target.value)}
            placeholder="you@company.com"
            required
          />
        </FormField>

        <FormField
          label="Password"
          htmlFor="invite-register-password"
          hint="Use at least 8 characters. This password is created through the invite registration flow, not public signup."
        >
          <TextInput
            id="invite-register-password"
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
          {pending ? 'Finishing account setup…' : 'Set password and continue'}
        </SubmitButton>

        <AuthLinkGroup>
          <span>Already have credentials?</span>
          <Link href={loginHref}>Sign in instead</Link>
        </AuthLinkGroup>
      </FormStack>
    </form>
  );
}
