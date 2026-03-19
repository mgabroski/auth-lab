'use client';

/**
 * frontend/src/shared/auth/components/mfa-setup-flow.tsx
 *
 * WHY:
 * - Implements the real MFA setup continuation flow using backend setup + verify-setup endpoints.
 * - Shows a scannable QR code, the raw authenticator URI, and recovery codes returned by the backend.
 * - Keeps the page thin while the browser owns the interactive setup state.
 *
 * PHASE 9 UPDATE (ADR 0003):
 * - Accepts a `role: MembershipRole` prop (supplied by the SSR page from
 *   routeState.me.membership.role) so getPostAuthRedirectPath routes
 *   NONE + ADMIN → /admin correctly after MFA setup completes.
 * - The verify-setup response always returns nextAction: 'NONE'; role comes from
 *   the SSR page props which already have the fully resolved session context.
 *   No extra GET /auth/me call is required.
 */

import {
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type CSSProperties,
  type FormEvent,
} from 'react';
import QRCode from 'react-qr-code';
import { useRouter } from 'next/navigation';
import type { MfaSetupResponse, MembershipRole } from '@/shared/auth/contracts';
import { setupMfa, verifyMfaSetup } from '@/shared/auth/browser-api';
import { parseOtpAuthUri } from '@/shared/auth/otpauth';
import { AUTHENTICATED_APP_ENTRY_PATH, getPostAuthRedirectPath } from '@/shared/auth/redirects';
import { AuthErrorBanner } from './auth-error-banner';
import { AuthSuccessBanner } from './auth-success-banner';
import {
  AuthNote,
  FormField,
  FormStack,
  SecondaryButton,
  SubmitButton,
  TextArea,
  TextInput,
} from './auth-form-ui';

const qrSectionStyle: CSSProperties = {
  display: 'grid',
  gap: '12px',
};

const qrCardStyle: CSSProperties = {
  display: 'grid',
  gap: '16px',
  padding: '16px',
  borderRadius: '16px',
  border: '1px solid #cbd5e1',
  background: '#f8fafc',
};

const qrImageShellStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  width: 'fit-content',
  padding: '12px',
  borderRadius: '12px',
  background: '#ffffff',
  boxShadow: 'inset 0 0 0 1px #e2e8f0',
};

const qrMetaStyle: CSSProperties = {
  display: 'grid',
  gap: '6px',
  color: '#334155',
  fontSize: '14px',
  lineHeight: 1.6,
};

const qrMetaLabelStyle: CSSProperties = {
  margin: 0,
  fontSize: '12px',
  fontWeight: 700,
  letterSpacing: '0.04em',
  textTransform: 'uppercase',
  color: '#475569',
};

const recoveryCodeListStyle: CSSProperties = {
  display: 'grid',
  gap: '8px',
  margin: 0,
  paddingLeft: '18px',
  color: '#334155',
  fontSize: '14px',
  lineHeight: 1.6,
};

type MfaSetupFlowProps = {
  userEmail: string;
  /** Phase 9: required to route NONE + ADMIN → /admin correctly after setup. */
  role: MembershipRole;
};

export function MfaSetupFlow({ userEmail, role }: MfaSetupFlowProps) {
  const router = useRouter();
  const setupRequestedRef = useRef(false);
  const [setupData, setSetupData] = useState<MfaSetupResponse | null>(null);
  const [setupPending, setSetupPending] = useState(false);
  const [verifyPending, setVerifyPending] = useState(false);
  const [code, setCode] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const parsedOtpAuth = setupData ? parseOtpAuthUri(setupData.qrCodeUri) : null;
  const expectedIssuer = parsedOtpAuth?.issuer ?? 'Hubins';
  const expectedAccountLabel = parsedOtpAuth?.accountLabel ?? userEmail;

  const requestSetup = async (): Promise<void> => {
    try {
      setSetupPending(true);
      setError(null);
      setSuccessMessage(null);

      const result = await setupMfa();

      if (!result.ok) {
        setError(result.error);
        setSetupPending(false);
        return;
      }

      setSetupData(result.data);
      setSetupPending(false);
    } catch (caughtError) {
      setError(caughtError);
      setSetupPending(false);
    }
  };

  const submitVerifySetup = async (): Promise<void> => {
    try {
      setVerifyPending(true);
      setError(null);
      setSuccessMessage(null);

      const result = await verifyMfaSetup({ code });

      if (!result.ok) {
        setError(result.error);
        setVerifyPending(false);
        return;
      }

      setSuccessMessage('MFA setup completed. Redirecting to your workspace…');
      // Phase 9: role prop is supplied by the SSR page so NONE + ADMIN → /admin.
      router.replace(getPostAuthRedirectPath(result.data.nextAction, role, null));
    } catch (caughtError) {
      setError(caughtError);
      setVerifyPending(false);
    }
  };

  useEffect(() => {
    if (setupRequestedRef.current) {
      return;
    }

    setupRequestedRef.current = true;
    void requestSetup();
  }, []);

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitVerifySetup();
  };

  return (
    <form onSubmit={handleSubmit}>
      <FormStack>
        <AuthSuccessBanner title="MFA setup" message={successMessage} />
        <AuthErrorBanner error={error} fallbackMessage="Unable to complete MFA setup." />

        <AuthNote>
          Configure your authenticator app for <strong>{userEmail}</strong>. The backend setup call
          returns a fresh secret, a QR-ready <code>otpauth://</code> URI, and one-time recovery
          codes.
        </AuthNote>

        {setupData ? (
          <>
            <div style={qrSectionStyle}>
              <strong style={{ fontSize: '14px', color: '#0f172a' }}>
                Scan in your authenticator app
              </strong>
              <p
                style={{
                  margin: 0,
                  fontSize: '14px',
                  lineHeight: 1.6,
                  color: '#475569',
                }}
              >
                Scan this QR code with Google Authenticator, Microsoft Authenticator, 1Password, or
                another TOTP app. After scanning, the app entry should show the issuer and verified
                email below.
              </p>
              <div style={qrCardStyle}>
                <div role="img" aria-label="Authenticator QR code" style={qrImageShellStyle}>
                  <QRCode size={176} value={setupData.qrCodeUri} />
                </div>
                <div style={qrMetaStyle}>
                  <p style={qrMetaLabelStyle}>Expected app entry</p>
                  <p style={{ margin: 0 }}>
                    <strong>Issuer:</strong> {expectedIssuer}
                  </p>
                  <p style={{ margin: 0 }}>
                    <strong>Account label:</strong> {expectedAccountLabel}
                  </p>
                </div>
              </div>
            </div>

            <FormField
              label="Authenticator secret"
              htmlFor="mfa-setup-secret"
              hint="Enter this secret manually if your authenticator app cannot scan the QR code or cannot open the URI directly."
            >
              <TextInput id="mfa-setup-secret" value={setupData.secret} readOnly />
            </FormField>

            <FormField
              label="Authenticator URI"
              htmlFor="mfa-setup-uri"
              hint="This is the exact backend-provided setup URI. It remains visible for manual import and proof debugging."
            >
              <TextArea id="mfa-setup-uri" value={setupData.qrCodeUri} readOnly />
            </FormField>

            <div>
              <strong style={{ fontSize: '14px', color: '#0f172a' }}>Recovery codes</strong>
              <p
                style={{
                  marginTop: '8px',
                  marginBottom: '8px',
                  fontSize: '14px',
                  lineHeight: 1.6,
                  color: '#475569',
                }}
              >
                Save these codes now. Each code can be used once if you lose access to your
                authenticator app.
              </p>
              <ol style={recoveryCodeListStyle}>
                {setupData.recoveryCodes.map((recoveryCode) => (
                  <li key={recoveryCode}>
                    <code>{recoveryCode}</code>
                  </li>
                ))}
              </ol>
            </div>
          </>
        ) : (
          <AuthNote>
            {setupPending
              ? 'Preparing your MFA secret, QR setup data, and recovery codes…'
              : 'The page is waiting for the backend to start MFA setup.'}
          </AuthNote>
        )}

        <FormField
          label="6-digit code"
          htmlFor="mfa-setup-code"
          hint="Open your authenticator app, enter the current 6-digit code, and submit it to POST /auth/mfa/verify-setup."
        >
          <TextInput
            id="mfa-setup-code"
            name="code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            disabled={setupPending || verifyPending || !setupData}
            onChange={(event: ChangeEvent<HTMLInputElement>) => setCode(event.target.value)}
            placeholder="123456"
            required
          />
        </FormField>

        <SubmitButton disabled={setupPending || verifyPending || !setupData}>
          {verifyPending ? 'Verifying MFA setup…' : 'Finish MFA setup'}
        </SubmitButton>

        <SecondaryButton
          disabled={setupPending || verifyPending}
          onClick={() => {
            void requestSetup();
          }}
        >
          {setupPending ? 'Refreshing setup secret…' : 'Generate a new setup secret'}
        </SecondaryButton>

        <SecondaryButton
          disabled={setupPending || verifyPending}
          onClick={() => {
            router.replace(AUTHENTICATED_APP_ENTRY_PATH);
          }}
        >
          Refresh auth state
        </SecondaryButton>
      </FormStack>
    </form>
  );
}
