'use client';

/**
 * frontend/src/shared/auth/components/logout-button.tsx
 *
 * WHY window.location.replace instead of router.replace:
 * - Logout clears the session cookie via Set-Cookie: sid=; Max-Age=0 in the
 *   POST /auth/logout response.
 * - Next.js router.replace() is a soft navigation — it fetches the RSC payload
 *   for the next route while cookie changes from the previous response may not
 *   yet be applied to the browser's cookie jar.
 * - This race condition causes the root page SSR to still see the old session
 *   cookie, redirecting back to /app instead of /auth/login.
 * - window.location.replace() is a hard redirect: the browser applies all
 *   pending cookie changes before issuing the new request. SSR then sees no
 *   cookie, reads 401 from /auth/me, and correctly redirects to /auth/login.
 */

import { useState } from 'react';
import { logout } from '@/shared/auth/browser-api';
import { getApiErrorMessage } from '@/shared/auth/api-errors';
import { ROOT_HANDOFF_PATH } from '@/shared/auth/redirects';

const buttonStyle = {
  minHeight: '42px',
  borderRadius: '12px',
  border: '1px solid rgba(148, 163, 184, 0.3)',
  backgroundColor: '#ffffff',
  color: '#0f172a',
  padding: '10px 14px',
  fontSize: '14px',
  fontWeight: 600,
  cursor: 'pointer',
} as const;

const feedbackStyle = {
  margin: 0,
  fontSize: '13px',
  lineHeight: 1.5,
  color: '#b91c1c',
} as const;

export function LogoutButton() {
  const [pending, setPending] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleLogout = async (): Promise<void> => {
    try {
      setPending(true);
      setErrorMessage(null);

      const result = await logout();

      if (result.ok || result.status === 401) {
        // Hard redirect — ensures the cleared session cookie is applied before
        // the next server request, so SSR correctly sees an unauthenticated state.
        window.location.replace(ROOT_HANDOFF_PATH);
        return;
      }

      setErrorMessage(getApiErrorMessage(result.error, 'Unable to log out right now.'));
      setPending(false);
    } catch (caughtError) {
      setErrorMessage(getApiErrorMessage(caughtError, 'Unable to log out right now.'));
      setPending(false);
    }
  };

  return (
    <div style={{ display: 'grid', gap: '8px', justifyItems: 'end' }}>
      <button
        type="button"
        style={buttonStyle}
        disabled={pending}
        onClick={() => void handleLogout()}
      >
        {pending ? 'Signing out…' : 'Log out'}
      </button>
      {errorMessage ? <p style={feedbackStyle}>{errorMessage}</p> : null}
    </div>
  );
}
