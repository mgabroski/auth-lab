'use client';

/**
 * frontend/src/shared/auth/components/logout-button.tsx
 *
 * WHY:
 * - Implements the real logout interaction for authenticated routes.
 * - Calls the backend logout endpoint so session destruction stays backend-owned.
 * - Routes the browser back through the public root handoff after the cookie is cleared.
 */

import { useRouter } from 'next/navigation';
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
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleLogout = async (): Promise<void> => {
    setPending(true);
    setErrorMessage(null);

    const result = await logout();

    if (result.ok) {
      router.replace(ROOT_HANDOFF_PATH);
      router.refresh();
      return;
    }

    if (result.status === 401) {
      router.replace(ROOT_HANDOFF_PATH);
      router.refresh();
      return;
    }

    setErrorMessage(getApiErrorMessage(result.error, 'Unable to log out right now.'));
    setPending(false);
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
