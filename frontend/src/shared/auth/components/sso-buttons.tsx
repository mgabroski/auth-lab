'use client';

/**
 * frontend/src/shared/auth/components/sso-buttons.tsx
 *
 * WHY:
 * - Centralizes SSO button rendering so future auth pages do not repeat provider-specific UI.
 * - Uses the shared `startSso()` navigation helper instead of fetch(), matching the locked topology.
 */

import type { CSSProperties } from 'react';
import { useState } from 'react';
import type { PublicSsoProvider } from '../contracts';
import { startSso } from '../sso';

type SsoButtonsProps = {
  providers: PublicSsoProvider[];
  returnTo?: string | null;
  disabled?: boolean;
};

const stackStyle: CSSProperties = {
  display: 'grid',
  gap: '12px',
};

const buttonStyle: CSSProperties = {
  width: '100%',
  borderRadius: '12px',
  border: '1px solid rgba(148, 163, 184, 0.35)',
  backgroundColor: '#ffffff',
  color: '#0f172a',
  padding: '12px 16px',
  fontSize: '14px',
  fontWeight: 600,
  cursor: 'pointer',
};

function labelForProvider(provider: PublicSsoProvider): string {
  switch (provider) {
    case 'google':
      return 'Continue with Google';
    case 'microsoft':
      return 'Continue with Microsoft';
    default: {
      const exhaustiveCheck: never = provider;
      throw new Error(`Unhandled SSO provider: ${String(exhaustiveCheck)}`);
    }
  }
}

export function SsoButtons({ providers, returnTo, disabled = false }: SsoButtonsProps) {
  const [pendingProvider, setPendingProvider] = useState<PublicSsoProvider | null>(null);

  if (!providers.length) {
    return null;
  }

  return (
    <div style={stackStyle}>
      {providers.map((provider) => {
        const isPending = pendingProvider === provider;

        return (
          <button
            key={provider}
            type="button"
            style={buttonStyle}
            disabled={disabled || pendingProvider !== null}
            onClick={() => {
              setPendingProvider(provider);
              startSso(provider, { returnTo });
            }}
          >
            {isPending ? 'Redirecting…' : labelForProvider(provider)}
          </button>
        );
      })}
    </div>
  );
}
