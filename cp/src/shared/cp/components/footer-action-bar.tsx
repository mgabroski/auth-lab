/**
 * cp/src/shared/cp/components/footer-action-bar.tsx
 *
 * WHY:
 * - Renders the locked CP footer action row (back / save-draft / continue pattern).
 * - Supports both link actions and button actions without requiring wrapper-specific composition.
 */

import Link from 'next/link';
import type { CSSProperties } from 'react';
import type { FooterAction } from '@/features/accounts/contracts';
import { panelStyle } from '../styles';

const footerStyle: CSSProperties = {
  ...panelStyle,
  padding: '16px 20px',
  display: 'flex',
  justifyContent: 'flex-end',
  gap: '12px',
  flexWrap: 'wrap',
};

const baseActionStyle: CSSProperties = {
  borderRadius: '999px',
  padding: '10px 16px',
  fontSize: '14px',
  fontWeight: 700,
  textDecoration: 'none',
  border: '1px solid transparent',
  cursor: 'pointer',
};

const variantStyles: Record<'ghost' | 'secondary' | 'primary', CSSProperties> = {
  ghost: {
    backgroundColor: 'transparent',
    borderColor: 'transparent',
    color: '#475569',
  },
  secondary: {
    backgroundColor: '#ffffff',
    borderColor: '#cbd5e1',
    color: '#0f172a',
  },
  primary: {
    backgroundColor: '#0f172a',
    borderColor: '#0f172a',
    color: '#ffffff',
  },
};

const disabledStyle: CSSProperties = {
  opacity: 0.55,
  cursor: 'not-allowed',
};

type FooterActionBarProps = {
  actions: FooterAction[];
};

export function FooterActionBar({ actions }: FooterActionBarProps) {
  return (
    <footer style={footerStyle}>
      {actions.map((action) => {
        const style = {
          ...baseActionStyle,
          ...variantStyles[action.variant ?? 'secondary'],
          ...(action.disabled ? disabledStyle : null),
        };

        if (action.href && !action.disabled) {
          return (
            <Link
              key={`${action.label}-${action.href}`}
              href={action.href}
              aria-label={action.ariaLabel}
              style={style}
            >
              {action.label}
            </Link>
          );
        }

        return (
          <button
            key={action.label}
            type="button"
            aria-label={action.ariaLabel}
            disabled={action.disabled}
            onClick={action.onClick}
            style={style}
          >
            {action.label}
          </button>
        );
      })}
    </footer>
  );
}
