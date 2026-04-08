import type { CSSProperties } from 'react';
import type { ControlPlaneAccountDraft } from '@/features/accounts/contracts';
import { panelStyle } from '../styles';

const barStyle: CSSProperties = {
  ...panelStyle,
  padding: '14px 18px',
  fontSize: '14px',
  fontWeight: 600,
  color: '#1e293b',
};

type AccountContextBarProps = {
  account: Pick<ControlPlaneAccountDraft, 'name' | 'key'>;
};

export function AccountContextBar({ account }: AccountContextBarProps) {
  return (
    <section aria-label="Account context" style={barStyle}>
      Account Name: {account.name} | Account Key: {account.key}
    </section>
  );
}
