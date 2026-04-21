import type { CSSProperties } from 'react';

import type {
  SettingsOverviewCardResponse,
  SettingsSetupStatus,
} from '@/shared/settings/contracts';

type DisplayStatus = SettingsSetupStatus | 'PLACEHOLDER';

const baseStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  padding: '4px 10px',
  borderRadius: '999px',
  border: '1px solid transparent',
  fontSize: '12px',
  fontWeight: 700,
  lineHeight: 1,
  whiteSpace: 'nowrap',
};

const statusStyles: Record<DisplayStatus, CSSProperties> = {
  NOT_STARTED: {
    color: '#475569',
    backgroundColor: '#f8fafc',
    borderColor: '#cbd5e1',
  },
  IN_PROGRESS: {
    color: '#1d4ed8',
    backgroundColor: '#dbeafe',
    borderColor: '#93c5fd',
  },
  COMPLETE: {
    color: '#166534',
    backgroundColor: '#dcfce7',
    borderColor: '#86efac',
  },
  NEEDS_REVIEW: {
    color: '#b45309',
    backgroundColor: '#fef3c7',
    borderColor: '#fcd34d',
  },
  PLACEHOLDER: {
    color: '#7c3aed',
    backgroundColor: '#f3e8ff',
    borderColor: '#d8b4fe',
  },
};

function getLabel(status: DisplayStatus): string {
  switch (status) {
    case 'NOT_STARTED':
      return 'Not started';
    case 'IN_PROGRESS':
      return 'In progress';
    case 'COMPLETE':
      return 'Complete';
    case 'NEEDS_REVIEW':
      return 'Needs review';
    case 'PLACEHOLDER':
      return 'Placeholder';
    default: {
      const exhaustiveCheck: never = status;
      return String(exhaustiveCheck);
    }
  }
}

type SettingsStatusChipProps = {
  status: SettingsOverviewCardResponse['status'];
};

export function SettingsStatusChip({ status }: SettingsStatusChipProps) {
  return <span style={{ ...baseStyle, ...statusStyles[status] }}>{getLabel(status)}</span>;
}
