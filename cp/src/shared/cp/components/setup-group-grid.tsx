import Link from 'next/link';
import type { CSSProperties } from 'react';
import type { ControlPlaneAccountDraft } from '@/features/accounts/contracts';
import { SETUP_GROUPS } from '@/features/accounts/setup-groups';
import { infoCardStyle, infoGridStyle, labelStyle, mutedTextStyle, valueStyle } from '../styles';

const badgeStyle = (reviewed: boolean): CSSProperties => ({
  display: 'inline-flex',
  width: 'fit-content',
  padding: '6px 10px',
  borderRadius: '999px',
  fontSize: '12px',
  fontWeight: 700,
  color: reviewed ? '#166534' : '#92400e',
  backgroundColor: reviewed ? '#dcfce7' : '#fef3c7',
});

const linkStyle: CSSProperties = {
  fontSize: '14px',
  fontWeight: 700,
  textDecoration: 'none',
  color: '#0f172a',
};

type SetupGroupGridProps = {
  account: Pick<ControlPlaneAccountDraft, 'setupGroupsReviewed'>;
  getGroupHref: (groupSlug: string) => string;
};

export function SetupGroupGrid({ account, getGroupHref }: SetupGroupGridProps) {
  return (
    <div style={infoGridStyle}>
      {SETUP_GROUPS.map((group) => {
        const reviewed = account.setupGroupsReviewed.includes(group.slug);

        return (
          <article key={group.slug} style={infoCardStyle}>
            <p style={labelStyle}>Setup group</p>
            <p style={valueStyle}>{group.title}</p>
            <p style={mutedTextStyle}>{group.description}</p>
            <span style={badgeStyle(reviewed)}>{reviewed ? 'Reviewed' : 'Needs review'}</span>
            <Link href={getGroupHref(group.slug)} style={linkStyle}>
              Open group →
            </Link>
          </article>
        );
      })}
    </div>
  );
}
