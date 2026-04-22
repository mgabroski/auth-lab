import Link from 'next/link';
import type { CSSProperties } from 'react';

import type {
  PersonalFieldConfigurationItemResponse,
  PersonalSettingsResponse,
} from '@/shared/settings/contracts';
import { SettingsStatusChip } from './settings-status-chip';

const cardStyle: CSSProperties = {
  display: 'grid',
  gap: '14px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -28px rgba(15, 23, 42, 0.35)',
};

const panelStyle: CSSProperties = {
  display: 'grid',
  gap: '12px',
  padding: '18px',
  borderRadius: '18px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#f8fafc',
};

const surfaceStyle: CSSProperties = {
  display: 'grid',
  gap: '12px',
  padding: '16px',
  borderRadius: '16px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
};

const actionLinkStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: '6px',
  color: '#1d4ed8',
  fontSize: '14px',
  fontWeight: 600,
  textDecoration: 'none',
};

const pillStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  padding: '4px 10px',
  borderRadius: '999px',
  border: '1px solid #cbd5e1',
  fontSize: '12px',
  fontWeight: 700,
  color: '#475569',
  backgroundColor: '#f8fafc',
};

function badgeStyle(params: {
  tone: 'slate' | 'amber' | 'blue' | 'green' | 'violet';
}): CSSProperties {
  switch (params.tone) {
    case 'amber':
      return {
        ...pillStyle,
        border: '1px solid #fcd34d',
        color: '#b45309',
        backgroundColor: '#fef3c7',
      };
    case 'blue':
      return {
        ...pillStyle,
        border: '1px solid #bfdbfe',
        color: '#1d4ed8',
        backgroundColor: '#eff6ff',
      };
    case 'green':
      return {
        ...pillStyle,
        border: '1px solid #bbf7d0',
        color: '#166534',
        backgroundColor: '#f0fdf4',
      };
    case 'violet':
      return {
        ...pillStyle,
        border: '1px solid #d8b4fe',
        color: '#7c3aed',
        backgroundColor: '#f3e8ff',
      };
    case 'slate':
    default:
      return pillStyle;
  }
}

function readinessLabel(field: PersonalFieldConfigurationItemResponse): {
  label: string;
  tone: 'slate' | 'blue' | 'green' | 'violet';
} {
  switch (field.readiness) {
    case 'SYSTEM_MANAGED':
      return {
        label: 'System-managed',
        tone: 'violet',
      };
    case 'CP_DEFAULT_SELECTED':
      return {
        label: 'CP default-selected',
        tone: 'green',
      };
    case 'AVAILABLE_TO_INCLUDE':
    default:
      return {
        label: 'Available to include later',
        tone: 'slate',
      };
  }
}

function requiredRuleLabel(field: PersonalFieldConfigurationItemResponse): {
  label: string;
  tone: 'amber' | 'slate' | 'violet';
} {
  switch (field.requiredRule) {
    case 'LOCKED_REQUIRED':
      return {
        label: 'Required (locked)',
        tone: 'amber',
      };
    case 'SYSTEM_MANAGED':
      return {
        label: 'System-managed',
        tone: 'violet',
      };
    case 'TENANT_CHOICE':
    default:
      return {
        label: 'Required or optional later',
        tone: 'slate',
      };
  }
}

function maskingRuleLabel(field: PersonalFieldConfigurationItemResponse): {
  label: string;
  tone: 'slate' | 'violet';
} {
  switch (field.maskingRule) {
    case 'LOCKED_SYSTEM_MANAGED':
      return {
        label: 'Masking locked',
        tone: 'violet',
      };
    case 'TENANT_CHOICE_WHEN_INCLUDED':
    default:
      return {
        label: 'Masked or unmasked later',
        tone: 'slate',
      };
  }
}

function fieldCard(field: PersonalFieldConfigurationItemResponse) {
  const readiness = readinessLabel(field);
  const requiredRule = requiredRuleLabel(field);
  const maskingRule = maskingRuleLabel(field);

  return (
    <article
      key={field.fieldKey}
      style={{
        display: 'grid',
        gap: '10px',
        padding: '14px',
        borderRadius: '14px',
        border: '1px solid rgba(148, 163, 184, 0.2)',
        backgroundColor: '#ffffff',
      }}
    >
      <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
        <h5 style={{ margin: 0, fontSize: '15px', lineHeight: 1.2, color: '#0f172a' }}>
          {field.label}
        </h5>
        <span style={badgeStyle({ tone: readiness.tone })}>{readiness.label}</span>
        {field.presentationState === 'READ_ONLY_SYSTEM_MANAGED' ? (
          <span style={badgeStyle({ tone: 'violet' })}>Read-only</span>
        ) : (
          <span style={badgeStyle({ tone: 'blue' })}>Tenant-configurable later</span>
        )}
      </div>

      <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#475569' }}>
        {field.notes}
      </p>

      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        <span style={badgeStyle({ tone: requiredRule.tone })}>{requiredRule.label}</span>
        <span style={badgeStyle({ tone: maskingRule.tone })}>{maskingRule.label}</span>
        {field.canBeExcludedLater ? (
          <span style={badgeStyle({ tone: 'slate' })}>May be excluded later</span>
        ) : (
          <span style={badgeStyle({ tone: 'amber' })}>Cannot be excluded</span>
        )}
      </div>

      <div style={{ display: 'grid', gap: '6px' }}>
        {field.blockers.length > 0 ? (
          <ul
            style={{
              margin: 0,
              paddingLeft: '18px',
              display: 'grid',
              gap: '4px',
              color: '#9a3412',
              fontSize: '13px',
              lineHeight: 1.6,
            }}
          >
            {field.blockers.map((blocker) => (
              <li key={blocker}>{blocker}</li>
            ))}
          </ul>
        ) : null}
        {field.warnings.length > 0 ? (
          <ul
            style={{
              margin: 0,
              paddingLeft: '18px',
              display: 'grid',
              gap: '4px',
              color: '#64748b',
              fontSize: '13px',
              lineHeight: 1.6,
            }}
          >
            {field.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        ) : null}
      </div>
    </article>
  );
}

type PersonalSettingsFoundationProps = {
  data: PersonalSettingsResponse;
};

export function PersonalSettingsFoundation({ data }: PersonalSettingsFoundationProps) {
  return (
    <div style={{ display: 'grid', gap: '16px' }}>
      <section style={cardStyle}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <h2 style={{ margin: 0, fontSize: '22px', lineHeight: 1.2, color: '#0f172a' }}>
            {data.title}
          </h2>
          <SettingsStatusChip status={data.status} />
        </div>
        <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
          {data.description}
        </p>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <span style={pillStyle}>Section version {data.version}</span>
          <span style={pillStyle}>CP revision {data.cpRevision}</span>
        </div>
        {data.nextAction ? (
          <Link href={data.nextAction.href} style={actionLinkStyle}>
            → {data.nextAction.label}
          </Link>
        ) : null}
        {data.blockers.length > 0 ? (
          <ul
            style={{
              margin: 0,
              paddingLeft: '18px',
              display: 'grid',
              gap: '6px',
              color: '#991b1b',
              fontSize: '13px',
              lineHeight: 1.6,
            }}
          >
            {data.blockers.map((blocker) => (
              <li key={blocker}>{blocker}</li>
            ))}
          </ul>
        ) : null}
        {data.warnings.length > 0 ? (
          <ul
            style={{
              margin: 0,
              paddingLeft: '18px',
              display: 'grid',
              gap: '6px',
              color: '#9a3412',
              fontSize: '13px',
              lineHeight: 1.6,
            }}
          >
            {data.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        ) : null}
      </section>

      <section style={panelStyle}>
        <div style={{ display: 'grid', gap: '6px' }}>
          <h3 style={{ margin: 0, fontSize: '18px', lineHeight: 1.2, color: '#0f172a' }}>
            {data.familyReview.title}
          </h3>
          <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
            {data.familyReview.description}
          </p>
          <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#64748b' }}>
            {data.familyReview.summary}
          </p>
        </div>

        <div style={{ display: 'grid', gap: '12px' }}>
          {data.familyReview.families.map((family) => (
            <article key={family.familyKey} style={surfaceStyle}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <h4 style={{ margin: 0, fontSize: '16px', lineHeight: 1.2, color: '#0f172a' }}>
                  {family.label}
                </h4>
                <span style={badgeStyle({ tone: 'slate' })}>Review not saved yet</span>
                {!family.canExclude ? (
                  <span style={badgeStyle({ tone: 'amber' })}>Family exclusion locked</span>
                ) : (
                  <span style={badgeStyle({ tone: 'blue' })}>Family may be excluded later</span>
                )}
              </div>
              <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#475569' }}>
                {family.allowedFieldCount} allowed fields · {family.defaultSelectedFieldCount} CP
                defaults
              </p>
              {family.requiredFieldKeys.length > 0 ? (
                <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#475569' }}>
                  Required baseline: {family.requiredFieldKeys.join(', ')}
                </p>
              ) : null}
              {family.systemManagedFieldKeys.length > 0 ? (
                <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#475569' }}>
                  System-managed: {family.systemManagedFieldKeys.join(', ')}
                </p>
              ) : null}
              <ul
                style={{
                  margin: 0,
                  paddingLeft: '18px',
                  display: 'grid',
                  gap: '6px',
                  fontSize: '13px',
                  lineHeight: 1.6,
                  color: '#64748b',
                }}
              >
                {family.notes.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </section>

      <section style={panelStyle}>
        <div style={{ display: 'grid', gap: '6px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <h3 style={{ margin: 0, fontSize: '18px', lineHeight: 1.2, color: '#0f172a' }}>
              {data.fieldConfiguration.title}
            </h3>
            <span style={badgeStyle({ tone: 'green' })}>Current foundation</span>
          </div>
          <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
            {data.fieldConfiguration.description}
          </p>
          <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#64748b' }}>
            {data.fieldConfiguration.summary}
          </p>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
            gap: '12px',
          }}
        >
          <article style={surfaceStyle}>
            <h4 style={{ margin: 0, fontSize: '15px', lineHeight: 1.2, color: '#0f172a' }}>
              Hidden
            </h4>
            <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#475569' }}>
              {data.fieldConfiguration.hiddenVsExcluded.hidden}
            </p>
          </article>
          <article style={surfaceStyle}>
            <h4 style={{ margin: 0, fontSize: '15px', lineHeight: 1.2, color: '#0f172a' }}>
              Excluded
            </h4>
            <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#475569' }}>
              {data.fieldConfiguration.hiddenVsExcluded.excluded}
            </p>
          </article>
        </div>

        <article style={surfaceStyle}>
          <h4 style={{ margin: 0, fontSize: '15px', lineHeight: 1.2, color: '#0f172a' }}>
            Conflict groundwork
          </h4>
          <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#475569' }}>
            {data.fieldConfiguration.conflictGuidance.summary}
          </p>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <span style={pillStyle}>
              Expected version {data.fieldConfiguration.conflictGuidance.version}
            </span>
            <span style={pillStyle}>
              Expected CP revision {data.fieldConfiguration.conflictGuidance.cpRevision}
            </span>
          </div>
          <ul
            style={{
              margin: 0,
              paddingLeft: '18px',
              display: 'grid',
              gap: '6px',
              fontSize: '13px',
              lineHeight: 1.6,
              color: '#64748b',
            }}
          >
            {data.fieldConfiguration.conflictGuidance.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </article>

        <div style={{ display: 'grid', gap: '12px' }}>
          {data.fieldConfiguration.families.map((family) => (
            <article key={family.familyKey} style={surfaceStyle}>
              <div style={{ display: 'grid', gap: '6px' }}>
                <div
                  style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}
                >
                  <h4 style={{ margin: 0, fontSize: '16px', lineHeight: 1.2, color: '#0f172a' }}>
                    {family.label}
                  </h4>
                  {family.canExclude ? (
                    <span style={badgeStyle({ tone: 'blue' })}>Family may be excluded later</span>
                  ) : (
                    <span style={badgeStyle({ tone: 'amber' })}>Family must stay visible</span>
                  )}
                </div>
                <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#475569' }}>
                  {family.visibleFieldCount} visible fields · {family.defaultSelectedFieldCount} CP
                  defaults · {family.minimumRequiredFieldCount} required-floor ·{' '}
                  {family.systemManagedFieldCount} system-managed
                </p>
                {family.exclusionLockedReason ? (
                  <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#9a3412' }}>
                    {family.exclusionLockedReason}
                  </p>
                ) : null}
                <ul
                  style={{
                    margin: 0,
                    paddingLeft: '18px',
                    display: 'grid',
                    gap: '4px',
                    fontSize: '13px',
                    lineHeight: 1.6,
                    color: '#64748b',
                  }}
                >
                  {family.notes.map((note) => (
                    <li key={note}>{note}</li>
                  ))}
                </ul>
              </div>
              <div style={{ display: 'grid', gap: '10px' }}>
                {family.fields.map((field) => fieldCard(field))}
              </div>
            </article>
          ))}
        </div>
      </section>

      <section style={panelStyle}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <h3 style={{ margin: 0, fontSize: '18px', lineHeight: 1.2, color: '#0f172a' }}>
            {data.sectionBuilder.title}
          </h3>
          <span style={badgeStyle({ tone: 'violet' })}>Future phase</span>
        </div>
        <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
          {data.sectionBuilder.description}
        </p>
        <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.7, color: '#64748b' }}>
          {data.sectionBuilder.summary}
        </p>
      </section>
    </div>
  );
}
