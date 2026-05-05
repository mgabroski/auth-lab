import Link from 'next/link';
import type { CSSProperties } from 'react';

import type {
  DeferredIntegrationCardResponse,
  IntegrationDisplayStatus,
  IntegrationSsoCardResponse,
  IntegrationsSettingsResponse,
} from '@/shared/settings/contracts';
import { SettingsStatusChip } from './settings-status-chip';

const pageStackStyle: CSSProperties = {
  display: 'grid',
  gap: '18px',
};

const heroCardStyle: CSSProperties = {
  display: 'grid',
  gap: '12px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -28px rgba(15, 23, 42, 0.35)',
};

const cardGridStyle: CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
  gap: '16px',
};

const cardStyle: CSSProperties = {
  display: 'grid',
  gap: '14px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -28px rgba(15, 23, 42, 0.35)',
};

const deferredCardStyle: CSSProperties = {
  ...cardStyle,
  backgroundColor: '#f8fafc',
};

const warningStyle: CSSProperties = {
  display: 'grid',
  gap: '8px',
  padding: '14px 16px',
  borderRadius: '16px',
  border: '1px solid #fed7aa',
  backgroundColor: '#fff7ed',
  color: '#9a3412',
};

const mutedTextStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#475569',
};

const eyebrowStyle: CSSProperties = {
  margin: 0,
  fontSize: '12px',
  fontWeight: 700,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: '#64748b',
};

const titleStyle: CSSProperties = {
  margin: 0,
  fontSize: '20px',
  lineHeight: 1.2,
  color: '#0f172a',
};

const smallListStyle: CSSProperties = {
  margin: 0,
  paddingLeft: '18px',
  display: 'grid',
  gap: '6px',
  fontSize: '13px',
  lineHeight: 1.6,
  color: '#475569',
};

const accessLinkStyle: CSSProperties = {
  color: '#1d4ed8',
  fontSize: '14px',
  fontWeight: 600,
  textDecoration: 'none',
};

function statusChipStyle(status: IntegrationDisplayStatus): CSSProperties {
  switch (status) {
    case 'READY':
      return {
        border: '1px solid #bbf7d0',
        backgroundColor: '#f0fdf4',
        color: '#166534',
      };
    case 'NOT_IN_USE':
      return {
        border: '1px solid #bfdbfe',
        backgroundColor: '#eff6ff',
        color: '#1d4ed8',
      };
    case 'BLOCKED':
      return {
        border: '1px solid #fed7aa',
        backgroundColor: '#fff7ed',
        color: '#9a3412',
      };
    case 'HIDDEN':
    default:
      return {
        border: '1px solid #e2e8f0',
        backgroundColor: '#f8fafc',
        color: '#475569',
      };
  }
}

function IntegrationStatusBadge({
  status,
  label,
}: {
  status: IntegrationDisplayStatus;
  label: string;
}) {
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        width: 'fit-content',
        padding: '6px 10px',
        borderRadius: '999px',
        fontSize: '12px',
        fontWeight: 700,
        ...statusChipStyle(status),
      }}
    >
      {label}
    </span>
  );
}

function SsoIntegrationCard({ integration }: { integration: IntegrationSsoCardResponse }) {
  return (
    <article style={cardStyle}>
      <div
        style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' }}
      >
        <div style={{ display: 'grid', gap: '6px' }}>
          <p style={eyebrowStyle}>Informational SSO</p>
          <h3 style={titleStyle}>{integration.title}</h3>
        </div>
        <IntegrationStatusBadge
          status={integration.displayStatus}
          label={integration.statusLabel}
        />
      </div>

      <p style={mutedTextStyle}>{integration.description}</p>

      {integration.warnings.length > 0 ? (
        <div style={warningStyle}>
          {integration.warnings.map((warning) => (
            <p key={warning} style={{ margin: 0, fontSize: '13px', lineHeight: 1.6 }}>
              {warning}
            </p>
          ))}
        </div>
      ) : null}

      <dl style={{ display: 'grid', gap: '10px', margin: 0 }}>
        <div>
          <dt style={eyebrowStyle}>Access dependency</dt>
          <dd style={{ ...mutedTextStyle, marginTop: '4px' }}>
            {integration.accessDependency.description}
          </dd>
        </div>
        <div>
          <dt style={eyebrowStyle}>Runtime readiness</dt>
          <dd style={{ ...mutedTextStyle, marginTop: '4px' }}>
            {integration.runtimeReadiness.status.replaceAll('_', ' ')} · checked{' '}
            {integration.runtimeReadiness.checkedAt}
            {integration.runtimeReadiness.detail ? ` — ${integration.runtimeReadiness.detail}` : ''}
          </dd>
        </div>
      </dl>

      {integration.resolutionHint ? (
        <p style={mutedTextStyle}>{integration.resolutionHint}</p>
      ) : null}

      <Link href="/admin/settings/access" style={accessLinkStyle}>
        Review Access &amp; Security dependency →
      </Link>

      <ul style={smallListStyle}>
        <li>No tenant credential entry in v1.</li>
        <li>No provider connection or recovery flow in v1.</li>
        <li>Status is never shown as connected.</li>
      </ul>
    </article>
  );
}

function DeferredIntegrationCard({
  integration,
}: {
  integration: DeferredIntegrationCardResponse;
}) {
  return (
    <article style={deferredCardStyle}>
      <div
        style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' }}
      >
        <div style={{ display: 'grid', gap: '6px' }}>
          <p style={eyebrowStyle}>
            {integration.category === 'HRIS' ? 'Deferred HRIS' : 'Deferred payments'}
          </p>
          <h3 style={titleStyle}>{integration.title}</h3>
        </div>
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            width: 'fit-content',
            padding: '6px 10px',
            borderRadius: '999px',
            border: '1px solid #e2e8f0',
            backgroundColor: '#ffffff',
            color: '#475569',
            fontSize: '12px',
            fontWeight: 700,
          }}
        >
          Deferred
        </span>
      </div>

      <p style={mutedTextStyle}>{integration.description}</p>
      <p style={mutedTextStyle}>{integration.reason}</p>

      {integration.capabilities.length > 0 ? (
        <ul style={smallListStyle}>
          {integration.capabilities.map((capability) => (
            <li key={capability.capabilityKey}>{capability.label} — deferred</li>
          ))}
        </ul>
      ) : null}

      <ul style={smallListStyle}>
        <li>No credential entry.</li>
        <li>No mapping editor.</li>
        <li>No import rules UI.</li>
        <li>No sync execution flow.</li>
      </ul>
    </article>
  );
}

export function IntegrationsSettingsView({ data }: { data: IntegrationsSettingsResponse }) {
  const visibleSso = data.ssoIntegrations.filter((integration) => integration.visible);

  return (
    <div style={pageStackStyle}>
      <section style={heroCardStyle}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <h2 style={titleStyle}>{data.title}</h2>
          <SettingsStatusChip status={data.status} />
        </div>
        <p style={mutedTextStyle}>{data.description}</p>
        <p style={mutedTextStyle}>
          Version {data.version} · CP revision {data.cpRevision}
        </p>
        {data.warnings.length > 0 ? (
          <div style={warningStyle}>
            {data.warnings.map((warning) => (
              <p key={warning} style={{ margin: 0, fontSize: '13px', lineHeight: 1.6 }}>
                {warning}
              </p>
            ))}
          </div>
        ) : null}
      </section>

      <section style={{ display: 'grid', gap: '12px' }}>
        <div style={{ display: 'grid', gap: '6px' }}>
          <p style={eyebrowStyle}>Live v1 informational surfaces</p>
          <h2 style={titleStyle}>SSO integration status</h2>
          <p style={mutedTextStyle}>
            Google and Microsoft SSO are shown only when CP allows their integration surface.
            Runtime readiness is read from cached auth/runtime truth only.
          </p>
        </div>

        {visibleSso.length > 0 ? (
          <div style={cardGridStyle}>
            {visibleSso.map((integration) => (
              <SsoIntegrationCard key={integration.integrationKey} integration={integration} />
            ))}
          </div>
        ) : (
          <section style={cardStyle}>
            <h3 style={titleStyle}>No SSO integrations are visible</h3>
            <p style={mutedTextStyle}>
              CP allowance currently hides Google SSO Integration and Microsoft SSO Integration for
              this tenant. Hidden integrations are not offered as setup actions in v1.
            </p>
          </section>
        )}
      </section>

      <section style={{ display: 'grid', gap: '12px' }}>
        <div style={{ display: 'grid', gap: '6px' }}>
          <p style={eyebrowStyle}>Deferred tenant configuration</p>
          <h2 style={titleStyle}>HRIS and Stripe</h2>
          <p style={mutedTextStyle}>
            These providers are conceptually present but cannot be configured by tenant admins in
            v1.
          </p>
        </div>
        <div style={cardGridStyle}>
          {data.deferredIntegrations.map((integration) => (
            <DeferredIntegrationCard key={integration.integrationKey} integration={integration} />
          ))}
        </div>
      </section>
    </div>
  );
}
