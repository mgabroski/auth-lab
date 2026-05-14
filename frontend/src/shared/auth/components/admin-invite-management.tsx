'use client';

/**
 * frontend/src/shared/auth/components/admin-invite-management.tsx
 *
 * WHY:
 * - Implements the browser-side admin invite management surface.
 * - Uses the real admin invite backend endpoints through the same-origin browser API wrapper.
 * - Wires Admin / Agent / User provisioning language to the canonical backend invite contract.
 *
 * RULES:
 * - This component is client-only because it reacts to admin actions after hydration.
 * - Access control is not decided here; the server page must gate entry with loadAuthBootstrap().
 * - Invite statuses and levels shown here come from backend truth, normalized at the API boundary.
 * - Agent group selection is provisioning-only. It does not grant Operational Access.
 */

import Link from 'next/link';
import React, {
  useEffect,
  useMemo,
  useState,
  type ChangeEvent,
  type CSSProperties,
  type FormEvent,
} from 'react';
import {
  cancelAdminInvite,
  createAdminInvite,
  listAdminInvites,
  resendAdminInvite,
} from '@/shared/auth/browser-api';
import type {
  CreateAdminInviteRequest,
  InviteRole,
  InviteRoleInput,
  InviteStatus,
  InviteSummary,
  ListAdminInvitesResponse,
} from '@/shared/auth/contracts';
import { normalizeMembershipRole } from '@/shared/auth/contracts';
import { fetchPeopleTeamGroupsBrowser } from '@/shared/people-teams/browser-api';
import type { PeopleTeamGroup } from '@/shared/people-teams/contracts';
import { AuthErrorBanner } from './auth-error-banner';
import {
  AuthNote,
  FormField,
  FormRow,
  FormStack,
  SecondaryButton,
  SubmitButton,
  TextInput,
} from './auth-form-ui';
import { AuthSuccessBanner } from './auth-success-banner';

const _jsxRuntimeReact = React;

const PEOPLE_TEAMS_ROUTE = '/admin/settings/people-teams';
const PAGE_SIZE = 20;

const cardStyle: CSSProperties = {
  borderRadius: '18px',
  border: '1px solid rgba(148, 163, 184, 0.22)',
  backgroundColor: '#ffffff',
  padding: '20px',
  display: 'grid',
  gap: '16px',
};

const sectionHeaderStyle: CSSProperties = { display: 'grid', gap: '6px' };
const sectionTitleStyle: CSSProperties = {
  margin: 0,
  fontSize: '20px',
  lineHeight: 1.2,
  fontWeight: 700,
};
const sectionDescriptionStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.6,
  color: '#475569',
};
const formGridStyle: CSSProperties = {
  display: 'grid',
  gap: '14px',
  gridTemplateColumns: 'minmax(0, 2fr) minmax(180px, 1fr)',
};
const selectStyle: CSSProperties = {
  width: '100%',
  minHeight: '46px',
  borderRadius: '12px',
  border: '1px solid rgba(148, 163, 184, 0.45)',
  backgroundColor: '#ffffff',
  color: '#0f172a',
  padding: '12px 14px',
  fontSize: '14px',
  lineHeight: 1.4,
  outline: 'none',
  boxSizing: 'border-box',
};
const controlsRowStyle: CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'flex-end',
  gap: '16px',
  flexWrap: 'wrap',
};
const inviteListStyle: CSSProperties = { display: 'grid', gap: '12px' };
const inviteCardStyle: CSSProperties = {
  borderRadius: '16px',
  border: '1px solid rgba(148, 163, 184, 0.22)',
  backgroundColor: 'rgba(248, 250, 252, 0.9)',
  padding: '16px',
  display: 'grid',
  gap: '14px',
};
const inviteHeaderStyle: CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'flex-start',
  gap: '12px',
  flexWrap: 'wrap',
};
const inviteEmailStyle: CSSProperties = {
  margin: 0,
  fontSize: '16px',
  lineHeight: 1.4,
  fontWeight: 700,
  color: '#0f172a',
  wordBreak: 'break-word',
};
const inviteMetaStyle: CSSProperties = {
  margin: 0,
  fontSize: '13px',
  lineHeight: 1.6,
  color: '#64748b',
};
const detailGridStyle: CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
  gap: '12px',
};
const detailLabelStyle: CSSProperties = {
  margin: 0,
  fontSize: '12px',
  fontWeight: 700,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: '#64748b',
};
const detailValueStyle: CSSProperties = {
  margin: '4px 0 0',
  fontSize: '14px',
  lineHeight: 1.5,
  color: '#0f172a',
};
const buttonRowStyle: CSSProperties = { display: 'flex', gap: '10px', flexWrap: 'wrap' };
const paginationRowStyle: CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  gap: '12px',
  flexWrap: 'wrap',
};
const helperTextStyle: CSSProperties = {
  margin: 0,
  fontSize: '13px',
  lineHeight: 1.6,
  color: '#475569',
};
const selectorCardStyle: CSSProperties = {
  borderRadius: '16px',
  border: '1px solid rgba(14, 165, 233, 0.22)',
  backgroundColor: 'rgba(240, 249, 255, 0.72)',
  padding: '16px',
  display: 'grid',
  gap: '12px',
};
const checkboxListStyle: CSSProperties = { display: 'grid', gap: '8px' };
const checkboxItemStyle: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: '10px',
  fontSize: '14px',
  lineHeight: 1.5,
  color: '#0f172a',
};
const linkStyle: CSSProperties = { color: '#0f172a', fontWeight: 700 };

const statusPillStyles: Record<InviteStatus, CSSProperties> = {
  PENDING: {
    border: '1px solid rgba(14, 165, 233, 0.28)',
    backgroundColor: 'rgba(224, 242, 254, 0.9)',
    color: '#0c4a6e',
  },
  ACCEPTED: {
    border: '1px solid rgba(16, 185, 129, 0.24)',
    backgroundColor: 'rgba(236, 253, 245, 0.98)',
    color: '#065f46',
  },
  CANCELLED: {
    border: '1px solid rgba(148, 163, 184, 0.3)',
    backgroundColor: 'rgba(241, 245, 249, 0.95)',
    color: '#334155',
  },
  EXPIRED: {
    border: '1px solid rgba(245, 158, 11, 0.28)',
    backgroundColor: 'rgba(255, 251, 235, 0.96)',
    color: '#92400e',
  },
};

const statusPillBaseStyle: CSSProperties = {
  borderRadius: '999px',
  padding: '6px 10px',
  fontSize: '12px',
  fontWeight: 700,
  letterSpacing: '0.04em',
  textTransform: 'uppercase',
};

export const INVITE_LEVEL_OPTIONS: ReadonlyArray<{ value: InviteRole; label: string }> = [
  { value: 'USER', label: 'User' },
  { value: 'AGENT', label: 'Agent' },
  { value: 'ADMIN', label: 'Admin' },
];

export type InviteFilterValue = 'ALL' | InviteStatus;
export type InviteDraft = { email: string; level: InviteRole; selectedAgentGroupIds: string[] };

type InviteListState = { loading: boolean; error: unknown; data: ListAdminInvitesResponse | null };
type AgentGroupsState = { loading: boolean; error: unknown; groups: PeopleTeamGroup[] };

function formatDateTime(value: string | null): string {
  if (!value) return 'Not available';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    date,
  );
}

function getVisibleRange(data: ListAdminInvitesResponse | null): string {
  if (!data || data.total === 0 || data.invites.length === 0) return 'Showing 0 invites';
  return `Showing ${data.offset + 1}-${data.offset + data.invites.length} of ${data.total} invites`;
}

function getEmptyStateCopy(filter: InviteFilterValue): string {
  return filter === 'ALL'
    ? 'No invites exist for this workspace yet.'
    : `No ${filter.toLowerCase()} invites match this filter right now.`;
}

function getInviteStatusDetail(invite: InviteSummary): string {
  switch (invite.status) {
    case 'PENDING':
      return 'Waiting for the recipient to accept the invitation.';
    case 'ACCEPTED':
      return invite.usedAt
        ? `Accepted ${formatDateTime(invite.usedAt)}.`
        : 'Accepted by the invited user.';
    case 'CANCELLED':
      return 'Cancelled by an admin action or replaced during resend.';
    case 'EXPIRED':
      return 'This invitation is no longer valid and cannot be used.';
    default: {
      const exhaustiveCheck: never = invite.status;
      return String(exhaustiveCheck);
    }
  }
}

function canResendInvite(invite: InviteSummary): boolean {
  return invite.status === 'PENDING';
}

function canCancelInvite(invite: InviteSummary): boolean {
  return invite.status === 'PENDING';
}

export function getInviteLevelLabel(level: InviteRoleInput): string {
  const normalized = normalizeMembershipRole(level);
  switch (normalized) {
    case 'USER':
      return 'User';
    case 'AGENT':
      return 'Agent';
    case 'ADMIN':
      return 'Admin';
    default: {
      const exhaustiveCheck: never = normalized;
      return String(exhaustiveCheck);
    }
  }
}

export function isSelectableAgentGroup(group: PeopleTeamGroup): boolean {
  return group.level === 'AGENT' && group.status === 'ACTIVE';
}

export function getSelectableAgentGroups(groups: readonly PeopleTeamGroup[]): PeopleTeamGroup[] {
  return groups.filter(isSelectableAgentGroup);
}

export function shouldShowAgentGroupSelector(level: InviteRole): boolean {
  return level === 'AGENT';
}

export function validateInviteDraft(draft: InviteDraft): string | null {
  if (draft.level === 'AGENT' && draft.selectedAgentGroupIds.length === 0) {
    return 'Select at least one active Agent group before inviting an Agent.';
  }
  return null;
}

export function getSelectedAgentGroupIdsForLevel(
  nextLevel: InviteRole,
  selectedAgentGroupIds: readonly string[],
): string[] {
  return nextLevel === 'AGENT' ? [...selectedAgentGroupIds] : [];
}

export function buildCreateInviteRequest(draft: InviteDraft): CreateAdminInviteRequest {
  if (draft.level !== 'AGENT') return { email: draft.email, role: draft.level };
  return { email: draft.email, role: 'AGENT', agentGroupIds: draft.selectedAgentGroupIds };
}

type AgentGroupSelectorProps = {
  loading: boolean;
  error: unknown;
  groups: PeopleTeamGroup[];
  selectedGroupIds: string[];
  disabled: boolean;
  onToggleGroup: (groupId: string) => void;
};

export function AdminInviteAgentGroupSelector({
  loading,
  error,
  groups,
  selectedGroupIds,
  disabled,
  onToggleGroup,
}: AgentGroupSelectorProps) {
  const selectableGroups = getSelectableAgentGroups(groups);
  const selectedGroups = selectableGroups.filter((group) => selectedGroupIds.includes(group.id));

  return (
    <div style={selectorCardStyle}>
      <div style={sectionHeaderStyle}>
        <p style={{ ...detailLabelStyle, color: '#0369a1' }}>Agent groups</p>
        <p style={helperTextStyle}>
          Agent invite group selection records provisioning context only. It does not grant
          Operational Access.
        </p>
      </div>

      {loading ? <AuthNote>Loading active Agent groups from People &amp; Teams…</AuthNote> : null}
      {error ? (
        <AuthErrorBanner error={error} fallbackMessage="Unable to load Agent groups." />
      ) : null}

      {!loading && !error && selectableGroups.length === 0 ? (
        <AuthNote>
          Create an active Agent group in People &amp; Teams before inviting an Agent.{' '}
          <Link href={PEOPLE_TEAMS_ROUTE} style={linkStyle}>
            Open People &amp; Teams
          </Link>
        </AuthNote>
      ) : null}

      {!loading && !error && selectableGroups.length > 0 ? (
        <div style={checkboxListStyle}>
          {selectableGroups.map((group) => (
            <label key={group.id} style={checkboxItemStyle}>
              <input
                type="checkbox"
                checked={selectedGroupIds.includes(group.id)}
                disabled={disabled}
                onChange={() => onToggleGroup(group.id)}
              />
              <span>{group.name}</span>
            </label>
          ))}
        </div>
      ) : null}

      {selectedGroups.length > 0 ? (
        <p style={helperTextStyle}>
          <strong>Selected Agent groups:</strong>{' '}
          {selectedGroups.map((group) => group.name).join(', ')}
        </p>
      ) : null}
    </div>
  );
}

function getAgentGroupSummary(invite: InviteSummary): string {
  if (invite.role !== 'AGENT') return 'Not applicable';
  const groups = invite.agentGroups ?? [];
  if (groups.length === 0) return 'No Agent groups returned';
  return `${groups.map((group) => group.name).join(', ')} (provisioning context only)`;
}

export function AdminInviteManagement() {
  const [email, setEmail] = useState('');
  const [level, setLevel] = useState<InviteRole>('USER');
  const [selectedAgentGroupIds, setSelectedAgentGroupIds] = useState<string[]>([]);
  const [filter, setFilter] = useState<InviteFilterValue>('ALL');
  const [offset, setOffset] = useState(0);
  const [reloadToken, setReloadToken] = useState(0);
  const [createPending, setCreatePending] = useState(false);
  const [createError, setCreateError] = useState<unknown>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [listState, setListState] = useState<InviteListState>({
    loading: true,
    error: null,
    data: null,
  });
  const [agentGroupsState, setAgentGroupsState] = useState<AgentGroupsState>({
    loading: true,
    error: null,
    groups: [],
  });
  const [resendingInviteId, setResendingInviteId] = useState<string | null>(null);
  const [cancellingInviteId, setCancellingInviteId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  const selectableAgentGroups = useMemo(
    () => getSelectableAgentGroups(agentGroupsState.groups),
    [agentGroupsState.groups],
  );

  useEffect(() => {
    let isActive = true;
    const loadInvites = async (): Promise<void> => {
      setListState((current) => ({ loading: true, error: null, data: current.data }));
      const result = await listAdminInvites({
        limit: PAGE_SIZE,
        offset,
        status: filter === 'ALL' ? undefined : filter,
      });
      if (!isActive) return;
      if (!result.ok) {
        setListState({ loading: false, error: result.error, data: null });
        return;
      }
      setListState({ loading: false, error: null, data: result.data });
    };
    void loadInvites();
    return () => {
      isActive = false;
    };
  }, [filter, offset, reloadToken]);

  useEffect(() => {
    let isActive = true;
    const loadGroups = async (): Promise<void> => {
      setAgentGroupsState((current) => ({ ...current, loading: true, error: null }));
      const result = await fetchPeopleTeamGroupsBrowser();
      if (!isActive) return;
      if (!result.ok) {
        setAgentGroupsState({ loading: false, error: result.error, groups: [] });
        return;
      }
      setAgentGroupsState({ loading: false, error: null, groups: result.data.groups });
    };
    void loadGroups();
    return () => {
      isActive = false;
    };
  }, []);

  const handleCreateInvite = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    setCreatePending(true);
    setCreateError(null);
    setActionError(null);
    setSuccessMessage(null);

    const draft: InviteDraft = { email, level, selectedAgentGroupIds };
    const validationMessage = validateInviteDraft(draft);
    if (validationMessage) {
      setCreateError(validationMessage);
      setCreatePending(false);
      return;
    }

    const result = await createAdminInvite(buildCreateInviteRequest(draft));
    if (!result.ok) {
      setCreateError(result.error);
      setCreatePending(false);
      return;
    }

    setEmail('');
    setLevel('USER');
    setSelectedAgentGroupIds([]);
    if (filter !== 'ALL' && filter !== 'PENDING') setFilter('PENDING');
    setOffset(0);
    setReloadToken((value) => value + 1);
    setSuccessMessage(`Invite created for ${result.data.invite.email}.`);
    setCreatePending(false);
  };

  const handleRefresh = (): void => {
    setActionError(null);
    setSuccessMessage(null);
    setReloadToken((value) => value + 1);
  };

  const handleFilterChange = (event: ChangeEvent<HTMLSelectElement>): void => {
    setFilter(event.target.value as InviteFilterValue);
    setOffset(0);
    setActionError(null);
    setSuccessMessage(null);
  };

  const handleLevelChange = (event: ChangeEvent<HTMLSelectElement>): void => {
    const nextLevel = event.target.value as InviteRole;
    setLevel(nextLevel);
    setCreateError(null);
    setSelectedAgentGroupIds((current) => getSelectedAgentGroupIdsForLevel(nextLevel, current));
  };

  const handleToggleAgentGroup = (groupId: string): void => {
    if (!selectableAgentGroups.some((group) => group.id === groupId)) return;
    setSelectedAgentGroupIds((current) =>
      current.includes(groupId) ? current.filter((id) => id !== groupId) : [...current, groupId],
    );
  };

  const handleResendInvite = async (invite: InviteSummary): Promise<void> => {
    setResendingInviteId(invite.id);
    setActionError(null);
    setCreateError(null);
    setSuccessMessage(null);
    const result = await resendAdminInvite(invite.id);
    if (!result.ok) {
      setActionError(result.error);
      setResendingInviteId(null);
      return;
    }
    if (filter !== 'ALL' && filter !== 'PENDING') setFilter('PENDING');
    setOffset(0);
    setReloadToken((value) => value + 1);
    setSuccessMessage(
      `Invite resent to ${result.data.invite.email}. The previous link has been replaced with a new one.`,
    );
    setResendingInviteId(null);
  };

  const handleCancelInvite = async (invite: InviteSummary): Promise<void> => {
    setCancellingInviteId(invite.id);
    setActionError(null);
    setCreateError(null);
    setSuccessMessage(null);
    const result = await cancelAdminInvite(invite.id);
    if (!result.ok) {
      setActionError(result.error);
      setCancellingInviteId(null);
      return;
    }
    const nextOffset =
      listState.data && listState.data.invites.length === 1 && offset > 0
        ? Math.max(0, offset - PAGE_SIZE)
        : offset;
    setOffset(nextOffset);
    setReloadToken((value) => value + 1);
    setSuccessMessage(`Invite for ${invite.email} cancelled.`);
    setCancellingInviteId(null);
  };

  const listData = listState.data;
  const hasPreviousPage = offset > 0;
  const hasNextPage = listData ? offset + listData.invites.length < listData.total : false;
  const disableAgentSubmit =
    level === 'AGENT' && (agentGroupsState.loading || selectableAgentGroups.length === 0);

  return (
    <div style={{ display: 'grid', gap: '20px' }}>
      <section style={cardStyle}>
        <div style={sectionHeaderStyle}>
          <h2 style={sectionTitleStyle}>Create invite</h2>
          <p style={sectionDescriptionStyle}>
            Send a new workspace invitation with the real backend contract. Admin invites require
            MFA after acceptance; User and Agent invites continue into the shared workspace shell.
          </p>
        </div>

        <AuthNote>
          Invite rules are backend-owned: invites expire after 7 days, each link is one-time use,
          and resending replaces the previous link. Agent group selection is provisioning-only and
          does not grant Operational Access.
        </AuthNote>

        <AuthSuccessBanner title="Invite updated" message={successMessage} />
        <AuthErrorBanner error={createError} fallbackMessage="Unable to create invite." />
        <AuthErrorBanner error={actionError} fallbackMessage="Unable to update invite." />

        <form onSubmit={(event) => void handleCreateInvite(event)}>
          <FormStack>
            <div style={formGridStyle}>
              <FormField
                label="Invitee email"
                htmlFor="admin-invite-email"
                hint="The backend applies tenant email-domain rules and duplicate-pending checks."
              >
                <TextInput
                  id="admin-invite-email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  inputMode="email"
                  placeholder="new-user@company.com"
                  value={email}
                  disabled={createPending}
                  onChange={(event: ChangeEvent<HTMLInputElement>) => setEmail(event.target.value)}
                  required
                />
              </FormField>

              <FormField label="Level" htmlFor="admin-invite-level">
                <select
                  id="admin-invite-level"
                  name="level"
                  value={level}
                  disabled={createPending}
                  onChange={handleLevelChange}
                  style={selectStyle}
                >
                  {INVITE_LEVEL_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </FormField>
            </div>

            {shouldShowAgentGroupSelector(level) ? (
              <AdminInviteAgentGroupSelector
                loading={agentGroupsState.loading}
                error={agentGroupsState.error}
                groups={agentGroupsState.groups}
                selectedGroupIds={selectedAgentGroupIds}
                disabled={createPending}
                onToggleGroup={handleToggleAgentGroup}
              />
            ) : null}

            <SubmitButton disabled={createPending || disableAgentSubmit}>
              {createPending ? 'Creating invite…' : 'Create invite'}
            </SubmitButton>
          </FormStack>
        </form>
      </section>

      <section style={cardStyle}>
        <div style={controlsRowStyle}>
          <div style={sectionHeaderStyle}>
            <h2 style={sectionTitleStyle}>Existing invites</h2>
            <p style={sectionDescriptionStyle}>
              Review tenant-scoped invite status, resend pending invites, or cancel them.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
            <FormField label="Status filter" htmlFor="admin-invite-filter">
              <select
                id="admin-invite-filter"
                name="status"
                value={filter}
                disabled={listState.loading}
                onChange={handleFilterChange}
                style={{ ...selectStyle, minWidth: '180px' }}
              >
                <option value="ALL">All statuses</option>
                <option value="PENDING">Pending</option>
                <option value="ACCEPTED">Accepted</option>
                <option value="CANCELLED">Cancelled</option>
                <option value="EXPIRED">Expired</option>
              </select>
            </FormField>

            <SecondaryButton disabled={listState.loading} onClick={handleRefresh}>
              {listState.loading ? 'Refreshing…' : 'Refresh list'}
            </SecondaryButton>
          </div>
        </div>

        <p style={helperTextStyle}>{getVisibleRange(listData)}</p>
        {listState.loading && !listData ? (
          <AuthNote>Loading invites from the workspace admin endpoints…</AuthNote>
        ) : null}
        {listState.error ? (
          <AuthErrorBanner error={listState.error} fallbackMessage="Unable to load invites." />
        ) : null}
        {!listState.loading && !listState.error && listData && listData.invites.length === 0 ? (
          <AuthNote>{getEmptyStateCopy(filter)}</AuthNote>
        ) : null}

        {!listState.error && listData && listData.invites.length > 0 ? (
          <div style={inviteListStyle}>
            {listData.invites.map((invite) => {
              const resendPending = resendingInviteId === invite.id;
              const cancelPending = cancellingInviteId === invite.id;
              const busy = resendPending || cancelPending;
              return (
                <article key={invite.id} style={inviteCardStyle}>
                  <div style={inviteHeaderStyle}>
                    <div style={{ display: 'grid', gap: '4px' }}>
                      <p style={inviteEmailStyle}>{invite.email}</p>
                      <p style={inviteMetaStyle}>{getInviteStatusDetail(invite)}</p>
                    </div>
                    <span style={{ ...statusPillBaseStyle, ...statusPillStyles[invite.status] }}>
                      {invite.status}
                    </span>
                  </div>

                  <div style={detailGridStyle}>
                    <div>
                      <p style={detailLabelStyle}>Level</p>
                      <p style={detailValueStyle}>{getInviteLevelLabel(invite.role)}</p>
                    </div>
                    <div>
                      <p style={detailLabelStyle}>Agent groups</p>
                      <p style={detailValueStyle}>{getAgentGroupSummary(invite)}</p>
                    </div>
                    <div>
                      <p style={detailLabelStyle}>Created</p>
                      <p style={detailValueStyle}>{formatDateTime(invite.createdAt)}</p>
                    </div>
                    <div>
                      <p style={detailLabelStyle}>Expires</p>
                      <p style={detailValueStyle}>{formatDateTime(invite.expiresAt)}</p>
                    </div>
                    <div>
                      <p style={detailLabelStyle}>Accepted at</p>
                      <p style={detailValueStyle}>
                        {invite.usedAt ? formatDateTime(invite.usedAt) : 'Not accepted'}
                      </p>
                    </div>
                  </div>

                  <div style={buttonRowStyle}>
                    {canResendInvite(invite) ? (
                      <SecondaryButton
                        disabled={busy}
                        onClick={() => {
                          void handleResendInvite(invite);
                        }}
                      >
                        {resendPending ? 'Resending…' : 'Resend invite'}
                      </SecondaryButton>
                    ) : null}
                    {canCancelInvite(invite) ? (
                      <SecondaryButton
                        disabled={busy}
                        onClick={() => {
                          void handleCancelInvite(invite);
                        }}
                      >
                        {cancelPending ? 'Cancelling…' : 'Cancel invite'}
                      </SecondaryButton>
                    ) : null}
                  </div>
                </article>
              );
            })}
          </div>
        ) : null}

        <div style={paginationRowStyle}>
          <p style={helperTextStyle}>
            Pending invites can be resent or cancelled. Accepted, cancelled, and expired invites are
            shown as read-only history.
          </p>
          <FormRow
            left={
              <SecondaryButton
                disabled={!hasPreviousPage || listState.loading}
                onClick={() => setOffset((current) => Math.max(0, current - PAGE_SIZE))}
              >
                Previous page
              </SecondaryButton>
            }
            right={
              <SecondaryButton
                disabled={!hasNextPage || listState.loading}
                onClick={() => setOffset((current) => current + PAGE_SIZE)}
              >
                Next page
              </SecondaryButton>
            }
          />
        </div>
      </section>
    </div>
  );
}
