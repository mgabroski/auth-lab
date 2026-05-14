'use client';

/**
 * frontend/src/shared/people-teams/components/people-teams-view.tsx
 *
 * WHY:
 * - Renders the first tenant-admin People & Teams management surface.
 * - Keeps this page limited to reusable groups and group membership management.
 *
 * RULES:
 * - Do not render Operational Access grants, Person Exceptions, Managed People,
 *   module action configuration, or Effective Access explanations here.
 * - Group level is classification only and does not change runtime login role.
 */

import React, { useEffect, useMemo, useState, type CSSProperties } from 'react';
import { getApiErrorMessage } from '@/shared/auth/api-errors';
import {
  addPeopleTeamGroupMember,
  archivePeopleTeamGroup,
  createPeopleTeamGroup,
  fetchPeopleTeamGroupMembersBrowser,
  fetchPeopleTeamGroupsBrowser,
  removePeopleTeamGroupMember,
  updatePeopleTeamGroup,
} from '../browser-api';
import type {
  PeopleTeamGroup,
  PeopleTeamGroupLevel,
  PeopleTeamGroupMember,
  PeopleTeamPerson,
  PeopleTeamsFoundationResponse,
} from '../contracts';

const GROUP_LEVELS: PeopleTeamGroupLevel[] = ['ADMIN', 'AGENT', 'USER'];

const pageGridStyle: CSSProperties = {
  display: 'grid',
  gap: '20px',
};

const panelStyle: CSSProperties = {
  display: 'grid',
  gap: '14px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.24)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -30px rgba(15, 23, 42, 0.4)',
};

const subtlePanelStyle: CSSProperties = {
  display: 'grid',
  gap: '10px',
  padding: '16px',
  borderRadius: '16px',
  border: '1px solid rgba(148, 163, 184, 0.24)',
  backgroundColor: '#f8fafc',
};

const rowStyle: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  gap: '12px',
  flexWrap: 'wrap',
};

const fieldGridStyle: CSSProperties = {
  display: 'grid',
  gap: '8px',
};

const inputStyle: CSSProperties = {
  width: '100%',
  boxSizing: 'border-box',
  border: '1px solid #cbd5e1',
  borderRadius: '12px',
  padding: '10px 12px',
  fontSize: '14px',
  color: '#0f172a',
  backgroundColor: '#ffffff',
};

const labelStyle: CSSProperties = {
  display: 'grid',
  gap: '6px',
  fontSize: '13px',
  fontWeight: 700,
  color: '#334155',
};

const helperTextStyle: CSSProperties = {
  margin: 0,
  color: '#475569',
  fontSize: '14px',
  lineHeight: 1.7,
};

const smallTextStyle: CSSProperties = {
  margin: 0,
  color: '#64748b',
  fontSize: '13px',
  lineHeight: 1.6,
};

const buttonStyle: CSSProperties = {
  border: 0,
  borderRadius: '12px',
  padding: '10px 14px',
  backgroundColor: '#0f172a',
  color: '#ffffff',
  fontSize: '14px',
  fontWeight: 700,
  cursor: 'pointer',
};

const secondaryButtonStyle: CSSProperties = {
  ...buttonStyle,
  border: '1px solid #cbd5e1',
  backgroundColor: '#ffffff',
  color: '#0f172a',
};

const dangerButtonStyle: CSSProperties = {
  ...buttonStyle,
  backgroundColor: '#991b1b',
};

const disabledButtonStyle: CSSProperties = {
  ...buttonStyle,
  backgroundColor: '#94a3b8',
  cursor: 'not-allowed',
};

const badgeStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  width: 'fit-content',
  borderRadius: '999px',
  padding: '4px 10px',
  backgroundColor: '#e0f2fe',
  color: '#075985',
  fontSize: '12px',
  fontWeight: 800,
  letterSpacing: '0.04em',
  textTransform: 'uppercase',
};

const errorStyle: CSSProperties = {
  margin: 0,
  padding: '12px 14px',
  borderRadius: '14px',
  border: '1px solid #fecaca',
  backgroundColor: '#fef2f2',
  color: '#991b1b',
  fontSize: '14px',
  lineHeight: 1.6,
};

const successStyle: CSSProperties = {
  margin: 0,
  padding: '12px 14px',
  borderRadius: '14px',
  border: '1px solid #bbf7d0',
  backgroundColor: '#f0fdf4',
  color: '#166534',
  fontSize: '14px',
  lineHeight: 1.6,
};

type GroupDraft = {
  name: string;
  description: string;
  level: PeopleTeamGroupLevel;
};

type FormMode = 'create' | 'edit';

type FeedbackState = {
  type: 'success' | 'error';
  message: string;
} | null;

type PeopleTeamsViewProps = {
  initialData: PeopleTeamsFoundationResponse;
};

function emptyDraft(): GroupDraft {
  return {
    name: '',
    description: '',
    level: 'AGENT',
  };
}

function draftFromGroup(group: PeopleTeamGroup): GroupDraft {
  return {
    name: group.name,
    description: group.description ?? '',
    level: group.level,
  };
}

function formatPersonLabel(person: Pick<PeopleTeamPerson, 'name' | 'email' | 'role'>): string {
  const name = person.name?.trim();
  const base = name ? `${name} — ${person.email}` : person.email;
  return `${base} (${person.role})`;
}

function levelLabel(level: PeopleTeamGroupLevel): string {
  switch (level) {
    case 'ADMIN':
      return 'Admin group';
    case 'AGENT':
      return 'Agent group';
    case 'USER':
      return 'User group';
    default: {
      const exhaustive: never = level;
      return exhaustive;
    }
  }
}

export function PeopleTeamsView({ initialData }: PeopleTeamsViewProps) {
  const [groups, setGroups] = useState<PeopleTeamGroup[]>(initialData.groups);
  const [people] = useState<PeopleTeamPerson[]>(initialData.people);
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(
    initialData.groups[0]?.id ?? null,
  );
  const [members, setMembers] = useState<PeopleTeamGroupMember[]>([]);
  const [membersLoading, setMembersLoading] = useState(false);
  const [membersError, setMembersError] = useState<string | null>(null);
  const [selectedMembershipId, setSelectedMembershipId] = useState('');
  const [formMode, setFormMode] = useState<FormMode>('create');
  const [draft, setDraft] = useState<GroupDraft>(emptyDraft);
  const [isSavingGroup, setIsSavingGroup] = useState(false);
  const [isMutatingMember, setIsMutatingMember] = useState(false);
  const [feedback, setFeedback] = useState<FeedbackState>(null);

  const selectedGroup = groups.find((group) => group.id === selectedGroupId) ?? null;
  const memberIdSet = useMemo(
    () => new Set(members.map((member) => member.membershipId)),
    [members],
  );
  const selectablePeople = people.filter((person) => !memberIdSet.has(person.membershipId));

  async function refreshGroups() {
    const result = await fetchPeopleTeamGroupsBrowser();
    if (result.ok) {
      setGroups(result.data.groups);
      if (selectedGroupId && !result.data.groups.some((group) => group.id === selectedGroupId)) {
        setSelectedGroupId(result.data.groups[0]?.id ?? null);
      }
    }
  }

  useEffect(() => {
    let cancelled = false;

    async function loadMembers(groupId: string) {
      setMembersLoading(true);
      setMembersError(null);
      const result = await fetchPeopleTeamGroupMembersBrowser(groupId);

      if (cancelled) return;

      if (result.ok) {
        setMembers(result.data.members);
      } else {
        setMembers([]);
        setMembersError(getApiErrorMessage(result.error, 'Group members could not be loaded.'));
      }

      setMembersLoading(false);
    }

    if (!selectedGroupId) {
      setMembers([]);
      setMembersError(null);
      return;
    }

    void loadMembers(selectedGroupId);

    return () => {
      cancelled = true;
    };
  }, [selectedGroupId]);

  function startCreate() {
    setFormMode('create');
    setDraft(emptyDraft());
    setFeedback(null);
  }

  function startEdit(group: PeopleTeamGroup) {
    setFormMode('edit');
    setSelectedGroupId(group.id);
    setDraft(draftFromGroup(group));
    setFeedback(null);
  }

  async function submitGroup() {
    if (!draft.name.trim()) {
      setFeedback({ type: 'error', message: 'Group name is required.' });
      return;
    }

    setIsSavingGroup(true);
    setFeedback(null);

    const payload = {
      name: draft.name.trim(),
      description: draft.description.trim() ? draft.description.trim() : null,
      level: draft.level,
    };

    const result =
      formMode === 'create'
        ? await createPeopleTeamGroup(payload)
        : selectedGroup
          ? await updatePeopleTeamGroup(selectedGroup.id, payload)
          : null;

    setIsSavingGroup(false);

    if (!result) {
      setFeedback({ type: 'error', message: 'Select a group before saving changes.' });
      return;
    }

    if (!result.ok) {
      setFeedback({
        type: 'error',
        message: getApiErrorMessage(result.error, 'The group could not be saved.'),
      });
      return;
    }

    setGroups((current) => {
      const exists = current.some((group) => group.id === result.data.group.id);
      if (exists) {
        return current.map((group) =>
          group.id === result.data.group.id ? result.data.group : group,
        );
      }

      return [...current, result.data.group].sort((a, b) => a.name.localeCompare(b.name));
    });
    setSelectedGroupId(result.data.group.id);
    setFormMode('edit');
    setDraft(draftFromGroup(result.data.group));
    setFeedback({
      type: 'success',
      message: formMode === 'create' ? 'Group created.' : 'Group updated.',
    });
  }

  async function archiveGroup(group: PeopleTeamGroup) {
    setIsSavingGroup(true);
    setFeedback(null);
    const result = await archivePeopleTeamGroup(group.id);
    setIsSavingGroup(false);

    if (!result.ok) {
      setFeedback({
        type: 'error',
        message: getApiErrorMessage(result.error, 'The group could not be archived.'),
      });
      return;
    }

    const remainingGroups = groups.filter((item) => item.id !== result.data.group.id);
    setGroups(remainingGroups);
    setSelectedGroupId((current) => {
      if (current !== result.data.group.id) return current;
      return remainingGroups[0]?.id ?? null;
    });
    setFormMode('create');
    setDraft(emptyDraft());
    setFeedback({ type: 'success', message: 'Group archived.' });
  }

  async function addSelectedMember() {
    if (!selectedGroup || !selectedMembershipId) {
      setFeedback({ type: 'error', message: 'Select a group and person before adding a member.' });
      return;
    }

    setIsMutatingMember(true);
    setFeedback(null);
    const result = await addPeopleTeamGroupMember(selectedGroup.id, {
      membershipId: selectedMembershipId,
    });
    setIsMutatingMember(false);

    if (!result.ok) {
      setFeedback({
        type: 'error',
        message: getApiErrorMessage(result.error, 'The member could not be added.'),
      });
      return;
    }

    setMembers((current) =>
      [...current, result.data.member].sort((a, b) => a.email.localeCompare(b.email)),
    );
    setSelectedMembershipId('');
    await refreshGroups();
    setFeedback({ type: 'success', message: 'Member added.' });
  }

  async function removeMember(membershipId: string) {
    if (!selectedGroup) return;

    setIsMutatingMember(true);
    setFeedback(null);
    const result = await removePeopleTeamGroupMember(selectedGroup.id, membershipId);
    setIsMutatingMember(false);

    if (!result.ok) {
      setFeedback({
        type: 'error',
        message: getApiErrorMessage(result.error, 'The member could not be removed.'),
      });
      return;
    }

    setMembers((current) => current.filter((member) => member.membershipId !== membershipId));
    await refreshGroups();
    setFeedback({ type: 'success', message: 'Member removed.' });
  }

  return (
    <div style={pageGridStyle}>
      <section style={panelStyle}>
        <div style={{ display: 'grid', gap: '8px' }}>
          <h2 style={{ margin: 0, color: '#0f172a', fontSize: '24px', lineHeight: 1.2 }}>Groups</h2>
          <p style={helperTextStyle}>
            Create reusable tenant teams and audiences. Use groups like HR Agents, IT, Branch
            Managers, or Employees instead of creating location-specific group explosions.
          </p>
          <p style={smallTextStyle}>
            Group level is classification only for now. It does not change a user&apos;s login role,
            does not grant module access, and does not configure Operational Access. Operational
            Access will be configured later.
          </p>
        </div>

        {feedback ? (
          <p
            role={feedback.type === 'error' ? 'alert' : 'status'}
            style={feedback.type === 'error' ? errorStyle : successStyle}
          >
            {feedback.message}
          </p>
        ) : null}

        <div style={{ display: 'grid', gap: '12px' }}>
          {groups.length === 0 ? (
            <section style={subtlePanelStyle}>
              <h3 style={{ margin: 0, color: '#0f172a', fontSize: '18px' }}>No groups yet</h3>
              <p style={helperTextStyle}>Create your first reusable People &amp; Teams group.</p>
            </section>
          ) : (
            groups.map((group) => (
              <article key={group.id} style={subtlePanelStyle}>
                <div style={rowStyle}>
                  <div style={{ display: 'grid', gap: '6px' }}>
                    <h3 style={{ margin: 0, color: '#0f172a', fontSize: '18px' }}>{group.name}</h3>
                    <p style={smallTextStyle}>{group.description || 'No description provided.'}</p>
                  </div>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    <span style={badgeStyle}>{levelLabel(group.level)}</span>
                    <span style={badgeStyle}>{group.status}</span>
                    <span style={badgeStyle}>{group.memberCount} members</span>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    style={secondaryButtonStyle}
                    onClick={() => setSelectedGroupId(group.id)}
                  >
                    Manage members
                  </button>
                  <button
                    type="button"
                    style={secondaryButtonStyle}
                    onClick={() => startEdit(group)}
                  >
                    Edit group
                  </button>
                  <button
                    type="button"
                    style={isSavingGroup ? disabledButtonStyle : dangerButtonStyle}
                    onClick={() => void archiveGroup(group)}
                    disabled={isSavingGroup}
                  >
                    Archive group
                  </button>
                </div>
              </article>
            ))
          )}
        </div>
      </section>

      <section style={panelStyle}>
        <div style={rowStyle}>
          <div>
            <h2 style={{ margin: 0, color: '#0f172a', fontSize: '22px', lineHeight: 1.2 }}>
              {formMode === 'create' ? 'Create group' : 'Edit group'}
            </h2>
            <p style={helperTextStyle}>
              Name the reusable team and choose its classification level.
            </p>
          </div>
          <button type="button" style={secondaryButtonStyle} onClick={startCreate}>
            New group
          </button>
        </div>

        <div style={fieldGridStyle}>
          <label style={labelStyle}>
            Group name
            <input
              aria-label="Group name"
              style={inputStyle}
              value={draft.name}
              onChange={(event) =>
                setDraft((current) => ({ ...current, name: event.target.value }))
              }
            />
          </label>
          <label style={labelStyle}>
            Description
            <textarea
              aria-label="Description"
              style={{ ...inputStyle, minHeight: '88px', resize: 'vertical' }}
              value={draft.description}
              onChange={(event) =>
                setDraft((current) => ({ ...current, description: event.target.value }))
              }
            />
          </label>
          <label style={labelStyle}>
            Level
            <select
              aria-label="Level"
              style={inputStyle}
              value={draft.level}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  level: event.target.value as PeopleTeamGroupLevel,
                }))
              }
            >
              {GROUP_LEVELS.map((level) => (
                <option key={level} value={level}>
                  {levelLabel(level)}
                </option>
              ))}
            </select>
          </label>
        </div>

        <button
          type="button"
          style={isSavingGroup ? disabledButtonStyle : buttonStyle}
          disabled={isSavingGroup}
          onClick={() => void submitGroup()}
        >
          {isSavingGroup ? 'Saving group…' : formMode === 'create' ? 'Create group' : 'Save group'}
        </button>
      </section>

      <section style={panelStyle}>
        <div style={{ display: 'grid', gap: '8px' }}>
          <h2 style={{ margin: 0, color: '#0f172a', fontSize: '22px', lineHeight: 1.2 }}>
            Members
          </h2>
          <p style={helperTextStyle}>
            Add active tenant memberships to the selected group. This does not change runtime role
            and does not grant module access.
          </p>
          {selectedGroup ? (
            <p style={smallTextStyle}>Selected group: {selectedGroup.name}</p>
          ) : null}
        </div>

        {!selectedGroup ? (
          <section style={subtlePanelStyle}>
            <p style={helperTextStyle}>Create or select a group before managing members.</p>
          </section>
        ) : (
          <>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <select
                aria-label="Person to add"
                style={{ ...inputStyle, flex: '1 1 280px' }}
                value={selectedMembershipId}
                onChange={(event) => setSelectedMembershipId(event.target.value)}
              >
                <option value="">Select an active tenant member</option>
                {selectablePeople.map((person) => (
                  <option key={person.membershipId} value={person.membershipId}>
                    {formatPersonLabel(person)}
                  </option>
                ))}
              </select>
              <button
                type="button"
                style={
                  isMutatingMember || !selectedMembershipId ? disabledButtonStyle : buttonStyle
                }
                disabled={isMutatingMember || !selectedMembershipId}
                onClick={() => void addSelectedMember()}
              >
                Add member
              </button>
            </div>

            {membersLoading ? <p style={helperTextStyle}>Loading group members…</p> : null}
            {membersError ? (
              <p role="alert" style={errorStyle}>
                {membersError}
              </p>
            ) : null}

            {!membersLoading && members.length === 0 ? (
              <section style={subtlePanelStyle}>
                <p style={helperTextStyle}>This group has no members yet.</p>
              </section>
            ) : null}

            <div style={{ display: 'grid', gap: '10px' }}>
              {members.map((member) => (
                <article key={member.membershipId} style={subtlePanelStyle}>
                  <div style={rowStyle}>
                    <div>
                      <h3 style={{ margin: 0, color: '#0f172a', fontSize: '16px' }}>
                        {member.name || member.email}
                      </h3>
                      <p style={smallTextStyle}>{member.email}</p>
                      <p style={smallTextStyle}>
                        Current membership role: {member.role}. Status: {member.status}.
                      </p>
                    </div>
                    <button
                      type="button"
                      style={isMutatingMember ? disabledButtonStyle : dangerButtonStyle}
                      disabled={isMutatingMember}
                      onClick={() => void removeMember(member.membershipId)}
                    >
                      Remove member
                    </button>
                  </div>
                </article>
              ))}
            </div>
          </>
        )}
      </section>
    </div>
  );
}
