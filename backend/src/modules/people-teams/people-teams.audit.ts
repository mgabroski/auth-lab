/**
 * backend/src/modules/people-teams/people-teams.audit.ts
 *
 * WHY:
 * - Typed audit helpers for People & Teams group lifecycle and membership writes.
 * - Keeps audit action names and payload shape consistent while the shared
 *   AuditWriter remains generic.
 *
 * RULES:
 * - No DB access here.
 * - No business rules.
 * - Do not log Operational Access grants because this module does not create any.
 */

import type { AuditWriter } from '../../shared/audit/audit.writer';
import type { MembershipRole, MembershipStatus } from '../memberships/membership.types';
import type { PeopleTeamGroupLevel } from './people-teams.types';

type GroupAuditSummary = {
  id: string;
  name: string;
  normalizedName: string;
  description: string | null;
  level: PeopleTeamGroupLevel;
  status: string;
};

type MemberAuditSummary = {
  groupId: string;
  membershipId: string;
  userId: string;
  email: string;
  name: string | null;
  role: MembershipRole;
  status: MembershipStatus;
};

export function auditPeopleTeamGroupCreated(
  writer: AuditWriter,
  data: { group: GroupAuditSummary; source: string },
): Promise<void> {
  return writer.append('people_teams.group_created', {
    source: data.source,
    group: data.group,
  });
}

export function auditPeopleTeamGroupUpdated(
  writer: AuditWriter,
  data: { before: GroupAuditSummary; after: GroupAuditSummary; source: string },
): Promise<void> {
  return writer.append('people_teams.group_updated', {
    source: data.source,
    before: data.before,
    after: data.after,
  });
}

export function auditPeopleTeamGroupArchived(
  writer: AuditWriter,
  data: { before: GroupAuditSummary; after: GroupAuditSummary; source: string },
): Promise<void> {
  return writer.append('people_teams.group_archived', {
    source: data.source,
    before: data.before,
    after: data.after,
  });
}

export function auditPeopleTeamMemberAdded(
  writer: AuditWriter,
  data: { member: MemberAuditSummary; source: string },
): Promise<void> {
  return writer.append('people_teams.member_added', {
    source: data.source,
    member: data.member,
  });
}

export function auditPeopleTeamMemberRemoved(
  writer: AuditWriter,
  data: { member: MemberAuditSummary; source: string },
): Promise<void> {
  return writer.append('people_teams.member_removed', {
    source: data.source,
    member: data.member,
  });
}
