/**
 * backend/src/modules/people-teams/people-teams.types.ts
 *
 * WHY:
 * - Defines the backend-owned DTO and domain vocabulary for the People & Teams
 *   foundation.
 * - Group level is classification only. It does not mutate canonical
 *   ADMIN/AGENT/USER runtime membership roles.
 *
 * RULES:
 * - Pure types/constants only.
 * - No Operational Access grants, scopes, Person Exceptions, or resolver types.
 */

import type { MembershipRole, MembershipStatus } from '../memberships/membership.types';

export const PEOPLE_TEAM_GROUP_LEVELS = ['ADMIN', 'AGENT', 'USER'] as const;
export type PeopleTeamGroupLevel = (typeof PEOPLE_TEAM_GROUP_LEVELS)[number];

export const PEOPLE_TEAM_GROUP_STATUSES = ['ACTIVE', 'ARCHIVED'] as const;
export type PeopleTeamGroupStatus = (typeof PEOPLE_TEAM_GROUP_STATUSES)[number];

export type PeopleTeamAuditContext = {
  requestId: string | null;
  ip: string | null;
  userAgent: string | null;
  tenantId: string;
  userId: string;
  membershipId: string;
};

export type PeopleTeamGroupDto = {
  id: string;
  name: string;
  normalizedName: string;
  description: string | null;
  level: PeopleTeamGroupLevel;
  status: PeopleTeamGroupStatus;
  memberCount: number;
  createdAt: string;
  updatedAt: string;
  archivedAt: string | null;
};

export type PeopleTeamGroupsResponse = {
  groups: PeopleTeamGroupDto[];
};

export type PeopleTeamGroupResponse = {
  group: PeopleTeamGroupDto;
};

export type PeopleTeamGroupMemberDto = {
  membershipId: string;
  userId: string;
  email: string;
  name: string | null;
  role: MembershipRole;
  status: MembershipStatus;
  addedAt: string;
};

export type PeopleTeamGroupMembersResponse = {
  members: PeopleTeamGroupMemberDto[];
};

export type PeopleTeamGroupMemberResponse = {
  member: PeopleTeamGroupMemberDto;
};

export type PeopleTeamPersonDto = {
  membershipId: string;
  userId: string;
  email: string;
  name: string | null;
  role: MembershipRole;
  status: Extract<MembershipStatus, 'ACTIVE'>;
};

export type PeopleTeamPeopleResponse = {
  people: PeopleTeamPersonDto[];
};
