/**
 * frontend/src/shared/people-teams/contracts.ts
 *
 * WHY:
 * - Central frontend contract layer for the People & Teams tenant-admin surface.
 * - Mirrors the backend People & Teams foundation DTOs without inventing
 *   frontend-owned permission, access-grant, or runtime-role truth.
 *
 * RULES:
 * - Group level is classification only: ADMIN / AGENT / USER.
 * - Current canonical runtime auth roles are ADMIN / AGENT / USER; MEMBER is a legacy alias.
 * - No Operational Access grants, Person Exceptions, Managed People, or
 *   Effective Access Resolver contracts belong here.
 */

import type { MembershipRole } from '@/shared/auth/contracts';

export type PeopleTeamGroupLevel = 'ADMIN' | 'AGENT' | 'USER';
export type PeopleTeamGroupStatus = 'ACTIVE' | 'ARCHIVED';
export type PeopleTeamMembershipStatus = 'ACTIVE' | 'INVITED' | 'SUSPENDED';

export type PeopleTeamGroup = {
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
  groups: PeopleTeamGroup[];
};

export type PeopleTeamGroupResponse = {
  group: PeopleTeamGroup;
};

export type PeopleTeamPerson = {
  membershipId: string;
  userId: string;
  email: string;
  name: string | null;
  role: MembershipRole;
  status: Extract<PeopleTeamMembershipStatus, 'ACTIVE'>;
};

export type PeopleTeamPeopleResponse = {
  people: PeopleTeamPerson[];
};

export type PeopleTeamGroupMember = {
  membershipId: string;
  userId: string;
  email: string;
  name: string | null;
  role: MembershipRole;
  status: PeopleTeamMembershipStatus;
  addedAt: string;
};

export type PeopleTeamGroupMembersResponse = {
  members: PeopleTeamGroupMember[];
};

export type PeopleTeamGroupMemberResponse = {
  member: PeopleTeamGroupMember;
};

export type CreatePeopleTeamGroupRequest = {
  name: string;
  description: string | null;
  level: PeopleTeamGroupLevel;
};

export type UpdatePeopleTeamGroupRequest = CreatePeopleTeamGroupRequest;

export type AddPeopleTeamGroupMemberRequest = {
  membershipId: string;
};

export type PeopleTeamsFoundationResponse = {
  groups: PeopleTeamGroup[];
  people: PeopleTeamPerson[];
};
