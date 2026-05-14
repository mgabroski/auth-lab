/**
 * backend/src/modules/people-teams/people-teams.errors.ts
 *
 * WHY:
 * - Module-scoped semantic errors for People & Teams.
 * - Keeps shared AppError free from group-specific wording and metadata.
 */

import { AppError } from '../../shared/http/errors';

export const PeopleTeamsErrors = {
  groupNotFound(groupId: string) {
    return AppError.notFound('People & Teams group not found.', { groupId });
  },

  duplicateGroupName(name: string) {
    return AppError.conflict('A People & Teams group with this name already exists.', { name });
  },

  archivedGroupReadOnly(groupId: string) {
    return AppError.conflict('Archived People & Teams groups cannot be modified.', { groupId });
  },

  membershipNotFound(membershipId: string) {
    return AppError.notFound('Tenant membership not found.', { membershipId });
  },

  inactiveMembership(membershipId: string) {
    return AppError.conflict('Only active tenant memberships can be added to a group.', {
      membershipId,
    });
  },

  duplicateGroupMember(groupId: string, membershipId: string) {
    return AppError.conflict('This tenant membership is already in the group.', {
      groupId,
      membershipId,
    });
  },

  groupMemberNotFound(groupId: string, membershipId: string) {
    return AppError.notFound('People & Teams group member not found.', {
      groupId,
      membershipId,
    });
  },
} as const;
