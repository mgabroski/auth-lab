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
} as const;
