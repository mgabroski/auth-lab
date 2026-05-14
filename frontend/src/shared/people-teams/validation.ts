/**
 * frontend/src/shared/people-teams/validation.ts
 *
 * WHY:
 * - Keeps client-side People & Teams form validation small, explicit, and unit-testable.
 * - Mirrors only lightweight UX checks; backend validation remains authoritative.
 *
 * RULES:
 * - Group level is classification only.
 * - Do not add access-grant, permission, scope, or runtime-role validation here.
 */

import type { PeopleTeamGroupLevel } from './contracts';

export const PEOPLE_TEAM_GROUP_LEVELS: readonly PeopleTeamGroupLevel[] = [
  'ADMIN',
  'AGENT',
  'USER',
] as const;

export type PeopleTeamGroupDraftValidationInput = {
  name: string;
  level: string;
};

export function validatePeopleTeamGroupDraft(
  draft: PeopleTeamGroupDraftValidationInput,
): string | null {
  if (!draft.name.trim()) {
    return 'Group name is required.';
  }

  if (!PEOPLE_TEAM_GROUP_LEVELS.includes(draft.level as PeopleTeamGroupLevel)) {
    return 'Choose a valid group level.';
  }

  return null;
}
