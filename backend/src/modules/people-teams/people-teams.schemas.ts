/**
 * backend/src/modules/people-teams/people-teams.schemas.ts
 *
 * WHY:
 * - Centralizes request validation for the People & Teams foundation endpoints.
 *
 * RULES:
 * - Group lifecycle writes manage tenant groups only.
 * - No member add/remove, Operational Access grants, scopes, Person Exceptions,
 *   or resolver request shapes live here.
 */

import { z } from 'zod';
import { PEOPLE_TEAM_GROUP_LEVELS } from './people-teams.types';

export const peopleTeamsEmptyQuerySchema = z.object({}).strict();

export const peopleTeamsGroupIdParamSchema = z
  .object({
    groupId: z.string().uuid(),
  })
  .strict();

export const peopleTeamsGroupMemberParamSchema = z
  .object({
    groupId: z.string().uuid(),
    membershipId: z.string().uuid(),
  })
  .strict();

const groupNameSchema = z.string().trim().min(1, 'Group name is required').max(120);
const groupDescriptionSchema = z
  .string()
  .trim()
  .max(500)
  .optional()
  .nullable()
  .transform((value) => {
    if (value === undefined || value === null || value === '') return null;
    return value;
  });

export const createPeopleTeamGroupSchema = z
  .object({
    name: groupNameSchema,
    description: groupDescriptionSchema,
    level: z.enum(PEOPLE_TEAM_GROUP_LEVELS),
  })
  .strict();

export const updatePeopleTeamGroupSchema = z
  .object({
    name: groupNameSchema,
    description: groupDescriptionSchema,
    level: z.enum(PEOPLE_TEAM_GROUP_LEVELS),
  })
  .strict();

export const addPeopleTeamGroupMemberSchema = z
  .object({
    membershipId: z.string().uuid(),
  })
  .strict();

export type CreatePeopleTeamGroupInput = z.infer<typeof createPeopleTeamGroupSchema>;
export type UpdatePeopleTeamGroupInput = z.infer<typeof updatePeopleTeamGroupSchema>;
export type AddPeopleTeamGroupMemberInput = z.infer<typeof addPeopleTeamGroupMemberSchema>;
