/**
 * backend/src/modules/people-teams/people-teams.schemas.ts
 *
 * WHY:
 * - Centralizes query validation for the People & Teams foundation endpoints.
 *
 * RULES:
 * - This foundation exposes read-only endpoints only.
 * - Normal group lists return ACTIVE groups only. Archived groups remain
 *   persisted for audit/history and are not returned by this read surface.
 */

import { z } from 'zod';

export const peopleTeamsEmptyQuerySchema = z.object({}).strict();
