/**
 * backend/src/modules/operational-access/operational-access.schemas.ts
 *
 * WHY:
 * - Centralizes request validation for Operational Access Step 3 endpoints.
 *
 * RULES:
 * - Accept only product-defined action, Primary Where, and Which Records keys.
 * - No Oversight, Temporary Coverage, Special Access, or arbitrary expressions.
 */

import { z } from 'zod';
import {
  OPERATIONAL_ACCESS_ACTION_KEYS,
  OPERATIONAL_ACCESS_PRIMARY_WHERE_KEYS,
  OPERATIONAL_ACCESS_WHICH_RECORDS_KEYS,
} from './operational-access.types';

export const operationalAccessEmptyQuerySchema = z.object({}).strict();

export const operationalAccessGroupIdParamSchema = z
  .object({
    groupId: z.string().uuid(),
  })
  .strict();

export const saveOperationalAccessGroupGrantsSchema = z
  .object({
    grants: z
      .array(
        z
          .object({
            actionKey: z.enum(OPERATIONAL_ACCESS_ACTION_KEYS),
            primaryWhere: z.enum(OPERATIONAL_ACCESS_PRIMARY_WHERE_KEYS),
            whichRecordsKey: z.enum(OPERATIONAL_ACCESS_WHICH_RECORDS_KEYS),
          })
          .strict(),
      )
      .max(25),
  })
  .strict();

export const saveOperationalAccessResponsibleForSchema = z
  .object({
    assignments: z
      .array(
        z
          .object({
            agentMembershipId: z.string().uuid(),
            targetMembershipId: z.string().uuid(),
          })
          .strict(),
      )
      .max(500),
  })
  .strict();

export type SaveOperationalAccessGroupGrantsInput = z.infer<
  typeof saveOperationalAccessGroupGrantsSchema
>;

export type SaveOperationalAccessResponsibleForInput = z.infer<
  typeof saveOperationalAccessResponsibleForSchema
>;
