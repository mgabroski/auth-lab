/**
 * backend/src/modules/operational-access/operational-access.schemas.ts
 *
 * WHY:
 * - Centralizes request validation for Operational Access configuration and
 *   resolver proof endpoints.
 *
 * RULES:
 * - Accept only product-defined action, Primary Where, and Which Records keys.
 * - Advanced coverage and Special Access require explicit metadata.
 * - No arbitrary permission expressions.
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

export const operationalAccessMembershipIdParamSchema = z
  .object({
    membershipId: z.string().uuid(),
  })
  .strict();

export const saveOperationalAccessOversightSchema = z
  .object({
    expectedVersion: z.number().int().positive(),
    replaceForMembershipIds: z.array(z.string().uuid()).max(500).default([]),
    entries: z
      .array(
        z
          .object({
            overseerMembershipId: z.string().uuid(),
            targetMembershipId: z.string().uuid(),
            includesResponsiblePeople: z.boolean().default(false),
            reason: z.string().trim().min(3).max(500),
            reviewAt: z.string().datetime({ offset: true }),
          })
          .strict(),
      )
      .max(500),
  })
  .strict();

export const saveOperationalAccessTemporaryCoverageSchema = z
  .object({
    expectedVersion: z.number().int().positive(),
    replaceForMembershipIds: z.array(z.string().uuid()).max(500).default([]),
    entries: z
      .array(
        z
          .object({
            coveringMembershipId: z.string().uuid(),
            coveredMembershipId: z.string().uuid(),
            startsAt: z.string().datetime({ offset: true }),
            expiresAt: z.string().datetime({ offset: true }),
            reason: z.string().trim().min(3).max(500),
            reviewAt: z.string().datetime({ offset: true }).nullable().optional(),
          })
          .strict(),
      )
      .max(500),
  })
  .strict();

export const saveOperationalAccessSpecialAccessSchema = z
  .object({
    expectedVersion: z.number().int().positive(),
    replaceForMembershipIds: z.array(z.string().uuid()).max(500).default([]),
    entries: z
      .array(
        z
          .object({
            membershipId: z.string().uuid(),
            targetMembershipId: z.string().uuid(),
            actionKey: z.enum(OPERATIONAL_ACCESS_ACTION_KEYS),
            reason: z.string().trim().min(3).max(500),
            reviewAt: z.string().datetime({ offset: true }),
            expiresAt: z.string().datetime({ offset: true }),
          })
          .strict(),
      )
      .max(500),
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

export type SaveOperationalAccessOversightInput = z.infer<
  typeof saveOperationalAccessOversightSchema
>;

export type SaveOperationalAccessTemporaryCoverageInput = z.infer<
  typeof saveOperationalAccessTemporaryCoverageSchema
>;

export type SaveOperationalAccessSpecialAccessInput = z.infer<
  typeof saveOperationalAccessSpecialAccessSchema
>;
