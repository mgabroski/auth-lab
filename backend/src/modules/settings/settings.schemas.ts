/**
 * backend/src/modules/settings/settings.schemas.ts
 *
 * WHY:
 * - Centralises Zod validation for the Settings module request shapes.
 * - Keeps the currently shipped Settings mutation contracts backend-owned and explicit.
 */

import { z } from 'zod';

const expectedMutationBaseSchema = z.object({
  expectedVersion: z.number().int().positive(),
  expectedCpRevision: z.number().int().min(0),
});

const nullableShortStringSchema = z
  .union([z.string().max(2048), z.null()])
  .transform((value) => (typeof value === 'string' ? value.trim() : null));

const multilineItemsSchema = z.array(z.string().max(255)).max(500);
const observedDatesSchema = z.array(z.string().regex(/^\d{4}-\d{2}-\d{2}$/)).max(500);

export const acknowledgeAccessSettingsSchema = expectedMutationBaseSchema;

export const saveAccountBrandingSchema = expectedMutationBaseSchema.extend({
  values: z.object({
    logoUrl: nullableShortStringSchema,
    menuColor: nullableShortStringSchema,
    fontColor: nullableShortStringSchema,
    welcomeMessage: z
      .union([z.string().max(4000), z.null()])
      .transform((value) => (typeof value === 'string' ? value.trim() : null)),
  }),
});

export const saveAccountOrgStructureSchema = expectedMutationBaseSchema.extend({
  values: z.object({
    employers: multilineItemsSchema,
    locations: multilineItemsSchema,
  }),
});

export const saveAccountCalendarSchema = expectedMutationBaseSchema.extend({
  values: z.object({
    observedDates: observedDatesSchema,
  }),
});

export type AcknowledgeAccessSettingsInput = z.infer<typeof acknowledgeAccessSettingsSchema>;
export type SaveAccountBrandingInput = z.infer<typeof saveAccountBrandingSchema>;
export type SaveAccountOrgStructureInput = z.infer<typeof saveAccountOrgStructureSchema>;
export type SaveAccountCalendarInput = z.infer<typeof saveAccountCalendarSchema>;
