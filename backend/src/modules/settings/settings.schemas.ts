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

const personalSectionFieldSchema = z.object({
  fieldKey: z.string().min(1).max(255),
  order: z.number().int().min(0).max(10_000),
});

const personalSectionSchema = z.object({
  sectionId: z.string().min(1).max(120),
  name: z.string().trim().min(1).max(120),
  order: z.number().int().min(0).max(10_000),
  fields: z.array(personalSectionFieldSchema).max(500),
});

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

export const savePersonalSettingsSchema = expectedMutationBaseSchema.extend({
  families: z
    .array(
      z.object({
        familyKey: z.string().min(1).max(255),
        reviewDecision: z.enum(['IN_USE', 'EXCLUDED']),
      }),
    )
    .max(50),
  fields: z
    .array(
      z.object({
        fieldKey: z.string().min(1).max(255),
        included: z.boolean(),
        required: z.boolean(),
        masked: z.boolean(),
      }),
    )
    .max(1000),
  sections: z.array(personalSectionSchema).max(100),
});

export type AcknowledgeAccessSettingsInput = z.infer<typeof acknowledgeAccessSettingsSchema>;
export type SaveAccountBrandingInput = z.infer<typeof saveAccountBrandingSchema>;
export type SaveAccountOrgStructureInput = z.infer<typeof saveAccountOrgStructureSchema>;
export type SaveAccountCalendarInput = z.infer<typeof saveAccountCalendarSchema>;
export type SavePersonalSettingsInput = z.infer<typeof savePersonalSettingsSchema>;
