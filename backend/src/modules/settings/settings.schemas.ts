/**
 * backend/src/modules/settings/settings.schemas.ts
 *
 * WHY:
 * - Centralises Zod validation for the Settings module request shapes.
 * - Keeps the first real Access mutation contract backend-owned and explicit.
 */

import { z } from 'zod';

export const acknowledgeAccessSettingsSchema = z.object({
  expectedVersion: z.number().int().positive(),
  expectedCpRevision: z.number().int().min(0),
});

export type AcknowledgeAccessSettingsInput = z.infer<typeof acknowledgeAccessSettingsSchema>;
