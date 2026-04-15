/**
 * backend/src/modules/control-plane/accounts/cp-accounts.schemas.ts
 *
 * WHY:
 * - Centralises Zod validation for all CP accounts HTTP surfaces.
 * - Controllers validate with these schemas before calling services.
 *
 * RULES:
 * - Zod only. No Kysely. No AppError.
 * - One schema per request shape.
 * - Inferred types are the controller ↔ service contract for input DTOs.
 *
 * ACCOUNT KEY FORMAT (locked, see CP prerequisite roadmap §11.4):
 * - lowercase letters, digits, and hyphens only
 * - matches ^[a-z0-9-]+$
 * - min 1 char, max 100 chars
 * - uniqueness enforced at the service layer (DB UNIQUE constraint + AppError)
 */

import { z } from 'zod';

export const ACCOUNT_KEY_REGEX = /^[a-z0-9-]+$/;

export const createCpAccountSchema = z.object({
  accountName: z
    .string({ required_error: 'Account name is required' })
    .min(1, 'Account name is required')
    .max(255, 'Account name must be 255 characters or fewer')
    .trim(),

  accountKey: z
    .string({ required_error: 'Account key is required' })
    .min(1, 'Account key is required')
    .max(100, 'Account key must be 100 characters or fewer')
    .regex(ACCOUNT_KEY_REGEX, 'Account key must be lowercase letters, digits, and hyphens only'),
});

export type CreateCpAccountInput = z.infer<typeof createCpAccountSchema>;
