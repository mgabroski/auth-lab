/**
 * backend/src/modules/invites/invite.schemas.ts
 *
 * WHY:
 * - Centralizes request validation for the Invites module.
 * - Prevents invalid payloads from reaching services.
 *
 * RULES:
 * - Use Zod for runtime validation.
 * - Never accept invite tokens in query params or URL paths (tokens leak).
 */

import { z } from 'zod';

export const acceptInviteSchema = z.object({
  token: z.string().min(20, 'Invalid invite token'),
});

export type AcceptInviteInput = z.infer<typeof acceptInviteSchema>;
