/**
 * backend/src/modules/invites/admin/admin-invite.schemas.ts
 *
 * WHY:
 * - Centralizes request validation for admin invite endpoints.
 * - Prevents invalid payloads from reaching services.
 *
 * RULES:
 * - Use Zod for runtime validation.
 * - inviteIdParamSchema validates :inviteId as UUID before any DB call (Decision 8).
 *   Invalid UUID → 400, keeping malformed IDs out of the DAL entirely.
 */

import { z } from 'zod';

export const createInviteSchema = z.object({
  email: z.string().email('Invalid email address'),
  role: z.enum(['ADMIN', 'MEMBER']),
});

export type CreateInviteInput = z.infer<typeof createInviteSchema>;

export const inviteIdParamSchema = z.object({
  inviteId: z.string().uuid('inviteId must be a valid UUID'),
});

export type InviteIdParam = z.infer<typeof inviteIdParamSchema>;

/**
 * PR2: list invites pagination schema (defined here so the schema file is
 * complete from PR1; the list endpoint is wired in PR2).
 */
export const listInvitesSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  offset: z.coerce.number().int().min(0).default(0),
  status: z.enum(['PENDING', 'ACCEPTED', 'CANCELLED', 'EXPIRED']).optional(),
});

export type ListInvitesInput = z.infer<typeof listInvitesSchema>;
