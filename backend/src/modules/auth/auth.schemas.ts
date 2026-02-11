/**
 * backend/src/modules/auth/auth.schemas.ts
 *
 * WHY:
 * - Centralizes request validation for the Auth module.
 * - Prevents invalid payloads from reaching services.
 *
 * RULES:
 * - Use Zod for runtime validation.
 * - Password rules: 8+ chars (more rules can be added later).
 * - Email normalized to lowercase in service, not here.
 */

import { z } from 'zod';

export const registerSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  name: z.string().min(1, 'Name is required').max(200),
  inviteToken: z.string().min(20, 'Invalid invite token'),
});

export type RegisterInput = z.infer<typeof registerSchema>;

export const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
});

export type LoginInput = z.infer<typeof loginSchema>;
