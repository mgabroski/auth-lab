/**
 * backend/src/modules/control-plane/accounts/cp-accounts.schemas.ts
 *
 * WHY:
 * - Centralises Zod validation for CP accounts request shapes.
 * - Keeps create, Step 2 save, publish, and status-toggle payload validation in one backend-owned surface.
 *
 * RULES:
 * - Zod only.
 * - No AppError here.
 */

import { z } from 'zod';

export const ACCOUNT_KEY_REGEX = /^[a-z0-9-]+$/;

const accountKeyParamSchema = z.object({
  accountKey: z.string().min(1, 'Account key is required'),
});

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

export const saveCpAccessSchema = z.object({
  loginMethods: z.object({
    password: z.boolean(),
    google: z.boolean(),
    microsoft: z.boolean(),
  }),
  mfaPolicy: z.object({
    adminRequired: z.boolean(),
    memberRequired: z.boolean(),
  }),
  signupPolicy: z.object({
    publicSignup: z.boolean(),
    adminInvitationsAllowed: z.boolean(),
    allowedDomains: z.array(z.string().trim().min(1)).max(50),
  }),
});

export const saveCpAccountSettingsSchema = z.object({
  branding: z.object({
    logo: z.boolean(),
    menuColor: z.boolean(),
    fontColor: z.boolean(),
    welcomeMessage: z.boolean(),
  }),
  organizationStructure: z.object({
    employers: z.boolean(),
    locations: z.boolean(),
  }),
  companyCalendar: z.object({
    allowed: z.boolean(),
  }),
});

export const saveCpModuleSettingsSchema = z.object({
  modules: z.object({
    personal: z.boolean(),
    documents: z.boolean(),
    benefits: z.boolean(),
    payments: z.boolean(),
  }),
});

export const saveCpPersonalSchema = z.object({
  families: z.array(
    z.object({
      familyKey: z.enum([
        'identity',
        'contact',
        'address',
        'dependents',
        'emergency',
        'identifiers',
        'signature',
      ]),
      isAllowed: z.boolean(),
    }),
  ),
  fields: z.array(
    z.object({
      fieldKey: z.string().min(1),
      isAllowed: z.boolean(),
      defaultSelected: z.boolean(),
    }),
  ),
});

export const saveCpIntegrationsSchema = z.object({
  integrations: z.array(
    z.object({
      integrationKey: z.string().min(1),
      isAllowed: z.boolean(),
      capabilities: z.array(
        z.object({
          capabilityKey: z.string().min(1),
          isAllowed: z.boolean(),
        }),
      ),
    }),
  ),
});

export const publishCpAccountSchema = z.object({
  targetStatus: z.enum(['Active', 'Disabled']),
});

export const updateCpAccountStatusSchema = z.object({
  targetStatus: z.enum(['Active', 'Disabled']),
});

export type AccountKeyParams = z.infer<typeof accountKeyParamSchema>;
export type CreateCpAccountInput = z.infer<typeof createCpAccountSchema>;
export type SaveCpAccessInput = z.infer<typeof saveCpAccessSchema>;
export type SaveCpAccountSettingsInput = z.infer<typeof saveCpAccountSettingsSchema>;
export type SaveCpModuleSettingsInput = z.infer<typeof saveCpModuleSettingsSchema>;
export type SaveCpPersonalInput = z.infer<typeof saveCpPersonalSchema>;
export type SaveCpIntegrationsInput = z.infer<typeof saveCpIntegrationsSchema>;
export type PublishCpAccountInput = z.infer<typeof publishCpAccountSchema>;
export type UpdateCpAccountStatusInput = z.infer<typeof updateCpAccountStatusSchema>;

export { accountKeyParamSchema };
