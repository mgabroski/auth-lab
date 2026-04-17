/**
 * backend/src/modules/control-plane/accounts/cp-accounts.controller.ts
 *
 * WHY:
 * - Maps HTTP requests to the CP accounts service layer.
 * - Validates request shapes with Zod before service execution, including
 *   the published-account status toggle surface added in Phase 5.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppError } from '../../../shared/http/errors';
import type { CpAuditRequestContext } from './cp-accounts.audit';
import {
  accountKeyParamSchema,
  createCpAccountSchema,
  publishCpAccountSchema,
  saveCpAccessSchema,
  saveCpAccountSettingsSchema,
  saveCpIntegrationsSchema,
  saveCpModuleSettingsSchema,
  saveCpPersonalSchema,
  updateCpAccountStatusSchema,
} from './cp-accounts.schemas';
import type { CpAccountsService } from './cp-accounts.service';

export class CpAccountsController {
  constructor(private readonly service: CpAccountsService) {}

  private buildAuditContext(req: FastifyRequest): CpAuditRequestContext {
    const userAgentHeader = req.headers['user-agent'];

    return {
      requestId: req.requestContext?.requestId ?? null,
      ip: req.ip ?? null,
      userAgent: typeof userAgentHeader === 'string' ? userAgentHeader : null,
    };
  }

  async createAccount(req: FastifyRequest, reply: FastifyReply) {
    const parsed = createCpAccountSchema.safeParse(req.body);

    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const account = await this.service.createAccount(parsed.data, this.buildAuditContext(req));
    return reply.status(201).send(account);
  }

  async getAccount(req: FastifyRequest<{ Params: { accountKey: string } }>, reply: FastifyReply) {
    const parsed = accountKeyParamSchema.safeParse(req.params);

    if (!parsed.success) {
      throw AppError.validationError('Invalid accountKey', { issues: parsed.error.issues });
    }

    const account = await this.service.getAccount(parsed.data.accountKey);
    return reply.status(200).send(account);
  }

  async getReview(req: FastifyRequest<{ Params: { accountKey: string } }>, reply: FastifyReply) {
    const parsed = accountKeyParamSchema.safeParse(req.params);

    if (!parsed.success) {
      throw AppError.validationError('Invalid accountKey', { issues: parsed.error.issues });
    }

    const review = await this.service.getReview(parsed.data.accountKey);
    return reply.status(200).send(review);
  }

  async listAccounts(_req: FastifyRequest, reply: FastifyReply) {
    const accounts = await this.service.listAccounts();
    return reply.status(200).send({ accounts });
  }

  async saveAccess(req: FastifyRequest<{ Params: { accountKey: string } }>, reply: FastifyReply) {
    const parsedParams = accountKeyParamSchema.safeParse(req.params);
    const parsedBody = saveCpAccessSchema.safeParse(req.body);

    if (!parsedParams.success || !parsedBody.success) {
      throw AppError.validationError('Invalid request body', {
        issues: [
          ...(parsedParams.success ? [] : parsedParams.error.issues),
          ...(parsedBody.success ? [] : parsedBody.error.issues),
        ],
      });
    }

    const account = await this.service.saveAccess(parsedParams.data.accountKey, parsedBody.data);
    return reply.status(200).send(account);
  }

  async saveAccountSettings(
    req: FastifyRequest<{ Params: { accountKey: string } }>,
    reply: FastifyReply,
  ) {
    const parsedParams = accountKeyParamSchema.safeParse(req.params);
    const parsedBody = saveCpAccountSettingsSchema.safeParse(req.body);

    if (!parsedParams.success || !parsedBody.success) {
      throw AppError.validationError('Invalid request body', {
        issues: [
          ...(parsedParams.success ? [] : parsedParams.error.issues),
          ...(parsedBody.success ? [] : parsedBody.error.issues),
        ],
      });
    }

    const account = await this.service.saveAccountSettings(
      parsedParams.data.accountKey,
      parsedBody.data,
    );
    return reply.status(200).send(account);
  }

  async saveModuleSettings(
    req: FastifyRequest<{ Params: { accountKey: string } }>,
    reply: FastifyReply,
  ) {
    const parsedParams = accountKeyParamSchema.safeParse(req.params);
    const parsedBody = saveCpModuleSettingsSchema.safeParse(req.body);

    if (!parsedParams.success || !parsedBody.success) {
      throw AppError.validationError('Invalid request body', {
        issues: [
          ...(parsedParams.success ? [] : parsedParams.error.issues),
          ...(parsedBody.success ? [] : parsedBody.error.issues),
        ],
      });
    }

    const account = await this.service.saveModuleSettings(
      parsedParams.data.accountKey,
      parsedBody.data,
    );
    return reply.status(200).send(account);
  }

  async savePersonal(req: FastifyRequest<{ Params: { accountKey: string } }>, reply: FastifyReply) {
    const parsedParams = accountKeyParamSchema.safeParse(req.params);
    const parsedBody = saveCpPersonalSchema.safeParse(req.body);

    if (!parsedParams.success || !parsedBody.success) {
      throw AppError.validationError('Invalid request body', {
        issues: [
          ...(parsedParams.success ? [] : parsedParams.error.issues),
          ...(parsedBody.success ? [] : parsedBody.error.issues),
        ],
      });
    }

    const account = await this.service.savePersonal(parsedParams.data.accountKey, parsedBody.data);
    return reply.status(200).send(account);
  }

  async saveIntegrations(
    req: FastifyRequest<{ Params: { accountKey: string } }>,
    reply: FastifyReply,
  ) {
    const parsedParams = accountKeyParamSchema.safeParse(req.params);
    const parsedBody = saveCpIntegrationsSchema.safeParse(req.body);

    if (!parsedParams.success || !parsedBody.success) {
      throw AppError.validationError('Invalid request body', {
        issues: [
          ...(parsedParams.success ? [] : parsedParams.error.issues),
          ...(parsedBody.success ? [] : parsedBody.error.issues),
        ],
      });
    }

    const account = await this.service.saveIntegrations(
      parsedParams.data.accountKey,
      parsedBody.data,
    );
    return reply.status(200).send(account);
  }

  async updateStatus(req: FastifyRequest<{ Params: { accountKey: string } }>, reply: FastifyReply) {
    const parsedParams = accountKeyParamSchema.safeParse(req.params);
    const parsedBody = updateCpAccountStatusSchema.safeParse(req.body);

    if (!parsedParams.success || !parsedBody.success) {
      throw AppError.validationError('Invalid request body', {
        issues: [
          ...(parsedParams.success ? [] : parsedParams.error.issues),
          ...(parsedBody.success ? [] : parsedBody.error.issues),
        ],
      });
    }

    const account = await this.service.updateStatus(
      parsedParams.data.accountKey,
      parsedBody.data,
      this.buildAuditContext(req),
    );
    return reply.status(200).send(account);
  }

  async publishAccount(
    req: FastifyRequest<{ Params: { accountKey: string } }>,
    reply: FastifyReply,
  ) {
    const parsedParams = accountKeyParamSchema.safeParse(req.params);
    const parsedBody = publishCpAccountSchema.safeParse(req.body);

    if (!parsedParams.success || !parsedBody.success) {
      throw AppError.validationError('Invalid request body', {
        issues: [
          ...(parsedParams.success ? [] : parsedParams.error.issues),
          ...(parsedBody.success ? [] : parsedBody.error.issues),
        ],
      });
    }

    const review = await this.service.publishAccount(
      parsedParams.data.accountKey,
      parsedBody.data,
      this.buildAuditContext(req),
    );
    return reply.status(200).send(review);
  }
}
