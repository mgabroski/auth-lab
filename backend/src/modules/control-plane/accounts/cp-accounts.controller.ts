/**
 * backend/src/modules/control-plane/accounts/cp-accounts.controller.ts
 *
 * WHY:
 * - Maps HTTP → service calls for the CP accounts subdomain.
 * - Validates request payloads with Zod before passing to the service.
 * - Maps service results to HTTP response shapes.
 *
 * RULES:
 * - No DB access here.
 * - No business rules here.
 * - Use Zod for request validation; throw AppError.validationError on failure.
 * - No raw tenantKey dependency — CP routes are /cp/* scoped, not tenant-scoped.
 *
 * RESPONSE SHAPES:
 * - POST   /cp/accounts          → 201 + full CpAccount DTO
 * - GET    /cp/accounts          → 200 + { accounts: CpAccountListRow[] }
 * - GET    /cp/accounts/:key     → 200 + full CpAccount DTO
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppError } from '../../../shared/http/errors';
import { createCpAccountSchema } from './cp-accounts.schemas';
import type { CpAccountsService } from './cp-accounts.service';

export class CpAccountsController {
  constructor(private readonly service: CpAccountsService) {}

  async createAccount(req: FastifyRequest, reply: FastifyReply) {
    const parsed = createCpAccountSchema.safeParse(req.body);

    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const account = await this.service.createAccount(parsed.data);

    return reply.status(201).send(account);
  }

  async getAccount(req: FastifyRequest<{ Params: { accountKey: string } }>, reply: FastifyReply) {
    const { accountKey } = req.params;

    const account = await this.service.getAccount(accountKey);

    return reply.status(200).send(account);
  }

  async listAccounts(_req: FastifyRequest, reply: FastifyReply) {
    const accounts = await this.service.listAccounts();

    return reply.status(200).send({ accounts });
  }
}
