/**
 * src/modules/auth/auth.routes.ts
 *
 * WHY:
 * - Declares Auth module endpoints.
 * - Keeps routing separate from controller logic.
 *
 * RULES:
 * - No business logic here.
 */

import type { FastifyInstance } from 'fastify';
import type { AuthController } from './auth.controller';

export function registerAuthRoutes(app: FastifyInstance, controller: AuthController) {
  app.post('/auth/register', controller.register.bind(controller));
  app.post('/auth/login', controller.login.bind(controller));
  app.post('/auth/forgot-password', controller.forgotPassword.bind(controller));
  app.post('/auth/reset-password', controller.resetPassword.bind(controller));

  // MFA (Brick 9)
  app.post('/auth/mfa/setup', controller.mfaSetup.bind(controller));
  app.post('/auth/mfa/verify-setup', controller.mfaVerifySetup.bind(controller));
  app.post('/auth/mfa/verify', controller.mfaVerify.bind(controller));
  app.post('/auth/mfa/recover', controller.mfaRecover.bind(controller));
}
