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
}
