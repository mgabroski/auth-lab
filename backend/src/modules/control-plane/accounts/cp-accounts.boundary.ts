/**
 * backend/src/modules/control-plane/accounts/cp-accounts.boundary.ts
 *
 * WHY:
 * - Keeps the CP backend route surface bounded to its dedicated host(s).
 * - Separates route existence (CP_ENABLED) from the temporary no-auth policy
 *   (CP_AUTH_MODE=none) so a missing dev flag does not masquerade as missing routes.
 * - Prevents tenant-host /api/cp/* traffic from reaching backend CP routes if a
 *   proxy or frontend shim drifts open.
 * - Preserves the locked rule that CP remains a separate internal app surface.
 *
 * RULES:
 * - Non-CP hosts must receive a generic 404 rather than a descriptive boundary
 *   error. This avoids turning tenant hosts into an oracle for hidden CP routes.
 * - Direct local host-run iteration is still allowed on localhost/127.0.0.1 so
 *   engineers can work against the backend without the full proxy topology.
 * - CP_AUTH_MODE=none is a local/CI-only bridge while real CP auth is deferred.
 * - CP_AUTH_MODE=session is fail-closed until the dedicated CP auth model ships.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';

import type { AppConfig } from '../../../app/config';
import { AppError } from '../../../shared/http/errors';

const CONTROL_PLANE_HOSTS = new Set(['cp.lvh.me', 'cp.hubins.com']);
const LOCAL_DEV_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

export function isAllowedControlPlaneHost(host: string | null): boolean {
  if (!host) return false;

  const normalizedHost = host.trim().toLowerCase();
  return CONTROL_PLANE_HOSTS.has(normalizedHost) || LOCAL_DEV_HOSTS.has(normalizedHost);
}

export function buildCpBoundaryPreHandler(config: AppConfig) {
  return function cpBoundaryPreHandler(
    req: FastifyRequest,
    _reply: FastifyReply,
    done: (err?: Error) => void,
  ) {
    const effectiveHost = req.requestContext?.host ?? null;
    if (!isAllowedControlPlaneHost(effectiveHost)) {
      done(AppError.notFound());
      return;
    }

    if (config.controlPlane.authMode === 'none') {
      done();
      return;
    }

    done(AppError.unauthorized('Control Plane authentication is not enabled yet.'));
  };
}
