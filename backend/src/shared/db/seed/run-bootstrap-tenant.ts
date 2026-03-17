/**
 * backend/src/shared/db/seed/run-bootstrap-tenant.ts
 *
 * WHY:
 * - Provides an explicit operator-safe tenant bootstrap entry point for
 *   QA/staging/production-like environments.
 * - Queues the bootstrap ADMIN invite through the normal outbox path without
 *   local-only raw token logging.
 *
 * RULES:
 * - This command is explicit. It must not run automatically on app startup.
 * - It may run in production because bootstrap is currently an operator flow,
 *   not a public self-serve flow.
 * - It must never print or log the raw invite token.
 */

import { buildConfig } from '../../../app/config';
import { buildDeps } from '../../../app/di';
import { logger } from '../../logger/logger';
import { runTenantBootstrap } from './bootstrap-tenant';

type BootstrapCliArgs = {
  tenantKey: string;
  tenantName: string;
  adminEmail: string;
  inviteTtlHours: number;
};

function readFlag(flag: string, args: string[]): string | undefined {
  const index = args.indexOf(flag);
  if (index === -1) {
    return undefined;
  }

  return args[index + 1];
}

function parseArgs(argv: string[]): BootstrapCliArgs {
  const tenantKey = readFlag('--tenant-key', argv);
  const tenantName = readFlag('--tenant-name', argv);
  const adminEmail = readFlag('--admin-email', argv);
  const inviteTtlHoursRaw = readFlag('--invite-ttl-hours', argv);

  if (!tenantKey || !tenantName || !adminEmail || !inviteTtlHoursRaw) {
    throw new Error(
      'Usage: yarn workspace @auth-lab/backend db:bootstrap:tenant --tenant-key <key> --tenant-name <name> --admin-email <email> --invite-ttl-hours <hours>',
    );
  }

  const inviteTtlHours = Number(inviteTtlHoursRaw);
  if (!Number.isInteger(inviteTtlHours) || inviteTtlHours <= 0) {
    throw new Error('--invite-ttl-hours must be a positive integer');
  }

  return {
    tenantKey,
    tenantName,
    adminEmail,
    inviteTtlHours,
  };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const config = buildConfig();
  const deps = await buildDeps(config);

  try {
    logger.info({
      flow: 'seed.bootstrap.cli',
      msg: 'seed.bootstrap.start',
      tenantKey: args.tenantKey,
      adminEmail: args.adminEmail,
      nodeEnv: config.nodeEnv,
    });

    await runTenantBootstrap({
      db: deps.db,
      tokenHasher: deps.tokenHasher,
      outboxRepo: deps.outboxRepo,
      outboxEncryption: deps.outboxEncryption,
      options: {
        tenantKey: args.tenantKey,
        tenantName: args.tenantName,
        adminEmail: args.adminEmail,
        inviteTtlHours: args.inviteTtlHours,
        emitRawInviteTokenToLogs: false,
        logInfo: (entry) => logger.info(entry),
      },
    });

    logger.info({
      flow: 'seed.bootstrap.cli',
      msg: 'seed.bootstrap.done',
      tenantKey: args.tenantKey,
      adminEmail: args.adminEmail,
      inviteTtlHours: args.inviteTtlHours,
    });
  } finally {
    await deps.close();
  }
}

void main().catch((err: unknown) => {
  logger.error('seed.bootstrap.failed', { err });
  process.exit(1);
});
