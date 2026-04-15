/**
 * backend/src/modules/control-plane/accounts/dal/cp-accounts.query-sql.ts
 *
 * WHY:
 * - DAL reads for Control Plane accounts and Step 2 group tables.
 * - Returns raw DB row shapes only; services compose domain DTOs.
 *
 * RULES:
 * - No AppError.
 * - No business logic.
 * - No transactions started here.
 */

import type { Selectable } from 'kysely';
import type { DbExecutor } from '../../../../shared/db/db';
import type {
  CpAccessConfig,
  CpAccountSettingsConfig,
  CpAccounts,
  CpIntegrationConfig,
  CpModuleConfig,
  CpPersonalFamilyConfig,
  CpPersonalFieldConfig,
} from '../../../../shared/db/database.types';

export type CpAccountRow = Selectable<CpAccounts>;
export type CpAccessConfigRow = Selectable<CpAccessConfig>;
export type CpAccountSettingsConfigRow = Selectable<CpAccountSettingsConfig>;
export type CpModuleConfigRow = Selectable<CpModuleConfig>;
export type CpPersonalFamilyConfigRow = Selectable<CpPersonalFamilyConfig>;
export type CpPersonalFieldConfigRow = Selectable<CpPersonalFieldConfig>;
export type CpIntegrationConfigRow = Selectable<CpIntegrationConfig>;

export async function findCpAccountByKeySql(
  db: DbExecutor,
  accountKey: string,
): Promise<CpAccountRow | undefined> {
  return db
    .selectFrom('cp_accounts')
    .selectAll()
    .where('account_key', '=', accountKey)
    .executeTakeFirst();
}

export async function listCpAccountsSql(db: DbExecutor): Promise<CpAccountRow[]> {
  return db.selectFrom('cp_accounts').selectAll().orderBy('created_at', 'asc').execute();
}

export async function findCpAccessConfigSql(
  db: DbExecutor,
  accountId: string,
): Promise<CpAccessConfigRow | undefined> {
  return db
    .selectFrom('cp_access_config')
    .selectAll()
    .where('account_id', '=', accountId)
    .executeTakeFirst();
}

export async function findCpAccountSettingsConfigSql(
  db: DbExecutor,
  accountId: string,
): Promise<CpAccountSettingsConfigRow | undefined> {
  return db
    .selectFrom('cp_account_settings_config')
    .selectAll()
    .where('account_id', '=', accountId)
    .executeTakeFirst();
}

export async function findCpModuleConfigSql(
  db: DbExecutor,
  accountId: string,
): Promise<CpModuleConfigRow | undefined> {
  return db
    .selectFrom('cp_module_config')
    .selectAll()
    .where('account_id', '=', accountId)
    .executeTakeFirst();
}

export async function listCpPersonalFamilyConfigSql(
  db: DbExecutor,
  accountId: string,
): Promise<CpPersonalFamilyConfigRow[]> {
  return db
    .selectFrom('cp_personal_family_config')
    .selectAll()
    .where('account_id', '=', accountId)
    .orderBy('family_key', 'asc')
    .execute();
}

export async function listCpPersonalFieldConfigSql(
  db: DbExecutor,
  accountId: string,
): Promise<CpPersonalFieldConfigRow[]> {
  return db
    .selectFrom('cp_personal_field_config')
    .selectAll()
    .where('account_id', '=', accountId)
    .orderBy('field_key', 'asc')
    .execute();
}

export async function listCpIntegrationConfigSql(
  db: DbExecutor,
  accountId: string,
): Promise<CpIntegrationConfigRow[]> {
  return db
    .selectFrom('cp_integration_config')
    .selectAll()
    .where('account_id', '=', accountId)
    .orderBy('integration_key', 'asc')
    .execute();
}
