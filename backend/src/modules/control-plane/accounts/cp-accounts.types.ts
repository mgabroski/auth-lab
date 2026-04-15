/**
 * backend/src/modules/control-plane/accounts/cp-accounts.types.ts
 *
 * WHY:
 * - Domain types for the Control Plane accounts subdomain.
 * - Decoupled from DB row shape (Kysely Selectable) and HTTP DTOs (Zod).
 * - Referenced by service, controller, and DAL layers.
 *
 * RULES:
 * - No Kysely imports here.
 * - No Zod imports here.
 * - No AppError here.
 * - Types must stay compatible with the locked CP status vocabulary.
 *
 * CP STATUS VOCABULARY (locked):
 * - Draft    — created but not yet published
 * - Active   — published and reachable by tenants
 * - Disabled — published but access is suspended
 *
 * CP REVISION:
 * - cpRevision starts at 0 on creation.
 * - Incremented on meaningful allowance mutations (group saves, publish).
 * - Phase 2 scope: only creation sets cpRevision = 0. Group saves are deferred.
 */

export type CpStatus = 'Draft' | 'Active' | 'Disabled';

/**
 * Full domain representation of a CP account.
 * Returned from service reads and used inside service orchestration.
 */
export type CpAccount = {
  id: string;
  accountName: string;
  accountKey: string;
  cpStatus: CpStatus;
  cpRevision: number;
  createdAt: Date;
  updatedAt: Date;
};

/**
 * Slim row shape for the accounts list endpoint.
 * Avoids over-fetching columns not needed by the list view.
 */
export type CpAccountListRow = {
  id: string;
  accountName: string;
  accountKey: string;
  cpStatus: CpStatus;
  cpRevision: number;
};
