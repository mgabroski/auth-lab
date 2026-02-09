import type { DbExecutor } from '../../../shared/db/db';

/**
 * DAL WRITES ONLY
 * - No transactions started here
 * - No AppError
 * - No policies
 *
 * Brick 5 doesn't need writes yet, but we keep the repo
 * to lock the structure and avoid future spaghetti.
 */
export class TenantRepo {
  constructor(private readonly db: DbExecutor) {}

  // Intentionally empty in Brick 5.
}
