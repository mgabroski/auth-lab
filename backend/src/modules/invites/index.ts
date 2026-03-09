/**
 * src/modules/invites/index.ts
 *
 * WHY:
 * - Defines the public surface of the invites module.
 * - Prevents other modules from coupling to internal query paths.
 *
 * RULES:
 * - Only export stable contracts needed by other modules.
 * - Internal flows, policies, dal, and admin subfolder are not exported.
 */

export { getInviteByTenantAndTokenHash } from './queries/invite.queries';
export type { Invite, InviteRole, InviteStatus } from './invite.types';
