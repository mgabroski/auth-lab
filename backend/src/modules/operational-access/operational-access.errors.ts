/**
 * backend/src/modules/operational-access/operational-access.errors.ts
 *
 * WHY:
 * - Module-scoped semantic errors for Operational Access configuration.
 * - Keeps user-facing error copy centralized and anti-drift safe.
 */

import { AppError } from '../../shared/http/errors';

export const OperationalAccessErrors = {
  capabilityDisabled() {
    return AppError.notFound('Operational Access is not enabled for this workspace.');
  },

  groupNotFound(groupId: string) {
    return AppError.notFound('Operational Access Agent group not found.', { groupId });
  },

  groupMustBeActiveAgent(groupId: string) {
    return AppError.conflict('Operational Access grants require an active Agent group.', {
      groupId,
    });
  },

  invalidActionKey(actionKey: string) {
    return AppError.validationError('Unsupported Operational Access action key.', { actionKey });
  },

  invalidPrimaryWhere(primaryWhere: string) {
    return AppError.validationError('Unsupported Primary Where option.', { primaryWhere });
  },

  invalidWhichRecords(whichRecordsKey: string) {
    return AppError.validationError('Unsupported Which Records choice.', { whichRecordsKey });
  },

  invalidGrantCombination(details: {
    actionKey: string;
    primaryWhere: string;
    whichRecordsKey: string;
  }) {
    return AppError.validationError(
      'The selected action, Primary Where, and Which Records combination is not product-defined.',
      details,
    );
  },

  duplicateGrant(actionKey: string) {
    return AppError.conflict('This group already has a grant for that action.', { actionKey });
  },

  unsupportedCoverage(type: string) {
    return AppError.validationError('This Operational Access coverage type is not shipped yet.', {
      type,
    });
  },

  membershipNotFound(membershipId: string) {
    return AppError.notFound('Tenant membership not found.', { membershipId });
  },

  agentMembershipRequired(membershipId: string) {
    return AppError.validationError(
      'Responsible For coverage requires an active Agent membership.',
      {
        membershipId,
      },
    );
  },

  agentMustBeGroupMember(membershipId: string, groupId: string) {
    return AppError.validationError(
      'Responsible For coverage requires the Agent to be a member of the selected group.',
      { membershipId, groupId },
    );
  },

  targetMembershipRequired(membershipId: string) {
    return AppError.validationError('Responsible For target must be an active tenant membership.', {
      membershipId,
    });
  },

  duplicateResponsibleForAssignment(agentMembershipId: string, targetMembershipId: string) {
    return AppError.conflict('This Responsible For assignment already exists in the request.', {
      agentMembershipId,
      targetMembershipId,
    });
  },

  selfResponsibleForNotAllowed(membershipId: string) {
    return AppError.validationError('An Agent cannot be Responsible For their own membership.', {
      membershipId,
    });
  },
} as const;
