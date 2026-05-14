import { describe, expect, it } from 'vitest';

import { validatePeopleTeamGroupDraft } from '../../../../src/shared/people-teams/validation';

describe('people teams validation', () => {
  it('requires a group name before submitting to backend-owned writes', () => {
    expect(validatePeopleTeamGroupDraft({ name: '   ', level: 'AGENT' })).toBe(
      'Group name is required.',
    );
  });

  it('rejects unknown group levels without changing runtime role semantics', () => {
    expect(validatePeopleTeamGroupDraft({ name: 'HR Agents', level: 'OWNER' })).toBe(
      'Choose a valid group level.',
    );
  });

  it('accepts the classification-only group levels used by the foundation UI', () => {
    expect(validatePeopleTeamGroupDraft({ name: 'HR Agents', level: 'ADMIN' })).toBeNull();
    expect(validatePeopleTeamGroupDraft({ name: 'HR Agents', level: 'AGENT' })).toBeNull();
    expect(validatePeopleTeamGroupDraft({ name: 'HR Agents', level: 'USER' })).toBeNull();
  });
});
