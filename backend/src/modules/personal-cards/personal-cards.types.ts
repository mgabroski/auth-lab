/**
 * backend/src/modules/personal-cards/personal-cards.types.ts
 *
 * WHY:
 * - Defines the first real Personal Cards read-model DTO that consumes
 *   backend-resolved Operational Access decisions.
 * - Keeps card/field output separate from the resolver decision so the module
 *   proves both record visibility and field masking/hiding.
 *
 * RULES:
 * - Values are already masked/hidden before reaching the frontend.
 * - Frontend renders treatment/value only; it never computes access.
 */

import type {
  OperationalAccessActionKey,
  OperationalAccessSourcePath,
} from '../operational-access/operational-access.types';

export type PersonalCardFieldKey =
  | 'person.name'
  | 'person.work_email'
  | 'person.ssn'
  | 'person.date_of_birth';

export type PersonalCardFieldTreatment = 'VISIBLE' | 'MASKED' | 'HIDDEN';
export type PersonalCardFieldSensitivity = 'STANDARD' | 'SENSITIVE';

export type PersonalCardFieldDto = {
  fieldKey: PersonalCardFieldKey;
  label: string;
  sensitivity: PersonalCardFieldSensitivity;
  treatment: PersonalCardFieldTreatment;
  value: string | null;
};

export type PersonalCardDto = {
  membershipId: string;
  title: string | null;
  fields: PersonalCardFieldDto[];
  fieldVisibility: PersonalCardFieldDto[];
  sourcePath: OperationalAccessSourcePath[];
  explanation: string[];
};

export type PersonalCardsListResponse = {
  actionKey: OperationalAccessActionKey;
  module: 'personal_cards';
  whichRecordsApplied: 'personal_cards_requiring_attention';
  cards: PersonalCardDto[];
};

export type PersonalCardDetailResponse = {
  actionKey: OperationalAccessActionKey;
  module: 'personal_cards';
  whichRecordsApplied: 'personal_cards_requiring_attention';
  card: PersonalCardDto;
};
