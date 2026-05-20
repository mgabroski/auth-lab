/**
 * backend/src/modules/personal-cards/personal-cards.service.ts
 *
 * WHY:
 * - Builds the Personal Cards read model from backend-resolved Operational
 *   Access visibility. This turns the previous resolver-only proof into a real
 *   module-consumer proof.
 * - The service intentionally uses a small card shape: identity/contact fields
 *   plus two deterministic sensitive proof fields.
 *
 * RULES:
 * - OperationalAccessService decides record visibility and field treatments.
 * - This service only applies those server decisions to module-owned output.
 * - Sensitive proof values are deterministic test/read-model placeholders, not
 *   persisted person data. They exist to prove masking/hiding behavior without
 *   introducing a broader Personal data schema in this correction pass.
 */

import type { OperationalAccessService } from '../operational-access/operational-access.service';
import type {
  OperationalAccessFieldVisibility,
  OperationalAccessResolveActor,
  OperationalAccessRuntimePersonDto,
  OperationalAccessRuntimePersonResponse,
} from '../operational-access/operational-access.types';
import type {
  PersonalCardDetailResponse,
  PersonalCardDto,
  PersonalCardFieldDto,
  PersonalCardFieldKey,
  PersonalCardFieldSensitivity,
  PersonalCardFieldTreatment,
  PersonalCardsListResponse,
} from './personal-cards.types';

const FIELD_META: Record<
  PersonalCardFieldKey,
  { label: string; sensitivity: PersonalCardFieldSensitivity }
> = {
  'person.name': { label: 'Name', sensitivity: 'STANDARD' },
  'person.work_email': { label: 'Work Email', sensitivity: 'STANDARD' },
  'person.ssn': { label: 'SSN', sensitivity: 'SENSITIVE' },
  'person.date_of_birth': { label: 'Date of Birth', sensitivity: 'SENSITIVE' },
};

function treatmentFor(
  visibility: OperationalAccessFieldVisibility[],
  key: OperationalAccessFieldVisibility['fieldKey'],
): PersonalCardFieldTreatment {
  return visibility.find((field) => field.fieldKey === key)?.treatment ?? 'HIDDEN';
}

function proofSensitiveValue(membershipId: string, fieldKey: PersonalCardFieldKey): string {
  const suffix = membershipId.replace(/-/g, '').slice(-4).padStart(4, '0');
  if (fieldKey === 'person.ssn') return `999-88-${suffix}`;
  return '1970-01-01';
}

function applyTreatment(
  value: string | null,
  treatment: PersonalCardFieldTreatment,
  sensitivity: PersonalCardFieldSensitivity,
): string | null {
  if (treatment === 'VISIBLE') return value;
  if (treatment === 'MASKED' && sensitivity === 'SENSITIVE') return 'MASKED';
  return null;
}

function fieldDto(input: {
  fieldKey: PersonalCardFieldKey;
  treatment: PersonalCardFieldTreatment;
  rawValue: string | null;
}): PersonalCardFieldDto {
  const meta = FIELD_META[input.fieldKey];
  return {
    fieldKey: input.fieldKey,
    label: meta.label,
    sensitivity: meta.sensitivity,
    treatment: input.treatment,
    value: applyTreatment(input.rawValue, input.treatment, meta.sensitivity),
  };
}

function cardFromRuntimePerson(person: OperationalAccessRuntimePersonDto): PersonalCardDto {
  const nameTreatment = treatmentFor(person.fieldVisibility, 'name');
  const emailTreatment = treatmentFor(person.fieldVisibility, 'email');
  const ssnTreatment = treatmentFor(person.fieldVisibility, 'person.ssn');
  const dateOfBirthTreatment = treatmentFor(person.fieldVisibility, 'person.date_of_birth');

  const fields = [
    fieldDto({ fieldKey: 'person.name', treatment: nameTreatment, rawValue: person.name }),
    fieldDto({ fieldKey: 'person.work_email', treatment: emailTreatment, rawValue: person.email }),
    fieldDto({
      fieldKey: 'person.ssn',
      treatment: ssnTreatment,
      rawValue: proofSensitiveValue(person.membershipId, 'person.ssn'),
    }),
    fieldDto({
      fieldKey: 'person.date_of_birth',
      treatment: dateOfBirthTreatment,
      rawValue: proofSensitiveValue(person.membershipId, 'person.date_of_birth'),
    }),
  ];

  return {
    membershipId: person.membershipId,
    title: fields.find((field) => field.fieldKey === 'person.name')?.value ?? null,
    fields,
    fieldVisibility: fields,
    sourcePath: person.sourcePath,
    explanation: person.explanation,
  };
}

export class PersonalCardsService {
  constructor(private readonly operationalAccessService: OperationalAccessService) {}

  async listCards(actor: OperationalAccessResolveActor): Promise<PersonalCardsListResponse> {
    const resolved = await this.operationalAccessService.listRuntimePeople(actor);
    return {
      actionKey: resolved.actionKey,
      module: 'personal_cards',
      whichRecordsApplied: 'personal_cards_requiring_attention',
      cards: resolved.people.map(cardFromRuntimePerson),
    };
  }

  async getCard(
    actor: OperationalAccessResolveActor,
    targetMembershipId: string,
  ): Promise<PersonalCardDetailResponse> {
    const resolved: OperationalAccessRuntimePersonResponse =
      await this.operationalAccessService.getRuntimePerson(actor, targetMembershipId);
    return {
      actionKey: resolved.actionKey,
      module: 'personal_cards',
      whichRecordsApplied: 'personal_cards_requiring_attention',
      card: cardFromRuntimePerson(resolved.person),
    };
  }
}
