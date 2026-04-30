'use client';

import { useMemo, useState, type CSSProperties } from 'react';

import { getApiErrorMessage } from '@/shared/auth/api-errors';
import type {
  PersonalFamilyReviewDecision,
  PersonalSettingsResponse,
  SavePersonalSettingsRequest,
} from '@/shared/settings/contracts';
import { fetchPersonalSettingsBrowser, savePersonalSettings } from '@/shared/settings/browser-api';
import { SettingsStatusChip } from './settings-status-chip';

type PersonalDraft = {
  families: Array<{
    familyKey: string;
    label: string;
    canExclude: boolean;
    reviewDecision: PersonalFamilyReviewDecision;
  }>;
  fields: Array<{
    fieldKey: string;
    familyKey: string;
    label: string;
    minimumRequired: 'none' | 'required' | 'auto';
    isSystemManaged: boolean;
    included: boolean;
    required: boolean;
    masked: boolean;
    canToggleInclude: boolean;
    canToggleRequired: boolean;
    canToggleMasking: boolean;
  }>;
  sections: Array<{
    sectionId: string;
    name: string;
    order: number;
    fields: Array<{
      fieldKey: string;
      order: number;
    }>;
  }>;
};

const pageStackStyle: CSSProperties = {
  display: 'grid',
  gap: '18px',
};

const heroCardStyle: CSSProperties = {
  display: 'grid',
  gap: '14px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -28px rgba(15, 23, 42, 0.35)',
};

const panelStyle: CSSProperties = {
  display: 'grid',
  gap: '14px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -28px rgba(15, 23, 42, 0.35)',
};

const surfaceStyle: CSSProperties = {
  display: 'grid',
  gap: '12px',
  padding: '16px',
  borderRadius: '16px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#f8fafc',
};

const noticeBaseStyle: CSSProperties = {
  display: 'grid',
  gap: '8px',
  padding: '14px 16px',
  borderRadius: '16px',
  border: '1px solid transparent',
};

const warningNoticeStyle: CSSProperties = {
  ...noticeBaseStyle,
  backgroundColor: '#fff7ed',
  borderColor: '#fed7aa',
  color: '#9a3412',
};

const errorNoticeStyle: CSSProperties = {
  ...noticeBaseStyle,
  backgroundColor: '#fef2f2',
  borderColor: '#fecaca',
  color: '#991b1b',
};

const successNoticeStyle: CSSProperties = {
  ...noticeBaseStyle,
  backgroundColor: '#f0fdf4',
  borderColor: '#bbf7d0',
  color: '#166534',
};

const infoNoticeStyle: CSSProperties = {
  ...noticeBaseStyle,
  backgroundColor: '#eff6ff',
  borderColor: '#bfdbfe',
  color: '#1d4ed8',
};

const inputStyle: CSSProperties = {
  width: '100%',
  minHeight: '42px',
  padding: '10px 12px',
  borderRadius: '14px',
  border: '1px solid #cbd5e1',
  backgroundColor: '#ffffff',
  color: '#0f172a',
  fontSize: '14px',
};

const buttonStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  minHeight: '42px',
  padding: '0 16px',
  borderRadius: '14px',
  border: '1px solid #1d4ed8',
  backgroundColor: '#1d4ed8',
  color: '#ffffff',
  fontSize: '14px',
  fontWeight: 700,
  cursor: 'pointer',
};

const secondaryButtonStyle: CSSProperties = {
  ...buttonStyle,
  borderColor: '#cbd5e1',
  backgroundColor: '#ffffff',
  color: '#0f172a',
};

const disabledButtonStyle: CSSProperties = {
  ...buttonStyle,
  borderColor: '#cbd5e1',
  backgroundColor: '#e2e8f0',
  color: '#64748b',
  cursor: 'not-allowed',
};

const smallBadgeStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  padding: '4px 10px',
  borderRadius: '999px',
  border: '1px solid #cbd5e1',
  fontSize: '12px',
  fontWeight: 700,
  color: '#475569',
  backgroundColor: '#f8fafc',
};

function familyLabelByKey(data: PersonalSettingsResponse): Map<string, string> {
  return new Map(data.familyReview.families.map((family) => [family.familyKey, family.label]));
}

function buildDraftFromDto(data: PersonalSettingsResponse): PersonalDraft {
  return {
    families: data.familyReview.families.map((family) => ({
      familyKey: family.familyKey,
      label: family.label,
      canExclude: family.canExclude,
      reviewDecision: family.reviewDecision,
    })),
    fields: data.fieldConfiguration.families.flatMap((family) =>
      family.fields.map((field) => ({
        fieldKey: field.fieldKey,
        familyKey: field.familyKey,
        label: field.label,
        minimumRequired: field.minimumRequired,
        isSystemManaged: field.isSystemManaged,
        included: field.included,
        required: field.required,
        masked: field.masked,
        canToggleInclude: field.canToggleInclude,
        canToggleRequired: field.canToggleRequired,
        canToggleMasking: field.canToggleMasking,
      })),
    ),
    sections: data.sectionBuilder.sections.map((section) => ({
      sectionId: section.sectionId,
      name: section.name,
      order: section.order,
      fields: section.fields.map((field) => ({ fieldKey: field.fieldKey, order: field.order })),
    })),
  };
}

function draftToRequest(
  data: PersonalSettingsResponse,
  draft: PersonalDraft,
): SavePersonalSettingsRequest {
  return {
    expectedVersion: data.version,
    expectedCpRevision: data.cpRevision,
    families: draft.families.map((family) => ({
      familyKey: family.familyKey,
      reviewDecision: family.reviewDecision,
    })),
    fields: draft.fields.map((field) => ({
      fieldKey: field.fieldKey,
      included: field.included,
      required: field.required,
      masked: field.masked,
    })),
    sections: draft.sections.map((section, sectionIndex) => ({
      sectionId: section.sectionId,
      name: section.name,
      order: sectionIndex,
      fields: section.fields.map((field, fieldIndex) => ({
        fieldKey: field.fieldKey,
        order: fieldIndex,
      })),
    })),
  };
}

function normalizeDraft(data: PersonalSettingsResponse, draft: PersonalDraft): PersonalDraft {
  const familyLabelMap = familyLabelByKey(data);
  const fieldMap = new Map(draft.fields.map((field) => [field.fieldKey, field]));
  const includedFields = draft.fields
    .filter((field) => field.included)
    .map((field) => field.fieldKey);
  const includedSet = new Set(includedFields);
  const seen = new Set<string>();

  const sections = draft.sections.map((section, sectionIndex) => ({
    ...section,
    order: sectionIndex,
    name: section.name,
    fields: section.fields
      .filter((field) => includedSet.has(field.fieldKey) && !seen.has(field.fieldKey))
      .map((field, fieldIndex) => {
        seen.add(field.fieldKey);
        return { fieldKey: field.fieldKey, order: fieldIndex };
      }),
  }));

  for (const fieldKey of includedFields) {
    if (seen.has(fieldKey)) {
      continue;
    }

    const field = fieldMap.get(fieldKey);
    if (!field) {
      continue;
    }

    const family = draft.families.find((item) => item.familyKey === field.familyKey);
    let target = sections.find(
      (section) =>
        section.name === (familyLabelMap.get(field.familyKey) ?? family?.label ?? field.familyKey),
    );

    if (!target) {
      target = {
        sectionId: `generated-${field.familyKey}`,
        name: familyLabelMap.get(field.familyKey) ?? family?.label ?? field.familyKey,
        order: sections.length,
        fields: [],
      };
      sections.push(target);
    }

    target.fields.push({ fieldKey, order: target.fields.length });
    seen.add(fieldKey);
  }

  return {
    ...draft,
    sections: sections.map((section, sectionIndex) => ({
      ...section,
      order: sectionIndex,
      fields: section.fields.map((field, fieldIndex) => ({ ...field, order: fieldIndex })),
    })),
  };
}

function buildDraftBlockers(params: {
  draft: PersonalDraft;
  serverReviewedFamiliesCount: number;
}): string[] {
  const blockers: string[] = [];
  if (params.serverReviewedFamiliesCount === 0) {
    blockers.push('No family reviewed yet.');
  }

  const draft = params.draft;

  for (const field of draft.fields) {
    if (
      (field.minimumRequired === 'required' || field.isSystemManaged) &&
      (!field.included || !field.required)
    ) {
      blockers.push('Required-floor fields still need configuration.');
      break;
    }
  }

  const includedFieldKeys = draft.fields
    .filter((field) => field.included)
    .map((field) => field.fieldKey);
  const assignedFieldKeys = draft.sections.flatMap((section) =>
    section.fields.map((field) => field.fieldKey),
  );

  if (includedFieldKeys.length === 0) {
    blockers.push('At least one included field must be assigned to a section.');
  }

  for (const section of draft.sections) {
    if (section.name.trim().length === 0) {
      blockers.push('Every section must have a name.');
      break;
    }
    if (section.fields.length === 0) {
      blockers.push('Empty sections cannot be saved.');
      break;
    }
  }

  const assignedSet = new Set(assignedFieldKeys);
  if (assignedSet.size !== assignedFieldKeys.length) {
    blockers.push('Each included field must appear in exactly one section.');
  }
  const includedSet = new Set(includedFieldKeys);
  if (
    includedSet.size !== assignedSet.size ||
    includedFieldKeys.some((fieldKey) => !assignedSet.has(fieldKey))
  ) {
    blockers.push('All included fields must be assigned to sections before saving.');
  }

  return Array.from(new Set(blockers));
}

type PersonalSettingsFoundationProps = {
  data: PersonalSettingsResponse;
};

export function PersonalSettingsFoundation({ data }: PersonalSettingsFoundationProps) {
  const [latestServer, setLatestServer] = useState(data);
  const [draft, setDraft] = useState<PersonalDraft>(() => buildDraftFromDto(data));
  const [saving, setSaving] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [conflictMessage, setConflictMessage] = useState<string | null>(null);

  const draftBlockers = useMemo(
    () =>
      buildDraftBlockers({
        draft,
        serverReviewedFamiliesCount: latestServer.progress.reviewedFamiliesCount,
      }),
    [draft, latestServer.progress.reviewedFamiliesCount],
  );
  const currentRequest = useMemo(() => draftToRequest(latestServer, draft), [latestServer, draft]);
  const latestRequest = useMemo(
    () => draftToRequest(latestServer, buildDraftFromDto(latestServer)),
    [latestServer],
  );
  const hasChanges = JSON.stringify(currentRequest) !== JSON.stringify(latestRequest);
  const familyLabelMap = useMemo(() => familyLabelByKey(latestServer), [latestServer]);

  async function refreshLatestServer(): Promise<PersonalSettingsResponse | null> {
    const refreshed = await fetchPersonalSettingsBrowser();
    if (!refreshed.ok) {
      setErrorMessage(getApiErrorMessage(refreshed.error));
      return null;
    }
    setLatestServer(refreshed.data);
    return refreshed.data;
  }

  function updateDraft(mutator: (current: PersonalDraft) => PersonalDraft) {
    setDraft((current) => normalizeDraft(latestServer, mutator(current)));
  }

  async function handleSave() {
    setSaving(true);
    setSuccessMessage(null);
    setErrorMessage(null);
    setConflictMessage(null);

    const result = await savePersonalSettings(currentRequest);

    if (!result.ok) {
      if (result.status === 409) {
        const latest = await refreshLatestServer();
        setConflictMessage(getApiErrorMessage(result.error));
        if (latest) {
          setLatestServer(latest);
        }
      } else {
        setErrorMessage(getApiErrorMessage(result.error));
      }
      setSaving(false);
      return;
    }

    const latest = await refreshLatestServer();
    if (latest) {
      setDraft(buildDraftFromDto(latest));
      setSuccessMessage('Personal configuration saved.');
    }
    setSaving(false);
  }

  function setFamilyDecision(familyKey: string, reviewDecision: PersonalFamilyReviewDecision) {
    updateDraft((current) => {
      const next = {
        ...current,
        families: current.families.map((family) =>
          family.familyKey === familyKey ? { ...family, reviewDecision } : family,
        ),
        fields: current.fields.map((field) => {
          if (field.familyKey !== familyKey) {
            return field;
          }
          if (reviewDecision === 'EXCLUDED') {
            return { ...field, included: false, required: false, masked: false };
          }
          if ((field.minimumRequired === 'required' || field.isSystemManaged) && !field.included) {
            return { ...field, included: true, required: true };
          }
          return field;
        }),
      };
      return next;
    });
  }

  function setFieldIncluded(fieldKey: string, included: boolean) {
    updateDraft((current) => ({
      ...current,
      fields: current.fields.map((field) => {
        if (field.fieldKey !== fieldKey) {
          return field;
        }
        if (!field.canToggleInclude) {
          return field;
        }
        return {
          ...field,
          included,
          required: included ? field.required : false,
          masked: included ? field.masked : false,
        };
      }),
    }));
  }

  function setFieldRequired(fieldKey: string, required: boolean) {
    updateDraft((current) => ({
      ...current,
      fields: current.fields.map((field) =>
        field.fieldKey === fieldKey && field.canToggleRequired ? { ...field, required } : field,
      ),
    }));
  }

  function setFieldMasked(fieldKey: string, masked: boolean) {
    updateDraft((current) => ({
      ...current,
      fields: current.fields.map((field) =>
        field.fieldKey === fieldKey && field.canToggleMasking ? { ...field, masked } : field,
      ),
    }));
  }

  function addSection() {
    updateDraft((current) => ({
      ...current,
      sections: [
        ...current.sections,
        {
          sectionId: `custom-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
          name: 'New section',
          order: current.sections.length,
          fields: [],
        },
      ],
    }));
  }

  function renameSection(sectionId: string, name: string) {
    updateDraft((current) => ({
      ...current,
      sections: current.sections.map((section) =>
        section.sectionId === sectionId ? { ...section, name } : section,
      ),
    }));
  }

  function moveSection(sectionId: string, direction: -1 | 1) {
    updateDraft((current) => {
      const sections = [...current.sections];
      const index = sections.findIndex((section) => section.sectionId === sectionId);
      const target = index + direction;
      if (index < 0 || target < 0 || target >= sections.length) {
        return current;
      }
      const [section] = sections.splice(index, 1);
      sections.splice(target, 0, section);
      return { ...current, sections };
    });
  }

  function removeSection(sectionId: string) {
    updateDraft((current) => ({
      ...current,
      sections: current.sections.filter((section) => section.sectionId !== sectionId),
    }));
  }

  function moveFieldWithinSection(sectionId: string, fieldKey: string, direction: -1 | 1) {
    updateDraft((current) => ({
      ...current,
      sections: current.sections.map((section) => {
        if (section.sectionId !== sectionId) {
          return section;
        }
        const fields = [...section.fields];
        const index = fields.findIndex((field) => field.fieldKey === fieldKey);
        const target = index + direction;
        if (index < 0 || target < 0 || target >= fields.length) {
          return section;
        }
        const [field] = fields.splice(index, 1);
        fields.splice(target, 0, field);
        return { ...section, fields };
      }),
    }));
  }

  function moveFieldToSection(fieldKey: string, targetSectionId: string) {
    updateDraft((current) => {
      const sections = current.sections.map((section) => ({
        ...section,
        fields: section.fields.filter((field) => field.fieldKey !== fieldKey),
      }));
      const target = sections.find((section) => section.sectionId === targetSectionId);
      if (target) {
        target.fields.push({ fieldKey, order: target.fields.length });
      }
      return { ...current, sections };
    });
  }

  return (
    <div style={pageStackStyle}>
      <section style={heroCardStyle}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            gap: '12px',
            flexWrap: 'wrap',
          }}
        >
          <div style={{ display: 'grid', gap: '8px' }}>
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
              <h2 style={{ margin: 0, fontSize: '22px', lineHeight: 1.2, color: '#0f172a' }}>
                {latestServer.title}
              </h2>
              <SettingsStatusChip status={latestServer.status} />
            </div>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
              {latestServer.description}
            </p>
          </div>
          <button
            type="button"
            style={saving || !hasChanges ? disabledButtonStyle : buttonStyle}
            disabled={saving || !hasChanges}
            onClick={() => {
              void handleSave();
            }}
          >
            {saving ? 'Saving…' : latestServer.stickySaveLabel}
          </button>
        </div>

        <div
          style={{
            display: 'grid',
            gap: '10px',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          }}
        >
          <div style={surfaceStyle}>
            <strong>Reviewed families</strong>
            <span>
              {latestServer.progress.reviewedFamiliesCount} of{' '}
              {latestServer.progress.totalAllowedFamilies}
            </span>
          </div>
          <div style={surfaceStyle}>
            <strong>Required-field readiness</strong>
            <span>{latestServer.progress.requiredFieldsReady ? 'Ready' : 'Needs attention'}</span>
          </div>
          <div style={surfaceStyle}>
            <strong>Section assignments</strong>
            <span>
              {latestServer.progress.sectionAssignmentsReady ? 'Ready' : 'Needs attention'}
            </span>
          </div>
        </div>

        {latestServer.warnings.length > 0 ? (
          <div style={warningNoticeStyle}>
            <strong>Needs review</strong>
            <ul style={{ margin: 0, paddingLeft: '18px', display: 'grid', gap: '4px' }}>
              {latestServer.warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          </div>
        ) : null}

        {draftBlockers.length > 0 ? (
          <div style={warningNoticeStyle}>
            <strong>Current draft blockers</strong>
            <ul style={{ margin: 0, paddingLeft: '18px', display: 'grid', gap: '4px' }}>
              {draftBlockers.map((blocker) => (
                <li key={blocker}>{blocker}</li>
              ))}
            </ul>
          </div>
        ) : null}

        {conflictMessage ? (
          <div style={infoNoticeStyle}>
            <strong>Conflict surfaced</strong>
            <p style={{ margin: 0 }}>{conflictMessage}</p>
            <p style={{ margin: 0 }}>{latestServer.conflictGuidance.summary}</p>
          </div>
        ) : null}

        {successMessage ? (
          <div style={successNoticeStyle}>
            <strong>Saved</strong>
            <p style={{ margin: 0 }}>{successMessage}</p>
          </div>
        ) : null}

        {errorMessage ? (
          <div style={errorNoticeStyle}>
            <strong>Save failed</strong>
            <p style={{ margin: 0 }}>{errorMessage}</p>
          </div>
        ) : null}
      </section>

      <section style={panelStyle}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            gap: '12px',
            flexWrap: 'wrap',
          }}
        >
          <div>
            <h3 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2, color: '#0f172a' }}>
              {latestServer.familyReview.title}
            </h3>
            <p style={{ margin: '8px 0 0', fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
              {latestServer.familyReview.description}
            </p>
          </div>
          <span style={smallBadgeStyle}>
            {latestServer.familyReview.status.replaceAll('_', ' ')}
          </span>
        </div>
        {draft.families.map((family) => (
          <article key={family.familyKey} style={surfaceStyle}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                gap: '12px',
                flexWrap: 'wrap',
              }}
            >
              <div>
                <h4 style={{ margin: 0, fontSize: '16px', lineHeight: 1.2, color: '#0f172a' }}>
                  {family.label}
                </h4>
                <p
                  style={{ margin: '6px 0 0', fontSize: '13px', lineHeight: 1.6, color: '#64748b' }}
                >
                  {family.canExclude
                    ? 'Choose whether this family stays in use.'
                    : 'Locked in use because it contains required-floor or system-managed fields.'}
                </p>
              </div>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  style={family.reviewDecision === 'IN_USE' ? buttonStyle : secondaryButtonStyle}
                  onClick={() => setFamilyDecision(family.familyKey, 'IN_USE')}
                >
                  In use
                </button>
                <button
                  type="button"
                  style={
                    family.reviewDecision === 'EXCLUDED' || !family.canExclude
                      ? disabledButtonStyle
                      : secondaryButtonStyle
                  }
                  disabled={!family.canExclude}
                  onClick={() => setFamilyDecision(family.familyKey, 'EXCLUDED')}
                >
                  Exclude
                </button>
              </div>
            </div>
          </article>
        ))}
      </section>

      <section style={panelStyle}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            gap: '12px',
            flexWrap: 'wrap',
          }}
        >
          <div>
            <h3 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2, color: '#0f172a' }}>
              {latestServer.fieldConfiguration.title}
            </h3>
            <p style={{ margin: '8px 0 0', fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
              {latestServer.fieldConfiguration.description}
            </p>
          </div>
          <span style={smallBadgeStyle}>
            {latestServer.fieldConfiguration.status.replaceAll('_', ' ')}
          </span>
        </div>
        {draft.families.map((family) => {
          const fields = draft.fields.filter((field) => field.familyKey === family.familyKey);
          return (
            <article key={family.familyKey} style={surfaceStyle}>
              <h4 style={{ margin: 0, fontSize: '16px', lineHeight: 1.2, color: '#0f172a' }}>
                {family.label}
              </h4>
              {fields.map((field) => (
                <div
                  key={field.fieldKey}
                  style={{
                    display: 'grid',
                    gap: '8px',
                    paddingTop: '12px',
                    borderTop: '1px solid rgba(226, 232, 240, 0.9)',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      gap: '12px',
                      flexWrap: 'wrap',
                    }}
                  >
                    <div>
                      <strong style={{ color: '#0f172a' }}>{field.label}</strong>
                      <p
                        style={{
                          margin: '4px 0 0',
                          fontSize: '13px',
                          lineHeight: 1.6,
                          color: '#64748b',
                        }}
                      >
                        {field.minimumRequired === 'required'
                          ? 'Required-floor field.'
                          : field.isSystemManaged
                            ? 'System-managed field.'
                            : 'Tenant-managed optional field.'}
                      </p>
                    </div>
                    <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                      <label
                        style={{
                          display: 'inline-flex',
                          gap: '6px',
                          alignItems: 'center',
                          fontSize: '13px',
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={field.included}
                          disabled={!field.canToggleInclude}
                          onChange={(event) =>
                            setFieldIncluded(field.fieldKey, event.target.checked)
                          }
                        />
                        Included
                      </label>
                      <label
                        style={{
                          display: 'inline-flex',
                          gap: '6px',
                          alignItems: 'center',
                          fontSize: '13px',
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={field.required}
                          disabled={!field.canToggleRequired}
                          onChange={(event) =>
                            setFieldRequired(field.fieldKey, event.target.checked)
                          }
                        />
                        Required
                      </label>
                      <label
                        style={{
                          display: 'inline-flex',
                          gap: '6px',
                          alignItems: 'center',
                          fontSize: '13px',
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={field.masked}
                          disabled={!field.canToggleMasking}
                          onChange={(event) => setFieldMasked(field.fieldKey, event.target.checked)}
                        />
                        Masked
                      </label>
                    </div>
                  </div>
                </div>
              ))}
            </article>
          );
        })}
      </section>

      <section style={panelStyle}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            gap: '12px',
            flexWrap: 'wrap',
          }}
        >
          <div>
            <h3 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2, color: '#0f172a' }}>
              {latestServer.sectionBuilder.title}
            </h3>
            <p style={{ margin: '8px 0 0', fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
              {latestServer.sectionBuilder.description}
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <span style={smallBadgeStyle}>
              {latestServer.sectionBuilder.status.replaceAll('_', ' ')}
            </span>
            <button type="button" style={secondaryButtonStyle} onClick={addSection}>
              Add section
            </button>
          </div>
        </div>

        {draft.sections.map((section, sectionIndex) => (
          <article key={section.sectionId} style={surfaceStyle}>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
              <input
                value={section.name}
                onChange={(event) => renameSection(section.sectionId, event.target.value)}
                style={{ ...inputStyle, maxWidth: '320px' }}
                aria-label={`Section name ${sectionIndex + 1}`}
              />
              <button
                type="button"
                style={secondaryButtonStyle}
                onClick={() => moveSection(section.sectionId, -1)}
                disabled={sectionIndex === 0}
              >
                Move up
              </button>
              <button
                type="button"
                style={secondaryButtonStyle}
                onClick={() => moveSection(section.sectionId, 1)}
                disabled={sectionIndex === draft.sections.length - 1}
              >
                Move down
              </button>
              <button
                type="button"
                style={section.fields.length === 0 ? secondaryButtonStyle : disabledButtonStyle}
                disabled={section.fields.length > 0}
                onClick={() => removeSection(section.sectionId)}
              >
                Remove section
              </button>
            </div>

            {section.fields.length === 0 ? (
              <div style={warningNoticeStyle}>
                <strong>Empty section</strong>
                <p style={{ margin: 0 }}>
                  Empty sections may not be saved. Move at least one included field here or remove
                  the section.
                </p>
              </div>
            ) : null}

            {section.fields.map((assignment, fieldIndex) => {
              const field = draft.fields.find(
                (candidate) => candidate.fieldKey === assignment.fieldKey,
              );
              if (!field) {
                return null;
              }

              return (
                <div
                  key={assignment.fieldKey}
                  style={{
                    display: 'grid',
                    gap: '8px',
                    paddingTop: '12px',
                    borderTop: '1px solid rgba(226, 232, 240, 0.9)',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      gap: '12px',
                      flexWrap: 'wrap',
                    }}
                  >
                    <div>
                      <strong style={{ color: '#0f172a' }}>{field.label}</strong>
                      <p
                        style={{
                          margin: '4px 0 0',
                          fontSize: '13px',
                          lineHeight: 1.6,
                          color: '#64748b',
                        }}
                      >
                        {familyLabelMap.get(field.familyKey) ?? field.familyKey}
                      </p>
                    </div>
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      <button
                        type="button"
                        style={secondaryButtonStyle}
                        onClick={() =>
                          moveFieldWithinSection(section.sectionId, assignment.fieldKey, -1)
                        }
                        disabled={fieldIndex === 0}
                      >
                        Up
                      </button>
                      <button
                        type="button"
                        style={secondaryButtonStyle}
                        onClick={() =>
                          moveFieldWithinSection(section.sectionId, assignment.fieldKey, 1)
                        }
                        disabled={fieldIndex === section.fields.length - 1}
                      >
                        Down
                      </button>
                      <select
                        value={section.sectionId}
                        onChange={(event) =>
                          moveFieldToSection(assignment.fieldKey, event.target.value)
                        }
                        style={{ ...inputStyle, minWidth: '180px', maxWidth: '220px' }}
                      >
                        {draft.sections.map((option) => (
                          <option key={option.sectionId} value={option.sectionId}>
                            {option.name}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                </div>
              );
            })}
          </article>
        ))}
      </section>

      <section style={heroCardStyle}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            gap: '12px',
            flexWrap: 'wrap',
            alignItems: 'center',
          }}
        >
          <div>
            <h3 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2, color: '#0f172a' }}>
              Save Personal Configuration
            </h3>
            <p style={{ margin: '8px 0 0', fontSize: '14px', lineHeight: 1.7, color: '#475569' }}>
              This is the one authoritative save action for Family Review, Field Configuration, and
              Section Builder.
            </p>
          </div>
          <button
            type="button"
            style={saving || !hasChanges ? disabledButtonStyle : buttonStyle}
            disabled={saving || !hasChanges}
            onClick={() => {
              void handleSave();
            }}
          >
            {saving ? 'Saving…' : latestServer.saveActionLabel}
          </button>
        </div>
      </section>
    </div>
  );
}
