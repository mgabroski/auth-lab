'use client';

import { useMemo, useState, type CSSProperties } from 'react';

import { getApiErrorMessage } from '@/shared/auth/api-errors';
import {
  saveAccountBranding,
  saveAccountCalendar,
  saveAccountOrgStructure,
} from '@/shared/settings/browser-api';
import { SettingsStatusChip } from '@/shared/settings/components/settings-status-chip';
import type {
  AccountBrandingCardResponse,
  AccountCalendarCardResponse,
  AccountOrgStructureCardResponse,
  AccountSettingsCardResponse,
  AccountSettingsResponse,
  SettingsMutationResultResponse,
  SettingsSetupStatus,
} from '@/shared/settings/contracts';

const pageStackStyle: CSSProperties = {
  display: 'grid',
  gap: '18px',
};

const heroCardStyle: CSSProperties = {
  display: 'grid',
  gap: '12px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -28px rgba(15, 23, 42, 0.35)',
};

const cardStyle: CSSProperties = {
  display: 'grid',
  gap: '16px',
  padding: '20px',
  borderRadius: '20px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  backgroundColor: '#ffffff',
  boxShadow: '0 18px 40px -28px rgba(15, 23, 42, 0.35)',
};

const noticeBaseStyle: CSSProperties = {
  display: 'grid',
  gap: '8px',
  padding: '14px 16px',
  borderRadius: '16px',
  border: '1px solid transparent',
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

const mutedTextStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.7,
  color: '#475569',
};

const labelStyle: CSSProperties = {
  display: 'grid',
  gap: '8px',
  fontSize: '14px',
  fontWeight: 600,
  color: '#0f172a',
};

const inputStyle: CSSProperties = {
  width: '100%',
  minHeight: '44px',
  padding: '10px 12px',
  borderRadius: '14px',
  border: '1px solid #cbd5e1',
  backgroundColor: '#ffffff',
  color: '#0f172a',
  fontSize: '14px',
};

const textareaStyle: CSSProperties = {
  ...inputStyle,
  minHeight: '112px',
  resize: 'vertical',
};

const buttonStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  minHeight: '44px',
  padding: '0 18px',
  borderRadius: '14px',
  border: '1px solid #1d4ed8',
  backgroundColor: '#1d4ed8',
  color: '#ffffff',
  fontSize: '14px',
  fontWeight: 700,
  cursor: 'pointer',
};

const disabledButtonStyle: CSSProperties = {
  ...buttonStyle,
  borderColor: '#cbd5e1',
  backgroundColor: '#e2e8f0',
  color: '#64748b',
  cursor: 'not-allowed',
};

type AccountCardState = {
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
  successMessage: string | null;
  errorMessage: string | null;
  pending: boolean;
};

function defaultCardState(card: AccountSettingsCardResponse): AccountCardState {
  return {
    status: card.status,
    version: card.version,
    cpRevision: card.cpRevision,
    successMessage: null,
    errorMessage: null,
    pending: false,
  };
}

function linesToList(value: string): string[] {
  return value
    .split('\n')
    .map((item) => item.trim())
    .filter((item, index, source) => item.length > 0 && source.indexOf(item) === index);
}

function listToLines(values: string[]): string {
  return values.join('\n');
}

type AccountSettingsFormProps = {
  initialData: AccountSettingsResponse;
};

export function AccountSettingsForm({ initialData }: AccountSettingsFormProps) {
  const brandingCard = useMemo(
    () =>
      initialData.cards.find(
        (card): card is AccountBrandingCardResponse => card.key === 'branding',
      ),
    [initialData.cards],
  );
  const orgCard = useMemo(
    () =>
      initialData.cards.find(
        (card): card is AccountOrgStructureCardResponse => card.key === 'orgStructure',
      ),
    [initialData.cards],
  );
  const calendarCard = useMemo(
    () =>
      initialData.cards.find(
        (card): card is AccountCalendarCardResponse => card.key === 'calendar',
      ),
    [initialData.cards],
  );

  const [brandingState, setBrandingState] = useState(() =>
    brandingCard
      ? {
          card: defaultCardState(brandingCard),
          values: {
            logoUrl: brandingCard.values.logoUrl ?? '',
            menuColor: brandingCard.values.menuColor ?? '',
            fontColor: brandingCard.values.fontColor ?? '',
            welcomeMessage: brandingCard.values.welcomeMessage ?? '',
          },
        }
      : null,
  );

  const [orgState, setOrgState] = useState(() =>
    orgCard
      ? {
          card: defaultCardState(orgCard),
          values: {
            employers: listToLines(orgCard.values.employers),
            locations: listToLines(orgCard.values.locations),
          },
        }
      : null,
  );

  const [calendarState, setCalendarState] = useState(() =>
    calendarCard
      ? {
          card: defaultCardState(calendarCard),
          values: {
            observedDates: listToLines(calendarCard.values.observedDates),
          },
        }
      : null,
  );

  const applyMutation = (
    current: AccountCardState,
    mutation: SettingsMutationResultResponse,
    successMessage: string,
  ): AccountCardState => ({
    ...current,
    status: mutation.card?.status ?? current.status,
    version: mutation.card?.version ?? current.version,
    cpRevision: mutation.card?.cpRevision ?? current.cpRevision,
    pending: false,
    errorMessage: null,
    successMessage,
  });

  const saveBrandingCard = async () => {
    if (!brandingState) return;

    setBrandingState((current) =>
      current
        ? {
            ...current,
            card: {
              ...current.card,
              pending: true,
              errorMessage: null,
              successMessage: null,
            },
          }
        : current,
    );

    try {
      const result = await saveAccountBranding({
        expectedVersion: brandingState.card.version,
        expectedCpRevision: brandingState.card.cpRevision,
        values: {
          logoUrl: brandingState.values.logoUrl.trim() || null,
          menuColor: brandingState.values.menuColor.trim() || null,
          fontColor: brandingState.values.fontColor.trim() || null,
          welcomeMessage: brandingState.values.welcomeMessage.trim() || null,
        },
      });

      if (!result.ok) {
        setBrandingState((current) =>
          current
            ? {
                ...current,
                card: {
                  ...current.card,
                  pending: false,
                  errorMessage: getApiErrorMessage(result.error, 'Unable to save Branding.'),
                },
              }
            : current,
        );
        return;
      }

      setBrandingState((current) =>
        current
          ? {
              ...current,
              card: applyMutation(current.card, result.data, 'Branding was saved.'),
            }
          : current,
      );
    } catch (error) {
      setBrandingState((current) =>
        current
          ? {
              ...current,
              card: {
                ...current.card,
                pending: false,
                errorMessage: getApiErrorMessage(error, 'Unable to save Branding.'),
              },
            }
          : current,
      );
    }
  };

  const saveOrgCard = async () => {
    if (!orgState) return;

    setOrgState((current) =>
      current
        ? {
            ...current,
            card: {
              ...current.card,
              pending: true,
              errorMessage: null,
              successMessage: null,
            },
          }
        : current,
    );

    try {
      const result = await saveAccountOrgStructure({
        expectedVersion: orgState.card.version,
        expectedCpRevision: orgState.card.cpRevision,
        values: {
          employers: linesToList(orgState.values.employers),
          locations: linesToList(orgState.values.locations),
        },
      });

      if (!result.ok) {
        setOrgState((current) =>
          current
            ? {
                ...current,
                card: {
                  ...current.card,
                  pending: false,
                  errorMessage: getApiErrorMessage(
                    result.error,
                    'Unable to save Organization Structure.',
                  ),
                },
              }
            : current,
        );
        return;
      }

      setOrgState((current) =>
        current
          ? {
              ...current,
              values: {
                employers: listToLines(linesToList(current.values.employers)),
                locations: listToLines(linesToList(current.values.locations)),
              },
              card: applyMutation(current.card, result.data, 'Organization Structure was saved.'),
            }
          : current,
      );
    } catch (error) {
      setOrgState((current) =>
        current
          ? {
              ...current,
              card: {
                ...current.card,
                pending: false,
                errorMessage: getApiErrorMessage(error, 'Unable to save Organization Structure.'),
              },
            }
          : current,
      );
    }
  };

  const saveCalendarCard = async () => {
    if (!calendarState) return;

    setCalendarState((current) =>
      current
        ? {
            ...current,
            card: {
              ...current.card,
              pending: true,
              errorMessage: null,
              successMessage: null,
            },
          }
        : current,
    );

    try {
      const result = await saveAccountCalendar({
        expectedVersion: calendarState.card.version,
        expectedCpRevision: calendarState.card.cpRevision,
        values: {
          observedDates: linesToList(calendarState.values.observedDates),
        },
      });

      if (!result.ok) {
        setCalendarState((current) =>
          current
            ? {
                ...current,
                card: {
                  ...current.card,
                  pending: false,
                  errorMessage: getApiErrorMessage(
                    result.error,
                    'Unable to save Company Calendar.',
                  ),
                },
              }
            : current,
        );
        return;
      }

      setCalendarState((current) =>
        current
          ? {
              ...current,
              values: {
                observedDates: listToLines(linesToList(current.values.observedDates)),
              },
              card: applyMutation(current.card, result.data, 'Company Calendar was saved.'),
            }
          : current,
      );
    } catch (error) {
      setCalendarState((current) =>
        current
          ? {
              ...current,
              card: {
                ...current.card,
                pending: false,
                errorMessage: getApiErrorMessage(error, 'Unable to save Company Calendar.'),
              },
            }
          : current,
      );
    }
  };

  return (
    <div style={pageStackStyle}>
      <section style={heroCardStyle}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <h2 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2, color: '#0f172a' }}>
            {initialData.title}
          </h2>
          <SettingsStatusChip status={initialData.status} />
        </div>
        <p style={mutedTextStyle}>{initialData.description}</p>
      </section>

      {brandingState ? (
        <section style={cardStyle}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            <h3 style={{ margin: 0, fontSize: '18px', lineHeight: 1.2, color: '#0f172a' }}>
              {brandingCard?.title}
            </h3>
            <SettingsStatusChip status={brandingState.card.status} />
          </div>
          <p style={mutedTextStyle}>{brandingCard?.description}</p>
          <p style={{ ...mutedTextStyle, fontSize: '13px' }}>
            Version: {brandingState.card.version} · cpRevision: {brandingState.card.cpRevision}
          </p>
          <div style={{ display: 'grid', gap: '14px' }}>
            {brandingCard?.visibility.logo ? (
              <label style={labelStyle}>
                Logo URL
                <input
                  style={inputStyle}
                  value={brandingState.values.logoUrl}
                  onChange={(event) =>
                    setBrandingState((current) =>
                      current
                        ? { ...current, values: { ...current.values, logoUrl: event.target.value } }
                        : current,
                    )
                  }
                />
              </label>
            ) : null}
            {brandingCard?.visibility.menuColor ? (
              <label style={labelStyle}>
                Menu Color
                <input
                  style={inputStyle}
                  placeholder="#0f172a"
                  value={brandingState.values.menuColor}
                  onChange={(event) =>
                    setBrandingState((current) =>
                      current
                        ? {
                            ...current,
                            values: { ...current.values, menuColor: event.target.value },
                          }
                        : current,
                    )
                  }
                />
              </label>
            ) : null}
            {brandingCard?.visibility.fontColor ? (
              <label style={labelStyle}>
                Font Color
                <input
                  style={inputStyle}
                  placeholder="#ffffff"
                  value={brandingState.values.fontColor}
                  onChange={(event) =>
                    setBrandingState((current) =>
                      current
                        ? {
                            ...current,
                            values: { ...current.values, fontColor: event.target.value },
                          }
                        : current,
                    )
                  }
                />
              </label>
            ) : null}
            {brandingCard?.visibility.welcomeMessage ? (
              <label style={labelStyle}>
                Welcome Message
                <textarea
                  style={textareaStyle}
                  value={brandingState.values.welcomeMessage}
                  onChange={(event) =>
                    setBrandingState((current) =>
                      current
                        ? {
                            ...current,
                            values: {
                              ...current.values,
                              welcomeMessage: event.target.value,
                            },
                          }
                        : current,
                    )
                  }
                />
              </label>
            ) : null}
          </div>
          {brandingState.card.successMessage ? (
            <div style={successNoticeStyle}>{brandingState.card.successMessage}</div>
          ) : null}
          {brandingState.card.errorMessage ? (
            <div style={errorNoticeStyle}>{brandingState.card.errorMessage}</div>
          ) : null}
          <div>
            <button
              type="button"
              style={brandingState.card.pending ? disabledButtonStyle : buttonStyle}
              disabled={brandingState.card.pending}
              onClick={() => {
                void saveBrandingCard();
              }}
            >
              {brandingState.card.pending ? 'Saving…' : 'Save Branding'}
            </button>
          </div>
        </section>
      ) : null}

      {orgState ? (
        <section style={cardStyle}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            <h3 style={{ margin: 0, fontSize: '18px', lineHeight: 1.2, color: '#0f172a' }}>
              {orgCard?.title}
            </h3>
            <SettingsStatusChip status={orgState.card.status} />
          </div>
          <p style={mutedTextStyle}>{orgCard?.description}</p>
          <p style={{ ...mutedTextStyle, fontSize: '13px' }}>
            Version: {orgState.card.version} · cpRevision: {orgState.card.cpRevision}
          </p>
          <div style={{ display: 'grid', gap: '14px' }}>
            {orgCard?.visibility.employers ? (
              <label style={labelStyle}>
                Employers (one per line)
                <textarea
                  style={textareaStyle}
                  value={orgState.values.employers}
                  onChange={(event) =>
                    setOrgState((current) =>
                      current
                        ? {
                            ...current,
                            values: { ...current.values, employers: event.target.value },
                          }
                        : current,
                    )
                  }
                />
              </label>
            ) : null}
            {orgCard?.visibility.locations ? (
              <label style={labelStyle}>
                Locations (one per line)
                <textarea
                  style={textareaStyle}
                  value={orgState.values.locations}
                  onChange={(event) =>
                    setOrgState((current) =>
                      current
                        ? {
                            ...current,
                            values: { ...current.values, locations: event.target.value },
                          }
                        : current,
                    )
                  }
                />
              </label>
            ) : null}
          </div>
          {orgState.card.successMessage ? (
            <div style={successNoticeStyle}>{orgState.card.successMessage}</div>
          ) : null}
          {orgState.card.errorMessage ? (
            <div style={errorNoticeStyle}>{orgState.card.errorMessage}</div>
          ) : null}
          <div>
            <button
              type="button"
              style={orgState.card.pending ? disabledButtonStyle : buttonStyle}
              disabled={orgState.card.pending}
              onClick={() => {
                void saveOrgCard();
              }}
            >
              {orgState.card.pending ? 'Saving…' : 'Save Organization Structure'}
            </button>
          </div>
        </section>
      ) : null}

      {calendarState ? (
        <section style={cardStyle}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            <h3 style={{ margin: 0, fontSize: '18px', lineHeight: 1.2, color: '#0f172a' }}>
              {calendarCard?.title}
            </h3>
            <SettingsStatusChip status={calendarState.card.status} />
          </div>
          <p style={mutedTextStyle}>{calendarCard?.description}</p>
          <p style={{ ...mutedTextStyle, fontSize: '13px' }}>
            Version: {calendarState.card.version} · cpRevision: {calendarState.card.cpRevision}
          </p>
          <label style={labelStyle}>
            Observed company dates (one YYYY-MM-DD per line)
            <textarea
              style={textareaStyle}
              value={calendarState.values.observedDates}
              onChange={(event) =>
                setCalendarState((current) =>
                  current
                    ? {
                        ...current,
                        values: { ...current.values, observedDates: event.target.value },
                      }
                    : current,
                )
              }
            />
          </label>
          {calendarState.card.successMessage ? (
            <div style={successNoticeStyle}>{calendarState.card.successMessage}</div>
          ) : null}
          {calendarState.card.errorMessage ? (
            <div style={errorNoticeStyle}>{calendarState.card.errorMessage}</div>
          ) : null}
          <div>
            <button
              type="button"
              style={calendarState.card.pending ? disabledButtonStyle : buttonStyle}
              disabled={calendarState.card.pending}
              onClick={() => {
                void saveCalendarCard();
              }}
            >
              {calendarState.card.pending ? 'Saving…' : 'Save Company Calendar'}
            </button>
          </div>
        </section>
      ) : null}
    </div>
  );
}
