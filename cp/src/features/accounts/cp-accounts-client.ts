'use client';

/**
 * cp/src/features/accounts/cp-accounts-client.ts
 *
 * WHY:
 * - Client-side same-origin API helpers for CP create/edit/review mutations.
 * - Keeps /api/* fetch details out of UI components.
 */

import type {
  ControlPlaneAccountDetail,
  ControlPlaneAccountReview,
  CreateCpAccountInput,
  PublishCpAccountInput,
  SaveCpAccessInput,
  SaveCpAccountSettingsInput,
  SaveCpIntegrationsInput,
  SaveCpModuleSettingsInput,
  SaveCpPersonalInput,
  UpdateCpAccountStatusInput,
} from './contracts';

type ErrorEnvelopeBody = {
  error?: {
    code?: string;
    message?: string;
  };
};

function isErrorEnvelopeBody(value: unknown): value is ErrorEnvelopeBody {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const candidate = value as Record<string, unknown>;
  const error = candidate['error'];

  if (error !== undefined && (typeof error !== 'object' || error === null)) {
    return false;
  }

  if (
    error &&
    typeof (error as Record<string, unknown>)['message'] !== 'undefined' &&
    typeof (error as Record<string, unknown>)['message'] !== 'string'
  ) {
    return false;
  }

  return true;
}

async function readJsonBody(res: Response): Promise<unknown> {
  const text = await res.text();

  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

function resolveErrorMessage(status: number, body: unknown): string {
  if (isErrorEnvelopeBody(body) && typeof body.error?.message === 'string') {
    return body.error.message;
  }

  return `Request failed (${status})`;
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init?.headers ?? {}),
    },
  });

  const body = await readJsonBody(res);

  if (!res.ok) {
    throw new Error(resolveErrorMessage(res.status, body));
  }

  return body as T;
}

export function createCpAccount(input: CreateCpAccountInput): Promise<ControlPlaneAccountDetail> {
  return requestJson<ControlPlaneAccountDetail>('/api/cp/accounts', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
}

export function saveCpAccess(
  accountKey: string,
  input: SaveCpAccessInput,
): Promise<ControlPlaneAccountDetail> {
  return requestJson<ControlPlaneAccountDetail>(
    `/api/cp/accounts/${encodeURIComponent(accountKey)}/access`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
}

export function saveCpAccountSettings(
  accountKey: string,
  input: SaveCpAccountSettingsInput,
): Promise<ControlPlaneAccountDetail> {
  return requestJson<ControlPlaneAccountDetail>(
    `/api/cp/accounts/${encodeURIComponent(accountKey)}/account-settings`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
}

export function saveCpModuleSettings(
  accountKey: string,
  input: SaveCpModuleSettingsInput,
): Promise<ControlPlaneAccountDetail> {
  return requestJson<ControlPlaneAccountDetail>(
    `/api/cp/accounts/${encodeURIComponent(accountKey)}/modules`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
}

export function saveCpPersonal(
  accountKey: string,
  input: SaveCpPersonalInput,
): Promise<ControlPlaneAccountDetail> {
  return requestJson<ControlPlaneAccountDetail>(
    `/api/cp/accounts/${encodeURIComponent(accountKey)}/modules/personal`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
}

export function saveCpIntegrations(
  accountKey: string,
  input: SaveCpIntegrationsInput,
): Promise<ControlPlaneAccountDetail> {
  return requestJson<ControlPlaneAccountDetail>(
    `/api/cp/accounts/${encodeURIComponent(accountKey)}/integrations`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
}

export function publishCpAccount(
  accountKey: string,
  input: PublishCpAccountInput,
): Promise<ControlPlaneAccountReview> {
  return requestJson<ControlPlaneAccountReview>(
    `/api/cp/accounts/${encodeURIComponent(accountKey)}/publish`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
}

export function updateCpAccountStatus(
  accountKey: string,
  input: UpdateCpAccountStatusInput,
): Promise<ControlPlaneAccountDetail> {
  return requestJson<ControlPlaneAccountDetail>(
    `/api/cp/accounts/${encodeURIComponent(accountKey)}/status`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
}
