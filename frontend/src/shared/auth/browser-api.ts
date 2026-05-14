/**
 * frontend/src/shared/auth/browser-api.ts
 *
 * WHY:
 * - Centralizes browser-side auth requests around the locked same-origin `/api/*` rule.
 * - Gives auth and invite/provisioning flows a thin, reusable API layer instead of hand-written fetch logic.
 * - Preserves backend-owned auth/session truth by returning real backend payloads and errors.
 *
 * RULES:
 * - Browser-only helper layer. Uses apiFetch() and never calls INTERNAL_API_URL directly.
 * - SSO start is intentionally NOT implemented here; use shared/auth/sso.ts.
 * - Returns structured success/error results so pages can stay thin and banner-friendly.
 */

import { apiFetch } from '@/shared/api-client';
import { readApiError, type ApiHttpError } from './api-errors';
import type {
  AcceptInviteRequest,
  AcceptInviteResponse,
  AuthResult,
  AuthResultWire,
  CancelAdminInviteResponse,
  ConfigResponse,
  CreateAdminInviteRequest,
  CreateAdminInviteResponse,
  CreateAdminInviteResponseWire,
  ForgotPasswordRequest,
  ForgotPasswordResponse,
  ListAdminInvitesRequest,
  ListAdminInvitesResponse,
  ListAdminInvitesResponseWire,
  LoginRequest,
  LogoutResponse,
  MeResponse,
  MeResponseWire,
  MfaCodeRequest,
  MfaRecoverRequest,
  MfaSetupResponse,
  MfaVerifyResponse,
  RegisterRequest,
  ResendAdminInviteResponse,
  ResendAdminInviteResponseWire,
  ResendVerificationResponse,
  ResetPasswordRequest,
  ResetPasswordResponse,
  SignupRequest,
  VerifyEmailRequest,
  VerifyEmailResponse,
} from './contracts';
import {
  normalizeAuthResult,
  normalizeCreateAdminInviteResponse,
  normalizeListAdminInvitesResponse,
  normalizeMeResponse,
  normalizeResendAdminInviteResponse,
} from './contracts';

export type BrowserAuthSuccess<T> = {
  ok: true;
  status: number;
  data: T;
};

export type BrowserAuthFailure = {
  ok: false;
  status: number;
  error: ApiHttpError;
};

export type BrowserAuthResult<T> = BrowserAuthSuccess<T> | BrowserAuthFailure;

type JsonBody = Record<string, unknown> | undefined;

async function requestJson<T>(path: string, init?: RequestInit): Promise<BrowserAuthResult<T>> {
  const response = await apiFetch(path, init);

  if (!response.ok) {
    const error = await readApiError(response);
    return {
      ok: false,
      status: response.status,
      error,
    };
  }

  const data = (await response.json()) as T;

  return {
    ok: true,
    status: response.status,
    data,
  };
}

function mapBrowserAuthResult<TInput, TOutput>(
  result: BrowserAuthResult<TInput>,
  mapper: (input: TInput) => TOutput,
): BrowserAuthResult<TOutput> {
  if (!result.ok) {
    return result;
  }

  return {
    ...result,
    data: mapper(result.data),
  };
}

function jsonRequest<T>(
  path: string,
  method: 'GET' | 'POST' | 'DELETE',
  body?: JsonBody,
): Promise<BrowserAuthResult<T>> {
  return requestJson<T>(path, {
    method,
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
}

export function getAuthConfig(): Promise<BrowserAuthResult<ConfigResponse>> {
  return jsonRequest<ConfigResponse>('/auth/config', 'GET');
}

export async function getAuthMe(): Promise<BrowserAuthResult<MeResponse>> {
  const result = await jsonRequest<MeResponseWire>('/auth/me', 'GET');
  return mapBrowserAuthResult(result, normalizeMeResponse);
}

export function acceptInvite(
  input: AcceptInviteRequest,
): Promise<BrowserAuthResult<AcceptInviteResponse>> {
  return jsonRequest<AcceptInviteResponse>('/auth/invites/accept', 'POST', input);
}

export async function login(input: LoginRequest): Promise<BrowserAuthResult<AuthResult>> {
  const result = await jsonRequest<AuthResultWire>('/auth/login', 'POST', input);
  return mapBrowserAuthResult(result, normalizeAuthResult);
}

export async function registerWithInvite(
  input: RegisterRequest,
): Promise<BrowserAuthResult<AuthResult>> {
  const result = await jsonRequest<AuthResultWire>('/auth/register', 'POST', input);
  return mapBrowserAuthResult(result, normalizeAuthResult);
}

export async function signup(input: SignupRequest): Promise<BrowserAuthResult<AuthResult>> {
  const result = await jsonRequest<AuthResultWire>('/auth/signup', 'POST', input);
  return mapBrowserAuthResult(result, normalizeAuthResult);
}

export function requestPasswordReset(
  input: ForgotPasswordRequest,
): Promise<BrowserAuthResult<ForgotPasswordResponse>> {
  return jsonRequest<ForgotPasswordResponse>('/auth/forgot-password', 'POST', input);
}

export function resetPassword(
  input: ResetPasswordRequest,
): Promise<BrowserAuthResult<ResetPasswordResponse>> {
  return jsonRequest<ResetPasswordResponse>('/auth/reset-password', 'POST', input);
}

export function verifyEmail(
  input: VerifyEmailRequest,
): Promise<BrowserAuthResult<VerifyEmailResponse>> {
  return jsonRequest<VerifyEmailResponse>('/auth/verify-email', 'POST', input);
}

export function resendVerification(): Promise<BrowserAuthResult<ResendVerificationResponse>> {
  return jsonRequest<ResendVerificationResponse>('/auth/resend-verification', 'POST');
}

export function setupMfa(): Promise<BrowserAuthResult<MfaSetupResponse>> {
  return jsonRequest<MfaSetupResponse>('/auth/mfa/setup', 'POST');
}

export function verifyMfaSetup(
  input: MfaCodeRequest,
): Promise<BrowserAuthResult<MfaVerifyResponse>> {
  return jsonRequest<MfaVerifyResponse>('/auth/mfa/verify-setup', 'POST', input);
}

export function verifyMfa(input: MfaCodeRequest): Promise<BrowserAuthResult<MfaVerifyResponse>> {
  return jsonRequest<MfaVerifyResponse>('/auth/mfa/verify', 'POST', input);
}

export function recoverMfa(
  input: MfaRecoverRequest,
): Promise<BrowserAuthResult<MfaVerifyResponse>> {
  return jsonRequest<MfaVerifyResponse>('/auth/mfa/recover', 'POST', input);
}

export function logout(): Promise<BrowserAuthResult<LogoutResponse>> {
  return jsonRequest<LogoutResponse>('/auth/logout', 'POST');
}

export async function createAdminInvite(
  input: CreateAdminInviteRequest,
): Promise<BrowserAuthResult<CreateAdminInviteResponse>> {
  const result = await jsonRequest<CreateAdminInviteResponseWire>('/admin/invites', 'POST', input);
  return mapBrowserAuthResult(result, normalizeCreateAdminInviteResponse);
}

export async function listAdminInvites(
  input: ListAdminInvitesRequest,
): Promise<BrowserAuthResult<ListAdminInvitesResponse>> {
  const params = new URLSearchParams();

  if (input.limit !== undefined) {
    params.set('limit', String(input.limit));
  }

  if (input.offset !== undefined) {
    params.set('offset', String(input.offset));
  }

  if (input.status !== undefined) {
    params.set('status', input.status);
  }

  const query = params.toString();
  const path = query ? `/admin/invites?${query}` : '/admin/invites';

  const result = await jsonRequest<ListAdminInvitesResponseWire>(path, 'GET');
  return mapBrowserAuthResult(result, normalizeListAdminInvitesResponse);
}

export async function resendAdminInvite(
  inviteId: string,
): Promise<BrowserAuthResult<ResendAdminInviteResponse>> {
  const result = await jsonRequest<ResendAdminInviteResponseWire>(
    `/admin/invites/${inviteId}/resend`,
    'POST',
  );
  return mapBrowserAuthResult(result, normalizeResendAdminInviteResponse);
}

export function cancelAdminInvite(
  inviteId: string,
): Promise<BrowserAuthResult<CancelAdminInviteResponse>> {
  return jsonRequest<CancelAdminInviteResponse>(`/admin/invites/${inviteId}`, 'DELETE');
}
