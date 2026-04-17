import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  createCpAccount,
  saveCpAccess,
  updateCpAccountStatus,
} from '../../../../src/features/accounts/cp-accounts-client';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('cp-accounts-client', () => {
  it('sends same-origin JSON mutations to the CP backend proxy', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          id: 'cp-account-1',
          accountName: 'QA Tenant',
          accountKey: 'qa-tenant',
        }),
        {
          status: 201,
          headers: {
            'Content-Type': 'application/json',
          },
        },
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      createCpAccount({
        accountName: 'QA Tenant',
        accountKey: 'qa-tenant',
      }),
    ).resolves.toMatchObject({
      accountKey: 'qa-tenant',
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/api/cp/accounts');
    expect(init.method).toBe('POST');

    const headers = new Headers(init.headers);
    expect(headers.get('Accept')).toBe('application/json');
    expect(headers.get('Content-Type')).toBe('application/json');
    expect(init.body).toBe(
      JSON.stringify({
        accountName: 'QA Tenant',
        accountKey: 'qa-tenant',
      }),
    );
  });

  it('URL-encodes account keys for nested mutations', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          id: 'cp-account-1',
          accountName: 'QA Tenant',
          accountKey: 'qa-tenant',
        }),
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
        },
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      saveCpAccess('tenant with spaces/1', {
        loginMethods: {
          password: true,
          google: false,
          microsoft: false,
        },
        mfaPolicy: {
          adminRequired: true,
          memberRequired: false,
        },
        signupPolicy: {
          publicSignup: false,
          adminInvitationsAllowed: true,
          allowedDomains: [],
        },
      }),
    ).resolves.toBeDefined();

    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [path] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/api/cp/accounts/tenant%20with%20spaces%2F1/access');
  });

  it('surfaces the real backend message from the structured error envelope', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          error: {
            code: 'CONFLICT',
            message:
              'Google login method requires the Google SSO integration allowance to be saved first.',
          },
        }),
        {
          status: 409,
          headers: {
            'Content-Type': 'application/json',
          },
        },
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      updateCpAccountStatus('qa-tenant', {
        targetStatus: 'Active',
      }),
    ).rejects.toThrow(
      'Google login method requires the Google SSO integration allowance to be saved first.',
    );
  });

  it('falls back to a generic status-based message when the response is malformed or legacy-flat', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ message: 'legacy-flat-message-should-not-leak' }), {
          status: 409,
          headers: {
            'Content-Type': 'application/json',
          },
        }),
      )
      .mockResolvedValueOnce(
        new Response('not-json', {
          status: 404,
          headers: {
            'Content-Type': 'text/plain',
          },
        }),
      );
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      updateCpAccountStatus('qa-tenant', {
        targetStatus: 'Disabled',
      }),
    ).rejects.toThrow('Request failed (409)');

    await expect(
      updateCpAccountStatus('qa-tenant', {
        targetStatus: 'Disabled',
      }),
    ).rejects.toThrow('Request failed (404)');
  });
});
