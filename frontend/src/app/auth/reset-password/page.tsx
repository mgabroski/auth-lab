/**
 * frontend/src/app/reset-password/page.tsx
 *
 * WHY:
 * - Matches the backend reset-email link contract (`/reset-password?token=...`).
 * - Preserves the existing Phase 3 screen implementation under `/auth/reset-password`.
 */

import { redirect } from 'next/navigation';
import { AUTH_RESET_PASSWORD_PATH } from '@/shared/auth/redirects';
import { getResetPasswordToken, type SearchParamsRecord } from '@/shared/auth/url-tokens';

export const dynamic = 'force-dynamic';

type PageProps = {
  searchParams: Promise<SearchParamsRecord>;
};

export default async function ResetPasswordAliasPage({ searchParams }: PageProps) {
  const resolvedSearchParams = await searchParams;
  const token = getResetPasswordToken(resolvedSearchParams);

  if (token) {
    redirect(`${AUTH_RESET_PASSWORD_PATH}?token=${encodeURIComponent(token)}`);
  }

  redirect(AUTH_RESET_PASSWORD_PATH);
}
