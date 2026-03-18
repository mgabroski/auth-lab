/**
 * frontend/test/e2e/helpers/mailpit.ts
 *
 * WHY:
 * - Real-stack E2E tests need to read emails delivered by the backend through
 *   the real outbox → SMTP → Mailpit pipeline.
 * - Mailpit exposes an HTTP API for programmatic inspection without needing a
 *   browser or IMAP client.
 * - This helper is the single place where Mailpit API URLs and polling logic live,
 *   so tests stay readable and the API surface is not scattered across spec files.
 *
 * MAILPIT API USED:
 *   DELETE /api/v1/messages         — purge all messages (before test)
 *   GET    /api/v1/messages         — list messages (poll for arrival)
 *   GET    /api/v1/message/:id      — get message detail with text body
 *
 * RULES:
 * - Only used by real-stack E2E tests.  Never imported by unit tests.
 * - MAILPIT_API_URL env var overrides the default for non-standard setups.
 * - Polling uses a 30-second deadline to tolerate outbox worker poll interval
 *   (default 5 s) plus SMTP delivery time.
 */

const MAILPIT_BASE = (process.env.MAILPIT_API_URL ?? 'http://localhost:8025').replace(/\/+$/, '');
const POLL_DEADLINE_MS = 30_000;
const POLL_INTERVAL_MS = 1_000;

// ─── Types ────────────────────────────────────────────────────────────────────

type MailpitAddress = {
  Address: string;
  Name: string;
};

type MailpitMessage = {
  ID: string;
  From: MailpitAddress;
  To: MailpitAddress[];
  Subject: string;
  Created: string;
};

type MailpitListResponse = {
  messages: MailpitMessage[] | null;
  messages_count: number;
  total: number;
};

type MailpitMessageDetail = {
  ID: string;
  From: MailpitAddress;
  To: MailpitAddress[];
  Subject: string;
  Created: string;
  /** Plain-text body.  Token links are embedded here. */
  Text: string;
};

// ─── API helpers ──────────────────────────────────────────────────────────────

async function mailpitFetch(path: string, init?: RequestInit): Promise<Response> {
  const res = await fetch(`${MAILPIT_BASE}${path}`, init);

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Mailpit API error ${res.status} ${path}: ${body}`);
  }

  return res;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Delete all messages in Mailpit.
 *
 * Call this at the start of any test that reads from Mailpit so emails from
 * previous test runs cannot interfere.
 */
export async function purgeMailpit(): Promise<void> {
  await mailpitFetch('/api/v1/messages', { method: 'DELETE' });
}

/**
 * Poll Mailpit until an email addressed to `recipientEmail` arrives, then
 * return the full message detail including the plain-text body.
 *
 * Throws if no matching email arrives within POLL_DEADLINE_MS (30 s).
 *
 * WHY polling: the backend outbox worker runs on a configurable interval
 * (default 5 s in local/CI config).  The email is not delivered synchronously
 * with the API call that triggers it.
 */
export async function waitForEmailToRecipient(
  recipientEmail: string,
): Promise<MailpitMessageDetail> {
  const deadline = Date.now() + POLL_DEADLINE_MS;
  const normalized = recipientEmail.toLowerCase();

  while (Date.now() < deadline) {
    const res = await mailpitFetch('/api/v1/messages?limit=50');
    const data = (await res.json()) as MailpitListResponse;

    const messages = data.messages ?? [];
    const match = messages.find((m) => m.To.some((t) => t.Address.toLowerCase() === normalized));

    if (match) {
      const detailRes = await mailpitFetch(`/api/v1/message/${match.ID}`);
      return (await detailRes.json()) as MailpitMessageDetail;
    }

    await sleep(POLL_INTERVAL_MS);
  }

  throw new Error(
    `[mailpit] No email addressed to '${recipientEmail}' arrived within ${POLL_DEADLINE_MS} ms. ` +
      'Check: outbox worker is running, SMTP env points to Mailpit, backend sent the message.',
  );
}

/**
 * Extract the first URL from the message text that contains `pathFragment`.
 *
 * Examples:
 *   extractLinkFromText(text, '/verify-email?token=')  → full verify URL
 *   extractLinkFromText(text, '/auth/reset-password?token=') → full reset URL
 *   extractLinkFromText(text, '/accept-invite?token=') → full invite URL
 */
export function extractLinkFromText(text: string, pathFragment: string): string {
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.includes(pathFragment)) {
      // Validate: must look like an http URL.
      if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
        return trimmed;
      }
    }
  }

  throw new Error(
    `[mailpit] Could not find a URL containing '${pathFragment}' in email text:\n\n${text}`,
  );
}

// ─── Internal ─────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
