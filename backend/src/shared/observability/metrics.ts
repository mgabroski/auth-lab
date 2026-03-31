/**
 * backend/src/shared/observability/metrics.ts
 *
 * WHY:
 * - Stage 3 needs real, scrapeable operability signals without forcing a metrics
 *   vendor choice yet.
 * - Provides a small in-repo Prometheus-text registry with disciplined, reusable,
 *   low-cardinality metric names and labels.
 *
 * RULES:
 * - Labels must remain low-cardinality.
 * - Never put requestId, tenantKey, userId, email, inviteId, or raw path params
 *   into metric labels.
 * - Dynamic routes must be normalized before metric recording.
 *
 * CURRENT SCOPE:
 * - request totals + request duration
 * - login failures
 * - invite failures
 * - password reset failures
 * - MFA failures
 * - SSO failures
 * - tenant-resolution failures
 * - SSR/bootstrap failures
 * - email delivery failures
 */

type LabelValue = string | number | boolean | null | undefined;
type MetricLabels = Record<string, LabelValue>;

type CounterSample = {
  value: number;
};

type HistogramSample = {
  buckets: number[];
  count: number;
  sum: number;
};

type CounterMetric = {
  kind: 'counter';
  name: string;
  help: string;
  labelNames: string[];
  samples: Map<string, CounterSample>;
};

type HistogramMetric = {
  kind: 'histogram';
  name: string;
  help: string;
  labelNames: string[];
  buckets: number[];
  samples: Map<string, HistogramSample>;
};

type RegisteredMetric = CounterMetric | HistogramMetric;

const HTTP_DURATION_BUCKETS_MS = [5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000];

function escapeLabelValue(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
}

function toMetricLabelValue(value: LabelValue): string {
  if (value === null || value === undefined) return 'unknown';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  return String(value);
}

function serializeLabelValues(labelNames: string[], labels: MetricLabels): string {
  return labelNames.map((name) => `${name}=${toMetricLabelValue(labels[name])}`).join('|');
}

function renderLabels(labelNames: string[], labels: MetricLabels): string {
  if (labelNames.length === 0) return '';

  const rendered = labelNames
    .map((name) => `${name}="${escapeLabelValue(toMetricLabelValue(labels[name]))}"`)
    .join(',');

  return `{${rendered}}`;
}

function parseSerializedLabels(serialized: string): MetricLabels {
  if (!serialized) return {};

  const out: MetricLabels = {};

  for (const part of serialized.split('|')) {
    const separatorIndex = part.indexOf('=');
    if (separatorIndex === -1) continue;

    const key = part.slice(0, separatorIndex);
    const value = part.slice(separatorIndex + 1);
    out[key] = value;
  }

  return out;
}

function statusClass(statusCode: number): '2xx' | '3xx' | '4xx' | '5xx' {
  if (statusCode >= 500) return '5xx';
  if (statusCode >= 400) return '4xx';
  if (statusCode >= 300) return '3xx';
  return '2xx';
}

function classifyReason(code: string, statusCode: number): string {
  if (code === 'RATE_LIMITED' || statusCode === 429) return 'rate_limited';
  if (code === 'UNAUTHORIZED' || statusCode === 401) return 'unauthorized';
  if (code === 'FORBIDDEN' || statusCode === 403) return 'forbidden';
  if (code === 'NOT_FOUND' || statusCode === 404) return 'not_found';
  if (code === 'CONFLICT' || statusCode === 409) return 'conflict';
  if (code === 'VALIDATION_ERROR' || statusCode === 400) return 'validation';
  if (code === 'INTERNAL' || statusCode >= 500) return 'unexpected';
  return 'other';
}

function firstHeaderValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function requestHeaderEquals(
  headers: Record<string, string | string[] | undefined>,
  name: string,
  expectedValue: string,
): boolean {
  const value = firstHeaderValue(headers[name]);
  return typeof value === 'string' && value.toLowerCase() === expectedValue.toLowerCase();
}

function normalizeInviteRoute(path: string): string {
  if (/^\/admin\/invites\/[^/]+\/resend$/.test(path)) return '/admin/invites/:inviteId/resend';
  if (/^\/admin\/invites\/[^/]+$/.test(path)) return '/admin/invites/:inviteId';
  return path;
}

export function normalizeMetricRouteFromUrl(url: string): string {
  const path = url.split('?')[0] ?? url;

  if (/^\/auth\/sso\/[^/]+\/callback$/.test(path)) {
    return '/auth/sso/:provider/callback';
  }

  if (/^\/auth\/sso\/[^/]+$/.test(path)) {
    return '/auth/sso/:provider';
  }

  return normalizeInviteRoute(path);
}

class MetricsRegistry {
  private readonly metrics = new Map<string, RegisteredMetric>();

  registerCounter(name: string, help: string, labelNames: string[] = []): CounterMetric {
    const metric: CounterMetric = {
      kind: 'counter',
      name,
      help,
      labelNames,
      samples: new Map<string, CounterSample>(),
    };

    this.metrics.set(name, metric);
    return metric;
  }

  registerHistogram(
    name: string,
    help: string,
    buckets: number[],
    labelNames: string[] = [],
  ): HistogramMetric {
    const metric: HistogramMetric = {
      kind: 'histogram',
      name,
      help,
      buckets: [...buckets].sort((a, b) => a - b),
      labelNames,
      samples: new Map<string, HistogramSample>(),
    };

    this.metrics.set(name, metric);
    return metric;
  }

  inc(metric: CounterMetric, labels: MetricLabels = {}, value = 1): void {
    const key = serializeLabelValues(metric.labelNames, labels);
    const existing = metric.samples.get(key);

    if (existing) {
      existing.value += value;
      return;
    }

    metric.samples.set(key, { value });
  }

  observe(metric: HistogramMetric, labels: MetricLabels = {}, value: number): void {
    const key = serializeLabelValues(metric.labelNames, labels);
    let sample = metric.samples.get(key);

    if (!sample) {
      sample = {
        buckets: metric.buckets.map(() => 0),
        count: 0,
        sum: 0,
      };
      metric.samples.set(key, sample);
    }

    sample.count += 1;
    sample.sum += value;

    for (let i = 0; i < metric.buckets.length; i += 1) {
      if (value <= metric.buckets[i]) {
        sample.buckets[i] += 1;
      }
    }
  }

  render(): string {
    const lines: string[] = [];

    for (const metric of this.metrics.values()) {
      lines.push(`# HELP ${metric.name} ${metric.help}`);
      lines.push(`# TYPE ${metric.name} ${metric.kind}`);

      if (metric.kind === 'counter') {
        for (const [serializedLabels, sample] of metric.samples.entries()) {
          const labels = parseSerializedLabels(serializedLabels);
          lines.push(`${metric.name}${renderLabels(metric.labelNames, labels)} ${sample.value}`);
        }
        continue;
      }

      for (const [serializedLabels, sample] of metric.samples.entries()) {
        const labels = parseSerializedLabels(serializedLabels);

        for (let i = 0; i < metric.buckets.length; i += 1) {
          const bucketLabels = {
            ...labels,
            le: metric.buckets[i],
          };

          lines.push(
            `${metric.name}_bucket${renderLabels([...metric.labelNames, 'le'], bucketLabels)} ${sample.buckets[i]}`,
          );
        }

        lines.push(
          `${metric.name}_bucket${renderLabels([...metric.labelNames, 'le'], { ...labels, le: '+Inf' })} ${sample.count}`,
        );
        lines.push(`${metric.name}_sum${renderLabels(metric.labelNames, labels)} ${sample.sum}`);
        lines.push(
          `${metric.name}_count${renderLabels(metric.labelNames, labels)} ${sample.count}`,
        );
      }
    }

    return `${lines.join('\n')}\n`;
  }
}

const registry = new MetricsRegistry();

const httpRequestsTotal = registry.registerCounter(
  'http_requests_total',
  'Total HTTP requests completed by normalized route, method, and status.',
  ['method', 'route', 'status', 'status_class'],
);

const httpRequestDurationMs = registry.registerHistogram(
  'http_request_duration_ms',
  'HTTP request duration in milliseconds by normalized route and method.',
  HTTP_DURATION_BUCKETS_MS,
  ['method', 'route', 'status_class'],
);

const authLoginFailuresTotal = registry.registerCounter(
  'auth_login_failures_total',
  'Total failed login attempts.',
  ['reason', 'code', 'status'],
);

const inviteFailuresTotal = registry.registerCounter(
  'invite_failures_total',
  'Total invite-related failures.',
  ['action', 'reason', 'code', 'status'],
);

const passwordResetFailuresTotal = registry.registerCounter(
  'password_reset_failures_total',
  'Total password reset request/confirm failures.',
  ['step', 'reason', 'code', 'status'],
);

const mfaFailuresTotal = registry.registerCounter(
  'mfa_failures_total',
  'Total MFA-related failures.',
  ['step', 'reason', 'code', 'status'],
);

const ssoFailuresTotal = registry.registerCounter(
  'sso_failures_total',
  'Total SSO-related failures.',
  ['step', 'provider', 'reason', 'code', 'status'],
);

const tenantResolutionFailuresTotal = registry.registerCounter(
  'tenant_resolution_failures_total',
  'Total tenant resolution failures observed in request handling.',
  ['route', 'reason', 'status'],
);

const ssrBootstrapFailuresTotal = registry.registerCounter(
  'ssr_bootstrap_failures_total',
  'Total backend failures observed on SSR bootstrap requests.',
  ['target', 'reason', 'status'],
);

const emailDeliveryFailuresTotal = registry.registerCounter(
  'email_delivery_failures_total',
  'Total outbox email delivery failures.',
  ['message_type', 'stage', 'reason'],
);

function extractSsoProvider(path: string): string {
  const startMatch = path.match(/^\/auth\/sso\/([^/]+)$/);
  if (startMatch?.[1]) return startMatch[1];

  const callbackMatch = path.match(/^\/auth\/sso\/([^/]+)\/callback$/);
  if (callbackMatch?.[1]) return callbackMatch[1];

  return 'unknown';
}

function extractTenantResolutionReason(input: {
  code: string;
  message: string;
  meta?: Record<string, unknown>;
}): string | null {
  const metaReason = typeof input.meta?.reason === 'string' ? input.meta.reason : null;
  if (metaReason === 'missing_key' || metaReason === 'inactive' || metaReason === 'not_found') {
    return metaReason;
  }

  if (input.message === 'Missing tenant context') {
    return 'missing_context';
  }

  if (input.message === 'This workspace is not available.') {
    return 'workspace_unavailable';
  }

  return null;
}

export function recordHttpRequestCompleted(input: {
  method: string;
  route: string;
  statusCode: number;
  durationMs: number;
}): void {
  const labels = {
    method: input.method.toUpperCase(),
    route: input.route,
    status: input.statusCode,
    status_class: statusClass(input.statusCode),
  };

  registry.inc(httpRequestsTotal, labels, 1);
  registry.observe(httpRequestDurationMs, labels, input.durationMs);
}

export function recordHttpFailure(input: {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  statusCode: number;
  code: string;
  message: string;
  meta?: Record<string, unknown>;
}): void {
  const path = normalizeMetricRouteFromUrl(input.url);
  const reason = classifyReason(input.code, input.statusCode);
  const status = input.statusCode;
  const method = input.method.toUpperCase();

  if (method === 'POST' && path === '/auth/login') {
    registry.inc(authLoginFailuresTotal, { reason, code: input.code, status }, 1);
  }

  if (method === 'POST' && path === '/auth/forgot-password') {
    registry.inc(
      passwordResetFailuresTotal,
      { step: 'request', reason, code: input.code, status },
      1,
    );
  }

  if (method === 'POST' && path === '/auth/reset-password') {
    registry.inc(
      passwordResetFailuresTotal,
      { step: 'confirm', reason, code: input.code, status },
      1,
    );
  }

  if (method === 'POST' && path === '/auth/mfa/setup') {
    registry.inc(mfaFailuresTotal, { step: 'setup', reason, code: input.code, status }, 1);
  }

  if (method === 'POST' && path === '/auth/mfa/verify-setup') {
    registry.inc(mfaFailuresTotal, { step: 'verify_setup', reason, code: input.code, status }, 1);
  }

  if (method === 'POST' && path === '/auth/mfa/verify') {
    registry.inc(mfaFailuresTotal, { step: 'verify', reason, code: input.code, status }, 1);
  }

  if (method === 'POST' && path === '/auth/mfa/recover') {
    registry.inc(mfaFailuresTotal, { step: 'recover', reason, code: input.code, status }, 1);
  }

  if (path === '/auth/sso/:provider' || path === '/auth/sso/:provider/callback') {
    registry.inc(
      ssoFailuresTotal,
      {
        step: path === '/auth/sso/:provider' ? 'start' : 'callback',
        provider: extractSsoProvider(input.url.split('?')[0] ?? input.url),
        reason,
        code: input.code,
        status,
      },
      1,
    );
  }

  if (method === 'POST' && path === '/auth/invites/accept') {
    registry.inc(inviteFailuresTotal, { action: 'accept', reason, code: input.code, status }, 1);
  }

  if (method === 'POST' && path === '/admin/invites') {
    registry.inc(inviteFailuresTotal, { action: 'create', reason, code: input.code, status }, 1);
  }

  if (method === 'POST' && path === '/admin/invites/:inviteId/resend') {
    registry.inc(inviteFailuresTotal, { action: 'resend', reason, code: input.code, status }, 1);
  }

  if (method === 'DELETE' && path === '/admin/invites/:inviteId') {
    registry.inc(inviteFailuresTotal, { action: 'cancel', reason, code: input.code, status }, 1);
  }

  const tenantReason = extractTenantResolutionReason({
    code: input.code,
    message: input.message,
    meta: input.meta,
  });

  if (tenantReason) {
    registry.inc(
      tenantResolutionFailuresTotal,
      {
        route: path,
        reason: tenantReason,
        status,
      },
      1,
    );
  }

  const isBootstrapRequest = requestHeaderEquals(input.headers, 'x-auth-bootstrap', '1');
  const bootstrapTarget =
    path === '/auth/config'
      ? 'config'
      : path === '/auth/me'
        ? 'me'
        : path === '/auth/register'
          ? 'register'
          : null;

  if (isBootstrapRequest && bootstrapTarget) {
    const isExpectedBootstrap401 = path === '/auth/me' && status === 401;

    if (!isExpectedBootstrap401) {
      registry.inc(
        ssrBootstrapFailuresTotal,
        {
          target: bootstrapTarget,
          reason,
          status,
        },
        1,
      );
    }
  }
}

export function recordEmailDeliveryFailure(input: {
  messageType: string;
  stage: 'decrypt' | 'send';
  reason: 'decrypt_failed' | 'retryable' | 'non_retryable' | 'max_attempts_exceeded' | 'unexpected';
}): void {
  registry.inc(
    emailDeliveryFailuresTotal,
    {
      message_type: input.messageType,
      stage: input.stage,
      reason: input.reason,
    },
    1,
  );
}

export const metricsContentType = 'text/plain; version=0.0.4; charset=utf-8';

export function renderMetricsSnapshot(): string {
  return registry.render();
}
