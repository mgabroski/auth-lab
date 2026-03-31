import 'server-only';

type LogLevel = 'info' | 'warn' | 'error';
type LogMeta = Record<string, unknown>;

const env = process.env.NODE_ENV ?? 'development';
const service = process.env.NEXT_PUBLIC_SERVICE_NAME ?? 'auth-lab-frontend';
const release = process.env.SERVICE_VERSION ?? 'dev';

function serializeValue(value: unknown, depth = 0): unknown {
  if (depth > 4) return '[Truncated]';
  if (value === null || value === undefined) return value;

  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      stack: value.stack,
    };
  }

  if (Array.isArray(value)) {
    return value.map((item) => serializeValue(item, depth + 1));
  }

  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      out[key] = serializeValue(entry, depth + 1);
    }
    return out;
  }

  return value;
}

function serializeMeta(meta: LogMeta): Record<string, unknown> {
  const out: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(meta)) {
    out[key] = serializeValue(value);
  }

  return out;
}

function emit(level: LogLevel, msg: string, meta: LogMeta = {}): void {
  const line = JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    service,
    env,
    release,
    msg,
    ...serializeMeta(meta),
  });

  if (level === 'error') {
    console.error(line);
    return;
  }

  if (level === 'warn') {
    console.warn(line);
    return;
  }

  console.log(line);
}

export const serverLogger = {
  info(msg: string, meta: LogMeta = {}) {
    emit('info', msg, meta);
  },

  warn(msg: string, meta: LogMeta = {}) {
    emit('warn', msg, meta);
  },

  error(msg: string, meta: LogMeta = {}) {
    emit('error', msg, meta);
  },
};
