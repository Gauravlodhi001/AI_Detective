/**
 * Structured JSON Logger with automatic sensitive data redaction.
 */

const SENSITIVE_KEYS = ['password', 'token', 'secret', 'key', 'authorization', 'cookie', 'jwt'];

/**
 * Deeply redacts sensitive keys from objects/arrays.
 */
function redact(data) {
  if (data === null || data === undefined) {
    return data;
  }
  
  if (typeof data !== 'object') {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(item => redact(item));
  }

  const redacted = {};
  for (const [key, val] of Object.entries(data)) {
    const isSensitive = SENSITIVE_KEYS.some(k => key.toLowerCase().includes(k));
    if (isSensitive) {
      redacted[key] = '[REDACTED]';
    } else if (typeof val === 'object') {
      redacted[key] = redact(val);
    } else {
      redacted[key] = val;
    }
  }
  return redacted;
}

/**
 * Standard log formatter.
 */
function writeLog(level, message, meta = {}) {
  // Convert Error objects in meta to string representations
  const formattedMeta = {};
  for (const [k, v] of Object.entries(meta)) {
    if (v instanceof Error) {
      formattedMeta[k] = {
        message: v.message,
        stack: process.env.NODE_ENV === 'production' ? undefined : v.stack
      };
    } else {
      formattedMeta[k] = v;
    }
  }

  const payload = {
    timestamp: new Date().toISOString(),
    level,
    message,
    meta: redact(formattedMeta)
  };

  if (level === 'error') {
    console.error(JSON.stringify(payload));
  } else {
    console.log(JSON.stringify(payload));
  }
}

module.exports = {
  info: (msg, meta) => writeLog('info', msg, meta),
  warn: (msg, meta) => writeLog('warn', msg, meta),
  error: (msg, meta) => writeLog('error', msg, meta)
};
