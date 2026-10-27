const LEVELS = { DEBUG: 10, INFO: 20, WARN: 30, ERROR: 40 };
const REDACTED = new Set(['password', 'passwordHash', 'authorization']);

export function createLogger(stream = process.stdout, env = process.env) {
  const threshold = LEVELS[(env.LOG_LEVEL || 'INFO').toUpperCase()] ?? LEVELS.INFO;

  function write(level, msg, fields = {}) {
    if ((LEVELS[level] ?? LEVELS.INFO) < threshold) return;
    const entry = {
      time: new Date().toISOString(),
      level,
      msg,
      service: 'library-api',
    };
    for (const [key, value] of Object.entries(fields)) {
      if (value === undefined) continue;
      entry[key] = REDACTED.has(key) ? '[redacted]' : value;
    }
    stream.write(`${JSON.stringify(entry)}\n`);
  }

  return {
    debug: (msg, fields) => write('DEBUG', msg, fields),
    info: (msg, fields) => write('INFO', msg, fields),
    warn: (msg, fields) => write('WARN', msg, fields),
    error: (msg, fields) => write('ERROR', msg, fields),
  };
}

export const logger = createLogger();
