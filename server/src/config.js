export function assertConfig(env = process.env) {
  const secret = env.JWT_SECRET || '';
  if (secret.length < 16) {
    throw new Error('JWT_SECRET должен быть не короче 16 символов');
  }
}

export function jwtSecret(env = process.env) {
  assertConfig(env);
  return env.JWT_SECRET;
}

export function tokenTtlSec(env = process.env) {
  const minutes = Number(env.JWT_TTL_MINUTES);
  if (!Number.isFinite(minutes) || minutes <= 0) return 30 * 60;
  return Math.round(minutes * 60);
}

export function maxSessions(env = process.env) {
  const value = Number(env.MAX_SESSIONS);
  if (!Number.isInteger(value) || value < 1) return 3;
  return value;
}

export function lockoutPolicy(env = process.env) {
  const failures = Number(env.LOGIN_MAX_FAILURES);
  const windowMinutes = Number(env.LOGIN_WINDOW_MINUTES);
  const lockMinutes = Number(env.LOGIN_LOCK_MINUTES);
  return {
    maxFailures: Number.isInteger(failures) && failures > 0 ? failures : 5,
    windowMs: (Number.isFinite(windowMinutes) && windowMinutes > 0 ? windowMinutes : 15) * 60 * 1000,
    lockMs: (Number.isFinite(lockMinutes) && lockMinutes > 0 ? lockMinutes : 15) * 60 * 1000,
  };
}

export function resetTtlMs(env = process.env) {
  const minutes = Number(env.RESET_TTL_MINUTES);
  if (!Number.isFinite(minutes) || minutes <= 0) return 30 * 60 * 1000;
  return Math.round(minutes * 60 * 1000);
}

export function appPublicUrl(env = process.env) {
  return String(env.APP_PUBLIC_URL || 'http://localhost:8080').replace(/\/$/, '');
}

export function mailMode(env = process.env) {
  return env.MAIL_MODE === 'smtp' ? 'smtp' : 'log';
}
