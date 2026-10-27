import { lockoutPolicy } from './config.js';
import { pool, withTransaction } from './db.js';
import { guardBlocked, recordFailure } from './lockout.js';

function mapGuard(row) {
  if (!row) return null;
  return {
    failedCount: row.failed_count,
    windowStartedAt: new Date(row.window_started_at).getTime(),
    lockedUntil: row.locked_until ? new Date(row.locked_until).getTime() : null,
  };
}

export async function getGuard(key) {
  const { rows } = await pool.query(
    `SELECT failed_count, window_started_at, locked_until
     FROM auth_guards
     WHERE guard_key = $1`,
    [key],
  );
  return mapGuard(rows[0]);
}

export async function clearGuard(key) {
  await pool.query('DELETE FROM auth_guards WHERE guard_key = $1', [key]);
}

export async function registerGuardFailure(key) {
  const now = Date.now();
  const policy = lockoutPolicy();
  return withTransaction(async (client) => {
    const { rows } = await client.query(
      `SELECT failed_count, window_started_at, locked_until
       FROM auth_guards
       WHERE guard_key = $1
       FOR UPDATE`,
      [key],
    );
    const next = recordFailure(mapGuard(rows[0]), now, policy);
    await client.query(
      `INSERT INTO auth_guards (guard_key, failed_count, window_started_at, locked_until, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (guard_key) DO UPDATE
       SET failed_count = EXCLUDED.failed_count,
           window_started_at = EXCLUDED.window_started_at,
           locked_until = EXCLUDED.locked_until,
           updated_at = NOW()`,
      [
        key,
        next.failedCount,
        new Date(next.windowStartedAt),
        next.lockedUntil ? new Date(next.lockedUntil) : null,
      ],
    );
    return guardBlocked(next, now);
  });
}

export async function openGuard(key) {
  return guardBlocked(await getGuard(key), Date.now());
}
