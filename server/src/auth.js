import { randomBytes, randomUUID } from 'node:crypto';
import { Router } from 'express';
import {
  appPublicUrl,
  jwtSecret,
  maxSessions,
  resetTtlMs,
  tokenTtlSec,
} from './config.js';
import { pool, withTransaction } from './db.js';
import { HttpError, requireJson, wrap } from './errors.js';
import { emailIssue, nameIssue, normalizeEmail, trimmedName } from './fields.js';
import { clearGuard, openGuard, registerGuardFailure } from './guards.js';
import { clientIp } from './ip.js';
import { logger } from './logger.js';
import { deliverMail } from './mail.js';
import { hashPassword, passwordIssue, verifyPassword } from './passwords.js';
import { can } from './permissions.js';
import { hashToken, signToken, verifyToken } from './tokens.js';

export const authRouter = Router();

const RESET_MESSAGE = 'Если учётная запись с таким адресом есть, на почту отправлены инструкции по восстановлению доступа.';

function userAgent(req) {
  return String(req.headers['user-agent'] || '').slice(0, 300);
}

function mapUser(row) {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role,
    createdAt: row.createdAt ?? row.created_at,
  };
}

function rejectDetails(message, pairs) {
  const details = pairs
    .filter((item) => item.message)
    .map((item) => ({ field: item.field, message: item.message }));
  if (details.length > 0) throw new HttpError(400, message, details);
}

function readCredentials(body, { enforcePolicy }) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new HttpError(400, 'Ожидается объект с полями учётной записи');
  }
  const email = normalizeEmail(body.email);
  const emailMessage = emailIssue(body.email);
  const passwordMessage = passwordIssue(body.password, { enforcePolicy });
  rejectDetails('Проверьте введённые данные', [
    { field: 'email', message: emailMessage },
    { field: 'password', message: passwordMessage },
  ]);
  return {
    email,
    password: body.password,
    revokeOldest: body.revokeOldest === true,
  };
}

async function findUserByEmail(email) {
  const { rows } = await pool.query(
    `SELECT id, email, name, role, password_hash, created_at
     FROM users
     WHERE email = $1`,
    [email],
  );
  return rows[0] || null;
}

async function ensureOpen(keys) {
  let retryAfter = 0;
  for (const key of keys) {
    const verdict = await openGuard(key);
    if (verdict.locked) retryAfter = Math.max(retryAfter, verdict.retryAfterSec);
  }
  if (retryAfter > 0) {
    throw new HttpError(
      429,
      'Слишком много неудачных попыток. Повторите позже.',
      [],
      'too_many_requests',
      { retryAfter },
    );
  }
}

async function noteFailures(keys) {
  let retryAfter = 0;
  for (const key of keys) {
    const verdict = await registerGuardFailure(key);
    if (verdict.locked) retryAfter = Math.max(retryAfter, verdict.retryAfterSec);
  }
  return retryAfter;
}

async function openSession(user, { ip, agent, revokeOldest, requestId }) {
  const limit = maxSessions();
  const exp = Math.floor(Date.now() / 1000) + tokenTtlSec();
  const expiresAt = new Date(exp * 1000);
  const sessionId = randomUUID();

  await withTransaction(async (client) => {
    await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [user.id]);
    const { rows } = await client.query(
      `SELECT id
       FROM sessions
       WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
       ORDER BY created_at ASC`,
      [user.id],
    );
    if (rows.length >= limit) {
      if (!revokeOldest) {
        throw new HttpError(
          409,
          `Достигнут предел одновременных сеансов (${limit}). Завершите один из них или войдите, закрыв самый старый сеанс.`,
          [],
          'too_many_sessions',
          { sessionLimit: limit, activeSessions: rows.length },
        );
      }
      const ids = rows.slice(0, rows.length - limit + 1).map((row) => row.id);
      for (const id of ids) {
        await client.query('UPDATE sessions SET revoked_at = NOW() WHERE id = $1', [id]);
      }
      logger.info('sessions_evicted', { requestId, userId: user.id, sessionIds: ids });
    }
    await client.query(
      `INSERT INTO sessions (id, user_id, expires_at, ip, user_agent)
       VALUES ($1, $2, $3, $4, $5)`,
      [sessionId, user.id, expiresAt, ip, agent],
    );
  });

  const signed = signToken(
    { sub: user.id, role: user.role, jti: sessionId },
    jwtSecret(),
    exp,
  );
  return {
    token: signed.token,
    expiresAt: signed.expiresAt,
    sessionId,
  };
}

async function activeSession(sessionId) {
  const { rows } = await pool.query(
    `SELECT s.id, s.user_id, s.expires_at, u.email, u.name, u.role, u.created_at
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.id = $1 AND s.revoked_at IS NULL AND s.expires_at > NOW()`,
    [sessionId],
  );
  return rows[0] || null;
}

export const requireAuth = wrap(async (req, res, next) => {
  const header = String(req.headers.authorization || '');
  const match = /^Bearer\s+(\S+)$/i.exec(header);
  if (!match) throw new HttpError(401, 'Требуется вход', [], 'unauthorized');

  const payload = verifyToken(match[1], jwtSecret());
  if (!payload.jti || payload.sub === undefined) {
    throw new HttpError(401, 'Недействительный ключ доступа', [], 'invalid_token');
  }
  const session = await activeSession(payload.jti);
  if (!session || String(session.user_id) !== String(payload.sub)) {
    throw new HttpError(401, 'Сеанс завершён', [], 'session_revoked');
  }
  req.user = {
    id: session.user_id,
    email: session.email,
    name: session.name,
    role: session.role,
    createdAt: session.created_at,
    sessionId: session.id,
    sessionExpiresAt: session.expires_at,
  };
  next();
});

export function requireAction(action) {
  return (req, res, next) => {
    if (!req.user) {
      next(new HttpError(401, 'Требуется вход', [], 'unauthorized'));
      return;
    }
    if (!can(req.user.role, action)) {
      logger.warn('access_denied', {
        requestId: req.id,
        userId: req.user.id,
        role: req.user.role,
        action,
        method: req.method,
        path: req.originalUrl,
      });
      next(new HttpError(403, 'Недостаточно прав', [], 'forbidden'));
      return;
    }
    next();
  };
}

authRouter.post('/register', requireJson, wrap(async (req, res) => {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    throw new HttpError(400, 'Ожидается объект с полями учётной записи');
  }
  const email = normalizeEmail(req.body.email);
  rejectDetails('Проверьте введённые данные', [
    { field: 'name', message: nameIssue(req.body.name) },
    { field: 'email', message: emailIssue(req.body.email) },
    { field: 'password', message: passwordIssue(req.body.password) },
  ]);

  const passwordHash = await hashPassword(req.body.password);
  let user;
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (email, name, role, password_hash)
       VALUES ($1, $2, 'reader', $3)
       RETURNING id, email, name, role, created_at`,
      [email, trimmedName(req.body.name), passwordHash],
    );
    user = rows[0];
  } catch (error) {
    if (error.code === '23505') {
      throw new HttpError(
        409,
        'Учётная запись с такой почтой уже есть',
        [{ field: 'email', message: 'Этот адрес уже зарегистрирован' }],
        'email_taken',
      );
    }
    throw error;
  }

  const session = await openSession(user, {
    ip: clientIp(req),
    agent: userAgent(req),
    revokeOldest: false,
    requestId: req.id,
  });
  logger.info('user_registered', { requestId: req.id, userId: user.id, email: user.email, role: user.role });
  res.status(201).json({
    token: session.token,
    expiresAt: session.expiresAt,
    user: mapUser(user),
  });
}));

authRouter.post('/login', requireJson, wrap(async (req, res) => {
  const { email, password, revokeOldest } = readCredentials(req.body, { enforcePolicy: false });
  const ip = clientIp(req);
  const keys = [`login:ip:${ip}`, `login:email:${email}`];
  await ensureOpen(keys);

  const user = await findUserByEmail(email);
  const matches = await verifyPassword(password, user?.password_hash);
  if (!user || !matches) {
    const retryAfter = await noteFailures(keys);
    logger.warn('login_failed', { requestId: req.id, email, ip });
    if (retryAfter > 0) {
      throw new HttpError(
        429,
        'Слишком много неудачных попыток входа. Адрес или учётная запись временно заблокированы.',
        [],
        'too_many_requests',
        { retryAfter },
      );
    }
    throw new HttpError(401, 'Неверная почта или пароль', [], 'invalid_credentials');
  }

  await Promise.all(keys.map((key) => clearGuard(key)));
  const session = await openSession(user, {
    ip,
    agent: userAgent(req),
    revokeOldest,
    requestId: req.id,
  });
  logger.info('login_success', {
    requestId: req.id,
    userId: user.id,
    email: user.email,
    role: user.role,
    sessionId: session.sessionId,
    ip,
    expiresAt: session.expiresAt,
  });
  res.json({
    token: session.token,
    expiresAt: session.expiresAt,
    user: mapUser(user),
  });
}));

authRouter.get('/me', requireAuth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS count
     FROM sessions
     WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()`,
    [req.user.id],
  );
  res.json({
    user: mapUser(req.user),
    session: {
      id: req.user.sessionId,
      expiresAt: req.user.sessionExpiresAt,
    },
    activeSessions: rows[0].count,
    sessionLimit: maxSessions(),
  });
}));

authRouter.post('/logout', requireAuth, wrap(async (req, res) => {
  await pool.query(
    'UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL',
    [req.user.sessionId],
  );
  logger.info('logout', { requestId: req.id, userId: req.user.id, sessionId: req.user.sessionId });
  res.status(204).end();
}));

authRouter.get('/sessions', requireAuth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, created_at, expires_at, ip, user_agent
     FROM sessions
     WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
     ORDER BY created_at DESC`,
    [req.user.id],
  );
  res.json({
    limit: maxSessions(),
    sessions: rows.map((row) => ({
      id: row.id,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      ip: row.ip,
      userAgent: row.user_agent,
      current: row.id === req.user.sessionId,
    })),
  });
}));

authRouter.delete('/sessions/:id', requireAuth, wrap(async (req, res) => {
  if (!/^[0-9a-f-]{36}$/i.test(req.params.id)) {
    throw new HttpError(400, 'Некорректный идентификатор сеанса');
  }
  const { rowCount } = await pool.query(
    `UPDATE sessions
     SET revoked_at = NOW()
     WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
    [req.params.id, req.user.id],
  );
  if (!rowCount) throw new HttpError(404, 'Сеанс не найден');
  logger.info('session_revoked', { requestId: req.id, userId: req.user.id, sessionId: req.params.id });
  res.status(204).end();
}));

authRouter.post('/forgot-password', requireJson, wrap(async (req, res) => {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    throw new HttpError(400, 'Ожидается объект с адресом почты');
  }
  const message = emailIssue(req.body.email);
  if (message) throw new HttpError(400, 'Проверьте введённые данные', [{ field: 'email', message }]);

  const email = normalizeEmail(req.body.email);
  const ip = clientIp(req);
  const guardKey = `forgot:ip:${ip}`;
  await ensureOpen([guardKey]);
  const retryAfter = await noteFailures([guardKey]);
  if (retryAfter > 0) {
    logger.warn('password_reset_limited', { requestId: req.id, ip });
    throw new HttpError(
      429,
      'Слишком много запросов на восстановление. Повторите позже.',
      [],
      'too_many_requests',
      { retryAfter },
    );
  }

  const user = await findUserByEmail(email);
  const token = randomBytes(32).toString('base64url');
  let previewUrl = null;
  if (user) {
    const resetUrl = `${appPublicUrl()}/#/reset?token=${encodeURIComponent(token)}`;
    const expiresAt = new Date(Date.now() + resetTtlMs());
    await withTransaction(async (client) => {
      await client.query('DELETE FROM password_resets WHERE user_id = $1', [user.id]);
      await client.query(
        `INSERT INTO password_resets (user_id, token_hash, expires_at)
         VALUES ($1, $2, $3)`,
        [user.id, hashToken(token), expiresAt],
      );
    });
    const minutes = Math.round(resetTtlMs() / 60000);
    const delivery = await deliverMail({
      to: user.email,
      subject: 'Восстановление доступа к каталогу библиотеки',
      resetUrl,
      text: [
        'Здравствуйте!',
        '',
        `Чтобы задать новый пароль, откройте ссылку. Она действует ${minutes} мин. и только один раз:`,
        resetUrl,
        '',
        'Если вы не запрашивали восстановление, проигнорируйте это письмо.',
      ].join('\n'),
    });
    previewUrl = delivery.previewUrl;
    logger.info('password_reset_requested', { requestId: req.id, userId: user.id, email: user.email });
  } else {
    logger.info('password_reset_unknown_email', { requestId: req.id, email });
  }

  const body = { message: RESET_MESSAGE };
  if (previewUrl) {
    body.delivery = 'log';
    body.previewUrl = previewUrl;
  }
  res.json(body);
}));

authRouter.post('/reset-password', requireJson, wrap(async (req, res) => {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    throw new HttpError(400, 'Ожидается объект с ключом и новым паролем');
  }
  const token = req.body.token;
  const passwordMessage = passwordIssue(req.body.password);
  const details = [];
  if (typeof token !== 'string' || token.length < 20 || token.length > 200) {
    details.push({ field: 'token', message: 'Ссылка недействительна или её срок истёк' });
  }
  if (passwordMessage) details.push({ field: 'password', message: passwordMessage });
  if (details.length > 0) throw new HttpError(400, 'Проверьте введённые данные', details);

  const passwordHash = await hashPassword(req.body.password);
  const user = await withTransaction(async (client) => {
    const { rows } = await client.query(
      `UPDATE password_resets
       SET used_at = NOW()
       WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
       RETURNING user_id`,
      [hashToken(token)],
    );
    if (!rows[0]) throw new HttpError(400, 'Ссылка недействительна или её срок истёк');
    const userId = rows[0].user_id;
    await client.query('UPDATE users SET password_hash = $1 WHERE id = $2', [passwordHash, userId]);
    await client.query(
      'UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL',
      [userId],
    );
    const found = await client.query('SELECT id, email FROM users WHERE id = $1', [userId]);
    return found.rows[0];
  });

  const ip = clientIp(req);
  await clearGuard(`login:email:${user.email}`);
  await clearGuard(`login:ip:${ip}`);
  logger.info('password_reset_completed', { requestId: req.id, userId: user.id });
  res.json({ message: 'Пароль обновлён. Войдите с новым паролем.' });
}));
