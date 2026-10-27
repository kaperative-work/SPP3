import { Router } from 'express';
import { pool } from './db.js';
import { HttpError, requireJson, wrap } from './errors.js';
import { logger } from './logger.js';
import { requireAction, requireAuth } from './auth.js';
import { ROLES } from './permissions.js';
import { parseId } from './validate.js';

export const usersRouter = Router();

usersRouter.use(requireAuth, requireAction('users:manage'));

function mapUser(row) {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role,
    createdAt: row.created_at,
  };
}

usersRouter.get('/', wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, email, name, role, created_at
     FROM users
     ORDER BY id ASC`,
  );
  res.json({ users: rows.map(mapUser) });
}));

usersRouter.patch('/:id', requireJson, wrap(async (req, res) => {
  const id = parseId(req.params.id);
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    throw new HttpError(400, 'Ожидается объект с полем role');
  }
  const { role } = req.body;
  if (!ROLES.includes(role)) {
    throw new HttpError(400, 'Неизвестная роль', [
      { field: 'role', message: 'Выберите роль из списка' },
    ]);
  }

  const existing = await pool.query(
    'SELECT id, email, name, role, created_at FROM users WHERE id = $1',
    [id],
  );
  const user = existing.rows[0];
  if (!user) throw new HttpError(404, 'Пользователь не найден');

  if (user.role === 'admin' && role !== 'admin') {
    const { rows } = await pool.query(
      `SELECT COUNT(*)::int AS count FROM users WHERE role = 'admin'`,
    );
    if (rows[0].count <= 1) {
      throw new HttpError(
        409,
        'В системе должен остаться хотя бы один администратор',
        [],
        'last_admin',
      );
    }
  }
  if (id === req.user.id) {
    throw new HttpError(403, 'Нельзя изменить собственную роль');
  }
  if (user.role === role) {
    res.json({ user: mapUser(user) });
    return;
  }

  const { rows } = await pool.query(
    `UPDATE users
     SET role = $1
     WHERE id = $2
     RETURNING id, email, name, role, created_at`,
    [role, id],
  );
  logger.info('role_changed', {
    requestId: req.id,
    actorId: req.user.id,
    userId: id,
    from: user.role,
    to: role,
  });
  res.json({ user: mapUser(rows[0]) });
}));
