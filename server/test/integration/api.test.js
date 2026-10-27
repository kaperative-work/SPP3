import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { after, beforeEach, describe, it } from 'node:test';
import request from 'supertest';
import { signToken } from '../../src/tokens.js';

process.env.DATABASE_URL ||= 'postgres://library:library@127.0.0.1:5432/library';
process.env.JWT_SECRET = 'integration-test-secret';
process.env.MAIL_MODE = 'log';
process.env.UPLOAD_DIR = path.join(os.tmpdir(), 'spp3-lab3-uploads');
process.env.APP_PUBLIC_URL = 'http://localhost:8080';
process.env.LOGIN_MAX_FAILURES = '5';
process.env.LOGIN_WINDOW_MINUTES = '15';
process.env.LOGIN_LOCK_MINUTES = '15';
process.env.MAX_SESSIONS = '3';
process.env.JWT_TTL_MINUTES = '30';

const { app } = await import('../../src/index.js');
const { initDb, pool } = await import('../../src/db.js');

let ready = false;

after(async () => {
  if (ready) {
    await pool.query(`DELETE FROM books WHERE title LIKE '[test]%'`);
    await pool.query(`DELETE FROM users WHERE email LIKE '%@test.local'`);
    await pool.query('DELETE FROM auth_guards');
  }
  await pool.end();
});

try {
  await pool.query('SELECT 1');
  await initDb();
  ready = true;
} catch (error) {
  if (process.env.CI) throw error;
  console.log(`Интеграционные тесты пропущены: ${error.message}`);
}

function assertError(res, status, code) {
  assert.equal(res.status, status);
  assert.equal(res.body.status, status);
  assert.equal(res.body.code, code);
  assert.equal(typeof res.body.error, 'string');
  assert.ok(res.body.error.length > 0);
  assert.ok(Array.isArray(res.body.details));
}

function bearer(token) {
  return { Authorization: `Bearer ${token}` };
}

function bookBody(title) {
  return {
    title,
    author: 'Тестовый автор',
    year: 2001,
    genre: 'Роман',
    description: 'Проверка лабораторной работы',
  };
}

async function login(email, password, extra = {}) {
  return request(app).post('/api/auth/login').send({ email, password, ...extra });
}

function tokenFromPreview(url) {
  const hash = new URL(url).hash;
  return new URLSearchParams(hash.slice(hash.indexOf('?') + 1)).get('token');
}

describe('HTTP API', { skip: ready ? false : 'Postgres недоступен' }, () => {
  beforeEach(async () => {
    await pool.query('DELETE FROM auth_guards');
    await pool.query(`
      UPDATE sessions
      SET revoked_at = NOW()
      WHERE revoked_at IS NULL
        AND user_id IN (
          SELECT id FROM users
          WHERE email LIKE '%@test.local' OR email LIKE '%@library.local'
        )
    `);
  });

  it('отдаёт здоровье, метаданные и единый 404', async () => {
    const health = await request(app).get('/api/health');
    assert.equal(health.status, 200);
    assert.equal(health.body.ok, true);

    const meta = await request(app).get('/api/meta');
    assert.equal(meta.status, 200);
    assert.equal(meta.body.roles.length, 3);
    assert.equal(meta.body.sessionLimit, 3);
    assert.ok(meta.body.permissions.reader.includes('books:read'));
    assert.equal(meta.body.permissions.reader.includes('books:write'), false);

    const missing = await request(app).get('/api/no-such-route');
    assertError(missing, 404, 'not_found');
  });

  it('пустой каталог без ключа недоступен, битый JSON и чужой тип отклоняются', async () => {
    const hidden = await request(app).get('/api/books');
    assertError(hidden, 401, 'unauthorized');

    const text = await request(app)
      .post('/api/auth/login')
      .set('Content-Type', 'text/plain')
      .send('email=a');
    assertError(text, 415, 'unsupported_media_type');

    const broken = await request(app)
      .post('/api/auth/login')
      .set('Content-Type', 'application/json')
      .send('{');
    assertError(broken, 400, 'bad_request');

    const huge = await request(app)
      .post('/api/auth/login')
      .set('Content-Type', 'application/json')
      .send(`{"email":"${'a'.repeat(120000)}@test.local","password":"x"}`);
    assert.equal(huge.status, 413);
    assert.equal(huge.body.code, 'payload_too_large');

    const empty = await request(app).post('/api/auth/login').send({});
    assert.equal(empty.status, 400);
    assert.ok(empty.body.details.some((item) => item.field === 'email'));
  });

  it('регистрирует читателя, пускает учебные роли и запрещает чужие действия', async () => {
    const email = `user-${randomUUID()}@test.local`;
    const created = await request(app).post('/api/auth/register').send({
      name: 'Новый читатель',
      email,
      password: 'Secret123',
    });
    assert.equal(created.status, 201);
    assert.equal(created.body.user.role, 'reader');
    assert.ok(created.body.token);

    const duplicate = await request(app).post('/api/auth/register').send({
      name: 'Ещё раз',
      email,
      password: 'Secret123',
    });
    assertError(duplicate, 409, 'email_taken');

    const weak = await request(app).post('/api/auth/register').send({
      name: 'Слабый',
      email: `weak-${randomUUID()}@test.local`,
      password: 'password',
    });
    assert.equal(weak.status, 400);

    const reader = await login('reader@library.local', 'Reader123!');
    const librarian = await login('librarian@library.local', 'Librarian123!');
    const admin = await login('admin@library.local', 'Admin123!');
    assert.equal(reader.status, 200);
    assert.equal(reader.body.user.role, 'reader');
    assert.equal(librarian.body.user.role, 'librarian');
    assert.equal(admin.body.user.role, 'admin');

    const title = `[test] ${randomUUID()}`;
    const denied = await request(app)
      .post('/api/books')
      .set(bearer(reader.body.token))
      .send(bookBody(title));
    assertError(denied, 403, 'forbidden');

    const listed = await request(app).get('/api/books').set(bearer(reader.body.token));
    assert.equal(listed.status, 200);
    assert.ok(Array.isArray(listed.body.books));

    const added = await request(app)
      .post('/api/books')
      .set(bearer(librarian.body.token))
      .send(bookBody(title));
    assert.equal(added.status, 201);
    assert.match(added.headers.location, /^\/api\/books\/\d+$/);
    const bookId = added.body.book.id;

    const invalid = await request(app)
      .put(`/api/books/${bookId}`)
      .set(bearer(librarian.body.token))
      .send({ ...bookBody(title), genre: 'Несуществующий' });
    assert.equal(invalid.status, 400);
    assert.ok(invalid.body.details.some((item) => item.field === 'genre'));

    const missingBook = await request(app).get('/api/books/99999999').set(bearer(reader.body.token));
    assertError(missingBook, 404, 'not_found');

    const badId = await request(app).get('/api/books/abc').set(bearer(reader.body.token));
    assert.equal(badId.status, 400);

    const librarianDelete = await request(app)
      .delete(`/api/books/${bookId}`)
      .set(bearer(librarian.body.token));
    assertError(librarianDelete, 403, 'forbidden');

    const png = Buffer.from(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
      'base64',
    );
    const coverDenied = await request(app)
      .put(`/api/books/${bookId}/cover`)
      .set(bearer(reader.body.token))
      .attach('cover', png, 'dot.png');
    assert.equal(coverDenied.status, 403);

    const cover = await request(app)
      .put(`/api/books/${bookId}/cover`)
      .set(bearer(librarian.body.token))
      .attach('cover', png, 'dot.png');
    assert.equal(cover.status, 200);
    assert.ok(cover.body.book.coverUrl);

    const removed = await request(app).delete(`/api/books/${bookId}`).set(bearer(admin.body.token));
    assert.equal(removed.status, 204);
    const gone = await request(app).get(`/api/books/${bookId}`).set(bearer(admin.body.token));
    assert.equal(gone.status, 404);

    const usersDenied = await request(app).get('/api/users').set(bearer(reader.body.token));
    assertError(usersDenied, 403, 'forbidden');
    const users = await request(app).get('/api/users').set(bearer(admin.body.token));
    assert.equal(users.status, 200);
    assert.ok(users.body.users.some((user) => user.email === 'librarian@library.local'));
  });

  it('блокирует подбор пароля и снимает блокировку восстановлением', async () => {
    const email = `lock-${randomUUID()}@test.local`;
    const password = 'Secret123';
    const created = await request(app).post('/api/auth/register').send({
      name: 'Блокировка',
      email,
      password,
    });
    assert.equal(created.status, 201);

    const attempts = [];
    for (let index = 0; index < 5; index += 1) {
      attempts.push(await login(email, 'wrong-pass-1'));
    }
    assert.equal(attempts[3].status, 401);
    assert.equal(attempts[3].body.code, 'invalid_credentials');
    assertError(attempts[4], 429, 'too_many_requests');
    assert.ok(Number(attempts[4].headers['retry-after']) > 0);

    const stillLocked = await login(email, password);
    assert.equal(stillLocked.status, 429);

    const unknown = await request(app).post('/api/auth/forgot-password').send({
      email: `missing-${randomUUID()}@test.local`,
    });
    assert.equal(unknown.status, 200);
    assert.equal(unknown.body.previewUrl, undefined);

    const forgot = await request(app).post('/api/auth/forgot-password').send({ email });
    assert.equal(forgot.status, 200);
    assert.ok(forgot.body.previewUrl);
    const token = tokenFromPreview(forgot.body.previewUrl);

    const reset = await request(app).post('/api/auth/reset-password').send({
      token,
      password: 'Newpass123',
    });
    assert.equal(reset.status, 200);

    const reused = await request(app).post('/api/auth/reset-password').send({
      token,
      password: 'Otherpass123',
    });
    assert.equal(reused.status, 400);

    const oldPassword = await login(email, password);
    assertError(oldPassword, 401, 'invalid_credentials');
    const next = await login(email, 'Newpass123');
    assert.equal(next.status, 200);
    assert.equal((await request(app).get('/api/auth/me').set(bearer(created.body.token))).status, 401);
  });

  it('не пускает четвёртый сеанс, пока не закрыт самый старый', async () => {
    const email = `sessions-${randomUUID()}@test.local`;
    const password = 'Secret123';
    const created = await request(app).post('/api/auth/register').send({
      name: 'Сеансы',
      email,
      password,
    });
    assert.equal(created.status, 201);

    const second = await login(email, password);
    const third = await login(email, password);
    assert.equal(third.status, 200);
    const fourth = await login(email, password);
    assertError(fourth, 409, 'too_many_sessions');

    const replaced = await login(email, password, { revokeOldest: true });
    assert.equal(replaced.status, 200);
    const sessions = await request(app).get('/api/auth/sessions').set(bearer(replaced.body.token));
    assert.equal(sessions.status, 200);
    assert.equal(sessions.body.sessions.length, 3);
    assert.equal(sessions.body.limit, 3);

    const evicted = await request(app).get('/api/auth/me').set(bearer(created.body.token));
    assert.equal(evicted.status, 401);
    assert.equal((await request(app).get('/api/auth/me').set(bearer(second.body.token))).status, 200);

    const current = sessions.body.sessions.find((item) => item.current);
    const logout = await request(app).delete(`/api/auth/sessions/${current.id}`).set(bearer(replaced.body.token));
    assert.equal(logout.status, 204);
    assert.equal((await request(app).get('/api/auth/me').set(bearer(replaced.body.token))).status, 401);
  });

  it('не даёт снять последнего администратора и меняет чужую роль', async () => {
    const admin = await login('admin@library.local', 'Admin123!');
    const self = await request(app)
      .patch(`/api/users/${admin.body.user.id}`)
      .set(bearer(admin.body.token))
      .send({ role: 'librarian' });
    assertError(self, 409, 'last_admin');

    const email = `promote-${randomUUID()}@test.local`;
    const created = await request(app).post('/api/auth/register').send({
      name: 'Повышение',
      email,
      password: 'Secret123',
    });
    const promoted = await request(app)
      .patch(`/api/users/${created.body.user.id}`)
      .set(bearer(admin.body.token))
      .send({ role: 'librarian' });
    assert.equal(promoted.status, 200);
    assert.equal(promoted.body.user.role, 'librarian');

    const token = (await login(email, 'Secret123')).body.token;
    const title = `[test] promote ${randomUUID()}`;
    const added = await request(app).post('/api/books').set(bearer(token)).send(bookBody(title));
    assert.equal(added.status, 201);

    const demoted = await request(app)
      .patch(`/api/users/${created.body.user.id}`)
      .set(bearer(admin.body.token))
      .send({ role: 'reader' });
    assert.equal(demoted.status, 200);
    const again = await request(app).post('/api/books').set(bearer(token)).send(bookBody(`${title} 2`));
    assert.equal(again.status, 403);
    await request(app).delete(`/api/books/${added.body.book.id}`).set(bearer(admin.body.token));
  });

  it('считает просроченный и чужой ключ недействительным', async () => {
    const expired = signToken(
      { sub: 1, role: 'reader', jti: randomUUID() },
      process.env.JWT_SECRET,
      Math.floor(Date.now() / 1000) - 10,
    );
    const old = await request(app).get('/api/books').set(bearer(expired.token));
    assertError(old, 401, 'token_expired');

    const unknown = signToken(
      { sub: 1, role: 'admin', jti: randomUUID() },
      process.env.JWT_SECRET,
      Math.floor(Date.now() / 1000) + 60,
    );
    const revoked = await request(app).get('/api/auth/me').set(bearer(unknown.token));
    assertError(revoked, 401, 'session_revoked');
  });
});
