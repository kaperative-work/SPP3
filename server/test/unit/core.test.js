import assert from 'node:assert/strict';
import express from 'express';
import { describe, it } from 'node:test';
import request from 'supertest';
import { maxSessions, tokenTtlSec } from '../../src/config.js';
import { HttpError, errorBody, errorHandler, wrap } from '../../src/errors.js';
import { emailIssue, nameIssue, normalizeEmail } from '../../src/fields.js';
import { clientIp } from '../../src/ip.js';
import { guardBlocked, recordFailure } from '../../src/lockout.js';
import { createLogger } from '../../src/logger.js';
import { deliverMail } from '../../src/mail.js';
import { hashPassword, passwordIssue, verifyPassword } from '../../src/passwords.js';
import { ROLES, can } from '../../src/permissions.js';
import { hashToken, signToken, verifyToken } from '../../src/tokens.js';
import { parseId, validateBook } from '../../src/validate.js';

const SECRET = 'integration-test-secret';

describe('пароли, почта и поля', () => {
  it('принимает пароль с буквой и цифрой и отличает неверный', async () => {
    assert.match(passwordIssue('short'), /8/);
    assert.match(passwordIssue('longpassword'), /цифр/);
    assert.equal(passwordIssue('Goodpass1'), '');
    assert.equal(passwordIssue('x', { enforcePolicy: false }), '');
    const hash = await hashPassword('Goodpass1');
    assert.equal(await verifyPassword('Goodpass1', hash), true);
    assert.equal(await verifyPassword('Goodpass2', hash), false);
    assert.equal(await verifyPassword('Goodpass1', 'broken'), false);
  });

  it('нормализует почту и имя', () => {
    assert.equal(normalizeEmail('  A@B.C '), 'a@b.c');
    assert.equal(emailIssue(''), 'Укажите электронную почту');
    assert.equal(emailIssue('not-an-email'), 'Некорректный адрес почты');
    assert.equal(emailIssue('user@library.local'), '');
    assert.equal(nameIssue(''), 'Укажите имя');
    assert.equal(nameIssue('Анна'), '');
  });
});

describe('временный ключ', () => {
  it('подписывает и проверяет JWT, отвергает подмену и просрочку', () => {
    const exp = Math.floor(Date.now() / 1000) + 60;
    const { token } = signToken({ sub: 7, role: 'reader', jti: 'session-1' }, SECRET, exp);
    const payload = verifyToken(token, SECRET);
    assert.equal(payload.sub, 7);
    assert.equal(payload.role, 'reader');
    assert.equal(hashToken('same').length, 64);

    const [header, body, signature] = token.split('.');
    const flipped = body.endsWith('a') ? 'b' : 'a';
    const tampered = `${header}.${body.slice(0, -1)}${flipped}.${signature}`;
    assert.throws(() => verifyToken(tampered, SECRET), (error) => error.code === 'invalid_token');

    const expired = signToken({ sub: 1, jti: 'old' }, SECRET, Math.floor(Date.now() / 1000) - 5);
    assert.throws(() => verifyToken(expired.token, SECRET), (error) => error.code === 'token_expired');
  });
});

describe('роли и блокировка', () => {
  it('различает три роли', () => {
    assert.deepEqual(ROLES, ['reader', 'librarian', 'admin']);
    assert.equal(can('reader', 'books:read'), true);
    assert.equal(can('reader', 'books:write'), false);
    assert.equal(can('reader', 'books:delete'), false);
    assert.equal(can('librarian', 'books:write'), true);
    assert.equal(can('librarian', 'books:delete'), false);
    assert.equal(can('admin', 'books:delete'), true);
    assert.equal(can('admin', 'users:manage'), true);
    assert.equal(can('guest', 'books:read'), false);
  });

  it('блокирует ключ после порога и сбрасывает окно', () => {
    const policy = { maxFailures: 5, windowMs: 1000, lockMs: 5000 };
    let state = null;
    for (let index = 0; index < 4; index += 1) state = recordFailure(state, 100, policy);
    assert.equal(guardBlocked(state, 100).locked, false);
    state = recordFailure(state, 100, policy);
    const blocked = guardBlocked(state, 100);
    assert.equal(blocked.locked, true);
    assert.ok(blocked.retryAfterSec >= 1);
    assert.equal(guardBlocked(state, 100 + 5000).locked, false);
    assert.equal(recordFailure(state, 100 + 1000, policy).failedCount, 1);
  });

  it('берёт адрес клиента только от доверенного прокси', () => {
    assert.equal(clientIp({
      socket: { remoteAddress: '8.8.8.8' },
      headers: { 'x-real-ip': '203.0.113.5', 'x-forwarded-for': '198.51.100.4' },
    }), '8.8.8.8');
    assert.equal(clientIp({
      socket: { remoteAddress: '172.18.0.3' },
      headers: { 'x-real-ip': '203.0.113.8' },
    }), '203.0.113.8');
    assert.equal(maxSessions({}), 3);
    assert.equal(maxSessions({ MAX_SESSIONS: '4' }), 4);
    assert.equal(tokenTtlSec({ JWT_TTL_MINUTES: '10' }), 600);
  });
});

describe('каталог и журнал', () => {
  it('проверяет карточку книги', () => {
    const book = validateBook({
      title: 'Название',
      author: 'Автор',
      year: 2000,
      genre: 'Роман',
      description: '',
    });
    assert.equal(book.title, 'Название');
    assert.throws(() => validateBook({ title: '', author: 'Автор', year: 2000, genre: 'Роман' }), (error) => {
      assert.equal(error.status, 400);
      assert.ok(error.details.some((item) => item.field === 'title'));
      return true;
    });
    assert.equal(parseId('12'), 12);
    assert.throws(() => parseId('0'), (error) => error instanceof HttpError);
  });

  it('пишет JSON с уровнем и скрывает пароль', () => {
    const lines = [];
    const logger = createLogger({ write(chunk) { lines.push(chunk); } });
    logger.info('login_failed', { email: 'a@b.c', password: 'secret' });
    logger.debug('skip', { requestId: '1' });
    const entry = JSON.parse(lines[0]);
    assert.equal(lines.length, 1);
    assert.equal(entry.level, 'INFO');
    assert.equal(entry.msg, 'login_failed');
    assert.equal(entry.password, '[redacted]');
    assert.equal(entry.service, 'library-api');
    assert.ok(entry.time);
  });

  it('в учебном режиме кладёт ссылку сброса в результат отправки', async () => {
    const previous = process.env.MAIL_MODE;
    process.env.MAIL_MODE = 'log';
    try {
      const result = await deliverMail({
        to: 'reader@library.local',
        subject: 'Восстановление',
        text: 'ссылка',
        resetUrl: 'http://localhost:8080/#/reset?token=abc',
      });
      assert.equal(result.transport, 'log');
      assert.equal(result.previewUrl, 'http://localhost:8080/#/reset?token=abc');
      process.env.MAIL_MODE = 'smtp';
      delete process.env.SMTP_HOST;
      await assert.rejects(
        () => deliverMail({ to: 'a@b.c', subject: 's', text: 't' }),
        (error) => error.status === 500,
      );
    } finally {
      if (previous === undefined) delete process.env.MAIL_MODE;
      else process.env.MAIL_MODE = previous;
    }
  });
});

describe('ответы об ошибках', () => {
  const app = express();
  app.get('/missing', wrap(async () => {
    throw new HttpError(404, 'Книга не найдена');
  }));
  app.get('/invalid', wrap(async () => {
    throw new HttpError(400, 'Проверьте введённые данные', [{ field: 'title', message: 'Укажите название' }]);
  }));
  app.get('/locked', wrap(async () => {
    throw new HttpError(429, 'Подождите', [], 'too_many_requests', { retryAfter: 12 });
  }));
  app.get('/boom', wrap(async () => {
    throw new Error('secret-token');
  }));
  app.get('/upload', (req, res, next) => {
    const error = new Error('too big');
    error.name = 'MulterError';
    error.code = 'LIMIT_FILE_SIZE';
    next(error);
  });
  app.use(errorHandler);

  it('сохраняет код HTTP, код ошибки и список полей', async () => {
    const missing = await request(app).get('/missing');
    assert.equal(missing.status, 404);
    assert.deepEqual(missing.body, errorBody(404, 'Книга не найдена'));

    const invalid = await request(app).get('/invalid');
    assert.equal(invalid.status, 400);
    assert.equal(invalid.body.details[0].field, 'title');

    const locked = await request(app).get('/locked');
    assert.equal(locked.status, 429);
    assert.equal(locked.headers['retry-after'], '12');
    assert.equal(locked.body.retryAfter, 12);

    const boom = await request(app).get('/boom');
    assert.equal(boom.status, 500);
    assert.equal(boom.body.error, 'Внутренняя ошибка сервера');
    assert.equal(JSON.stringify(boom.body).includes('secret-token'), false);

    const upload = await request(app).get('/upload');
    assert.equal(upload.status, 400);
    assert.equal(upload.body.code, 'upload_error');
  });
});
