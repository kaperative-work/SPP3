import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import express from 'express';
import { authRouter } from './auth.js';
import { booksRouter } from './books.js';
import { assertConfig, lockoutPolicy } from './config.js';
import { initDb, pool, waitForDb } from './db.js';
import { HttpError, errorHandler, sendError, wrap } from './errors.js';
import { ensureUploadDir, uploadDir } from './files.js';
import { clientIp } from './ip.js';
import { logger } from './logger.js';
import { accessMeta } from './permissions.js';
import { usersRouter } from './users.js';
import { GENRES, YEAR_MIN, yearMax } from './validate.js';

const maxCoverBytes = 5 * 1024 * 1024;

export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use((req, res, next) => {
    const started = Date.now();
    req.id = randomUUID();
    res.setHeader('X-Request-Id', req.id);
    res.on('finish', () => {
      const fields = {
        requestId: req.id,
        method: req.method,
        path: req.originalUrl.split('?')[0],
        status: res.statusCode,
        durationMs: Date.now() - started,
        ip: clientIp(req),
        userId: req.user?.id ?? null,
      };
      if (fields.path === '/api/health') logger.debug('request', fields);
      else logger.info('request', fields);
    });
    next();
  });

  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Expose-Headers', 'Location, Retry-After, X-Request-Id');
    if (req.method === 'OPTIONS') {
      res.sendStatus(204);
      return;
    }
    next();
  });

  app.use(express.json({ limit: '100kb' }));

  app.get('/api/health', wrap(async (req, res) => {
    try {
      await pool.query('SELECT 1');
    } catch (error) {
      logger.error('health_failed', { requestId: req.id, message: error.message });
      throw new HttpError(503, 'База данных недоступна');
    }
    res.json({ ok: true });
  }));

  app.get('/api/meta', (req, res) => {
    const policy = lockoutPolicy();
    res.json({
      genres: GENRES,
      yearMin: YEAR_MIN,
      yearMax: yearMax(),
      maxCoverBytes,
      ...accessMeta(),
      loginMaxFailures: policy.maxFailures,
      loginLockMinutes: Math.round(policy.lockMs / 60000),
    });
  });

  app.use('/api/auth', authRouter);
  app.use('/api/users', usersRouter);
  app.use('/api/books', booksRouter);

  app.use('/uploads', express.static(uploadDir, {
    index: false,
    fallthrough: true,
    dotfiles: 'deny',
  }));

  app.use((req, res) => {
    const message = req.path.startsWith('/uploads/') ? 'Файл не найден' : 'Ресурс не найден';
    sendError(res, 404, message);
  });

  app.use(errorHandler);
  return app;
}

export const app = createApp();

function isDirectRun() {
  const entry = process.argv[1];
  if (!entry) return false;
  return pathToFileURL(path.resolve(entry)).href.toLowerCase() === import.meta.url.toLowerCase();
}

async function main() {
  assertConfig();
  await waitForDb();
  await initDb();
  await ensureUploadDir();
  const port = Number(process.env.PORT) || 3000;
  const server = app.listen(port, () => {
    logger.info('listen', { port });
  });

  let stopping = false;
  const shutdown = async () => {
    if (stopping) return;
    stopping = true;
    logger.info('shutdown');
    server.close();
    await pool.end();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

if (isDirectRun()) {
  main().catch((error) => {
    logger.error('startup_failed', { message: error.message, stack: error.stack });
    process.exit(1);
  });
}
