import { logger } from './logger.js';

const STATUS_CODES = {
  400: 'bad_request',
  401: 'unauthorized',
  403: 'forbidden',
  404: 'not_found',
  409: 'conflict',
  413: 'payload_too_large',
  415: 'unsupported_media_type',
  429: 'too_many_requests',
  500: 'internal_error',
  502: 'bad_gateway',
  503: 'service_unavailable',
};

export function codeForStatus(status) {
  return STATUS_CODES[status] || 'error';
}

export function errorBody(status, message, details = [], code, extra = {}) {
  return {
    error: message,
    code: code || codeForStatus(status),
    status,
    details: Array.isArray(details) ? details : [],
    ...extra,
  };
}

export function sendError(res, status, message, details = [], code, extra = {}) {
  const body = errorBody(status, message, details, code, extra);
  const fields = {
    requestId: res.req?.id,
    method: res.req?.method,
    path: res.req?.originalUrl,
    status: body.status,
    code: body.code,
    message: body.error,
  };
  if (status >= 500) logger.error('http_error', fields);
  else logger.warn('http_error', fields);
  if (Number.isFinite(body.retryAfter) && body.retryAfter > 0) {
    res.setHeader('Retry-After', String(Math.ceil(body.retryAfter)));
  }
  res.status(status).json(body);
}

export class HttpError extends Error {
  constructor(status, message, details = [], code, extra = {}) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.details = Array.isArray(details) ? details : [];
    this.code = code || codeForStatus(status);
    this.extra = extra && typeof extra === 'object' ? extra : {};
  }
}

export function wrap(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

export function requireJson(req, res, next) {
  const type = String(req.headers['content-type'] || '').toLowerCase();
  if (!type.includes('application/json')) {
    sendError(res, 415, 'Ожидается Content-Type: application/json');
    return;
  }
  next();
}

export function errorHandler(err, req, res, next) {
  if (res.headersSent) {
    next(err);
    return;
  }

  if (err?.name === 'MulterError') {
    const message = err.code === 'LIMIT_FILE_SIZE'
      ? 'Максимальный размер обложки — 5 МБ'
      : 'Не удалось принять файл обложки';
    sendError(res, 400, 'Ошибка загрузки файла', [{ field: 'cover', message }], 'upload_error');
    return;
  }

  if (err?.type === 'entity.parse.failed') {
    sendError(res, 400, 'Некорректный JSON');
    return;
  }

  if (err?.type === 'entity.too.large' || err?.status === 413) {
    sendError(res, 413, 'Слишком большой запрос');
    return;
  }

  if (err?.code === '23514') {
    sendError(res, 400, 'Данные не прошли проверку');
    return;
  }

  if (err instanceof HttpError) {
    sendError(res, err.status, err.message, err.details, err.code, err.extra);
    return;
  }

  logger.error('unhandled_error', {
    requestId: req.id,
    method: req.method,
    path: req.originalUrl,
    message: err?.message,
    stack: err?.stack,
  });
  sendError(res, 500, 'Внутренняя ошибка сервера');
}
