import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { HttpError } from './errors.js';

function base64url(value) {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value);
  return buffer.toString('base64url');
}

export function hashToken(token) {
  return createHash('sha256').update(String(token)).digest('hex');
}

export function signToken(claims, secret, exp) {
  if (!secret || secret.length < 16) {
    throw new Error('JWT_SECRET должен быть не короче 16 символов');
  }
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64url(JSON.stringify({
    ...claims,
    iat: Math.floor(Date.now() / 1000),
    exp,
  }));
  const data = `${header}.${body}`;
  const signature = createHmac('sha256', secret).update(data).digest('base64url');
  return {
    token: `${data}.${signature}`,
    expiresAt: new Date(exp * 1000).toISOString(),
  };
}

export function verifyToken(token, secret) {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length !== 3) {
    throw new HttpError(401, 'Недействительный ключ доступа', [], 'invalid_token');
  }
  const [headerPart, bodyPart, signaturePart] = parts;
  const expected = createHmac('sha256', secret).update(`${headerPart}.${bodyPart}`).digest('base64url');
  const actualBuffer = Buffer.from(signaturePart);
  const expectedBuffer = Buffer.from(expected);
  if (actualBuffer.length !== expectedBuffer.length || !timingSafeEqual(actualBuffer, expectedBuffer)) {
    throw new HttpError(401, 'Недействительный ключ доступа', [], 'invalid_token');
  }

  let header;
  let payload;
  try {
    header = JSON.parse(Buffer.from(headerPart, 'base64url').toString('utf8'));
    payload = JSON.parse(Buffer.from(bodyPart, 'base64url').toString('utf8'));
  } catch {
    throw new HttpError(401, 'Недействительный ключ доступа', [], 'invalid_token');
  }

  if (header?.alg !== 'HS256' || header?.typ !== 'JWT' || typeof payload !== 'object' || payload === null) {
    throw new HttpError(401, 'Недействительный ключ доступа', [], 'invalid_token');
  }
  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) {
    throw new HttpError(401, 'Недействительный ключ доступа', [], 'invalid_token');
  }
  if (payload.exp <= Math.floor(Date.now() / 1000)) {
    throw new HttpError(401, 'Срок действия ключа истёк', [], 'token_expired');
  }
  return payload;
}
