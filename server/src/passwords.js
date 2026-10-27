import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

export function passwordIssue(password, { enforcePolicy = true } = {}) {
  if (typeof password !== 'string' || password.length === 0) return 'Укажите пароль';
  if (password.length > 200) return 'Пароль не длиннее 200 символов';
  if (!enforcePolicy) return '';
  if (password.length < 8) return 'Пароль не короче 8 символов';
  if (!/\p{L}/u.test(password) || !/\p{N}/u.test(password)) {
    return 'Пароль должен содержать букву и цифру';
  }
  return '';
}

export async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const hash = (await scryptAsync(password, salt, 64, SCRYPT_PARAMS)).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

const dummyHashPromise = hashPassword('dummy-password-not-used');

async function verifyAgainst(password, stored) {
  const [, salt, hash] = String(stored).split('$');
  const actual = await scryptAsync(password, salt, 64, SCRYPT_PARAMS);
  const expected = Buffer.from(hash, 'hex');
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(actual, expected);
}

export async function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') {
    await verifyAgainst(password, await dummyHashPromise);
    return false;
  }
  return verifyAgainst(password, stored);
}
