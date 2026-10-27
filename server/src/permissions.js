import { maxSessions, tokenTtlSec } from './config.js';

export const ROLES = ['reader', 'librarian', 'admin'];

export const ROLE_LABELS = {
  reader: 'Читатель',
  librarian: 'Библиотекарь',
  admin: 'Администратор',
};

export const PERMISSIONS = {
  'books:read': ['reader', 'librarian', 'admin'],
  'books:write': ['librarian', 'admin'],
  'books:delete': ['admin'],
  'users:manage': ['admin'],
};

export function can(role, action) {
  return PERMISSIONS[action]?.includes(role) ?? false;
}

export function actionsFor(role) {
  return Object.entries(PERMISSIONS)
    .filter(([, roles]) => roles.includes(role))
    .map(([action]) => action);
}

export function accessMeta(env = process.env) {
  return {
    roles: ROLES.map((id) => ({ id, label: ROLE_LABELS[id] })),
    permissions: Object.fromEntries(ROLES.map((role) => [role, actionsFor(role)])),
    sessionLimit: maxSessions(env),
    tokenTtlMinutes: Math.round(tokenTtlSec(env) / 60),
  };
}
