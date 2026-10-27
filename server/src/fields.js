export function normalizeEmail(value) {
  if (typeof value !== 'string') return '';
  return value.trim().toLowerCase();
}

export function emailIssue(value) {
  const email = normalizeEmail(value);
  if (!email) return 'Укажите электронную почту';
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return 'Некорректный адрес почты';
  }
  return '';
}

function hasControlChar(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 32 || code === 127) return true;
  }
  return false;
}

export function nameIssue(value) {
  if (typeof value !== 'string') return 'Укажите имя';
  const name = value.trim();
  if (!name) return 'Укажите имя';
  if (name.length > 100) return 'Имя не длиннее 100 символов';
  if (hasControlChar(name)) return 'Имя содержит недопустимые символы';
  return '';
}

export function trimmedName(value) {
  return String(value).trim();
}
