const TOKEN_KEY = 'library.token';

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

async function request(method, url, { body, signal } = {}) {
  const headers = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const options = { method, signal, cache: 'no-store', headers };
  if (body instanceof FormData) {
    options.body = body;
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }

  let response;
  try {
    response = await fetch(url, options);
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    const failure = new Error('Нет соединения с сервером. Проверьте, что контейнеры запущены.');
    failure.details = [];
    throw failure;
  }

  if (response.status === 204) return null;

  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }

  if (!response.ok) {
    const failure = new Error(data?.error || `Ошибка сервера (${response.status})`);
    failure.status = response.status;
    failure.code = data?.code || '';
    failure.details = Array.isArray(data?.details) ? data.details : [];
    const retryHeader = Number(response.headers.get('Retry-After'));
    const retryBody = Number(data?.retryAfter);
    if (Number.isFinite(retryBody) && retryBody > 0) failure.retryAfter = retryBody;
    else if (Number.isFinite(retryHeader) && retryHeader > 0) failure.retryAfter = retryHeader;
    throw failure;
  }

  return data;
}

export const api = {
  meta() {
    return request('GET', '/api/meta');
  },
  login(body) {
    return request('POST', '/api/auth/login', { body });
  },
  register(body) {
    return request('POST', '/api/auth/register', { body });
  },
  forgot(body) {
    return request('POST', '/api/auth/forgot-password', { body });
  },
  reset(body) {
    return request('POST', '/api/auth/reset-password', { body });
  },
  me() {
    return request('GET', '/api/auth/me');
  },
  logout() {
    return request('POST', '/api/auth/logout');
  },
  sessions() {
    return request('GET', '/api/auth/sessions');
  },
  revokeSession(id) {
    return request('DELETE', `/api/auth/sessions/${id}`);
  },
  users() {
    return request('GET', '/api/users');
  },
  setRole(id, role) {
    return request('PATCH', `/api/users/${id}`, { body: { role } });
  },
  list({ q, genre, signal }) {
    const params = new URLSearchParams();
    if (q) params.set('q', q);
    if (genre) params.set('genre', genre);
    const query = params.toString();
    return request('GET', `/api/books${query ? `?${query}` : ''}`, { signal });
  },
  get(id) {
    return request('GET', `/api/books/${id}`);
  },
  create(body) {
    return request('POST', '/api/books', { body });
  },
  update(id, body) {
    return request('PUT', `/api/books/${id}`, { body });
  },
  remove(id) {
    return request('DELETE', `/api/books/${id}`);
  },
  uploadCover(id, file) {
    const body = new FormData();
    body.append('cover', file);
    return request('PUT', `/api/books/${id}/cover`, { body });
  },
  removeCover(id) {
    return request('DELETE', `/api/books/${id}/cover`);
  },
};
