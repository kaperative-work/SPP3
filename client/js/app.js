import { api, getToken, setToken } from './api.js';

const els = {
  brand: document.getElementById('brand'),
  addBtn: document.getElementById('add-btn'),
  banner: document.getElementById('banner'),
  filters: document.getElementById('filters'),
  search: document.getElementById('search'),
  genreFilter: document.getElementById('genre-filter'),
  listStatus: document.getElementById('list-status'),
  bookList: document.getElementById('book-list'),
  form: document.getElementById('book-form'),
  formTitle: document.getElementById('form-title'),
  title: document.getElementById('field-title'),
  author: document.getElementById('field-author'),
  year: document.getElementById('field-year'),
  genre: document.getElementById('field-genre'),
  description: document.getElementById('field-description'),
  cover: document.getElementById('field-cover'),
  preview: document.getElementById('cover-preview'),
  removeCoverWrap: document.getElementById('remove-cover-wrap'),
  removeCover: document.getElementById('field-remove-cover'),
  cancel: document.getElementById('form-cancel'),
  submit: document.getElementById('form-submit'),
  detail: document.getElementById('detail'),
  missingTitle: document.getElementById('missing-title'),
  missingText: document.getElementById('missing-text'),
  retry: document.getElementById('retry'),
  dialog: document.getElementById('confirm-dialog'),
  confirmText: document.getElementById('confirm-text'),
  sessionBox: document.getElementById('session-box'),
  sessionUser: document.getElementById('session-user'),
  sessionRole: document.getElementById('session-role'),
  sessionExpiry: document.getElementById('session-expiry'),
  sessionsBtn: document.getElementById('sessions-btn'),
  usersLink: document.getElementById('users-link'),
  logoutBtn: document.getElementById('logout-btn'),
  authPolicy: document.getElementById('auth-policy'),
  loginForm: document.getElementById('login-form'),
  loginEmail: document.getElementById('login-email'),
  loginPassword: document.getElementById('login-password'),
  loginSubmit: document.getElementById('login-submit'),
  loginEvict: document.getElementById('login-evict'),
  registerForm: document.getElementById('register-form'),
  registerName: document.getElementById('register-name'),
  registerEmail: document.getElementById('register-email'),
  registerPassword: document.getElementById('register-password'),
  registerSubmit: document.getElementById('register-submit'),
  forgotForm: document.getElementById('forgot-form'),
  forgotEmail: document.getElementById('forgot-email'),
  forgotSubmit: document.getElementById('forgot-submit'),
  forgotResult: document.getElementById('forgot-result'),
  mailPreview: document.getElementById('mail-preview'),
  mailLink: document.getElementById('mail-link'),
  resetForm: document.getElementById('reset-form'),
  resetToken: document.getElementById('reset-token'),
  resetPassword: document.getElementById('reset-password'),
  resetPassword2: document.getElementById('reset-password2'),
  resetSubmit: document.getElementById('reset-submit'),
  userList: document.getElementById('user-list'),
  sessionsDialog: document.getElementById('sessions-dialog'),
  sessionsList: document.getElementById('sessions-list'),
  sessionsClose: document.getElementById('sessions-close'),
};

const views = {
  auth: document.getElementById('view-auth'),
  users: document.getElementById('view-users'),
  list: document.getElementById('view-list'),
  form: document.getElementById('view-form'),
  detail: document.getElementById('view-detail'),
  missing: document.getElementById('view-missing'),
};

const PUBLIC_ROUTES = new Set(['login', 'register', 'forgot', 'reset']);

let meta = null;
let flash = null;
let routeToken = 0;
let listAbort = null;
let listTimer = null;
let previewUrl = null;
let booted = false;
let currentUser = null;
let currentAuth = null;

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[char]));
}

function initial(title) {
  const char = String(title || '').trim().charAt(0);
  return char ? char.toUpperCase() : '?';
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString('ru-RU');
}

function errorText(error) {
  const base = error.status ? `${error.status} — ${error.message}` : (error.message || 'Неизвестная ошибка');
  if (error.retryAfter) return `${base} Повторите через ${error.retryAfter} с.`;
  return base;
}

function roleCan(action) {
  return Boolean(meta?.permissions?.[currentUser?.role]?.includes(action));
}

function roleLabel(role) {
  return meta?.roles?.find((item) => item.id === role)?.label || role || '';
}

function showBanner(kind, text) {
  els.banner.hidden = false;
  els.banner.className = `banner ${kind}`;
  els.banner.setAttribute('role', kind === 'error' ? 'alert' : 'status');
  els.banner.textContent = text;
}

function clearBanner() {
  els.banner.hidden = true;
  els.banner.className = 'banner';
  els.banner.textContent = '';
}

function show(name) {
  if (name !== 'list' && listAbort) {
    listAbort.abort();
    listAbort = null;
  }
  for (const [key, section] of Object.entries(views)) {
    section.hidden = key !== name;
  }
  if (name !== 'missing') els.retry.hidden = true;
}

function showMissing(title, text, withRetry = false) {
  show('missing');
  els.missingTitle.textContent = title;
  els.missingText.textContent = text;
  els.retry.hidden = !withRetry;
}

function renderSession() {
  const loggedIn = Boolean(currentUser);
  els.sessionBox.hidden = !loggedIn;
  els.addBtn.hidden = !roleCan('books:write');
  if (!loggedIn) return;
  els.sessionUser.textContent = currentUser.name;
  els.sessionRole.textContent = roleLabel(currentUser.role);
  const expires = currentAuth?.session?.expiresAt;
  els.sessionExpiry.textContent = expires ? `ключ до ${formatDate(expires)}` : '';
  const limit = currentAuth?.sessionLimit ?? meta?.sessionLimit;
  els.sessionsBtn.textContent = currentAuth?.activeSessions
    ? `Сеансы (${currentAuth.activeSessions}/${limit})`
    : 'Сеансы';
  els.usersLink.hidden = !roleCan('users:manage');
}

function fillPolicy() {
  if (!meta) return;
  els.authPolicy.textContent = `Временный ключ действует ${meta.tokenTtlMinutes} мин. Сеансов одновременно: не больше ${meta.sessionLimit}. После ${meta.loginMaxFailures} неудачных входов адрес и учётная запись блокируются на ${meta.loginLockMinutes} мин.`;
}

function parseRoute() {
  const raw = (location.hash || '#/').slice(1);
  const [path, queryString = ''] = raw.split('?');
  const params = new URLSearchParams(queryString);
  const q = params.get('q') || '';
  const genre = params.get('genre') || '';
  if (path === '' || path === '/') return { name: 'list', q, genre };
  if (path === '/login') return { name: 'login' };
  if (path === '/register') return { name: 'register' };
  if (path === '/forgot') return { name: 'forgot' };
  if (path === '/reset') return { name: 'reset', token: params.get('token') || '' };
  if (path === '/users') return { name: 'users' };
  if (path === '/new') return { name: 'create' };
  let match = path.match(/^\/book\/(\d+)\/edit$/);
  if (match) return { name: 'edit', id: Number(match[1]) };
  match = path.match(/^\/book\/(\d+)$/);
  if (match) return { name: 'detail', id: Number(match[1]) };
  return { name: 'missing' };
}

function writeListHash(q, genre) {
  const params = new URLSearchParams();
  if (q) params.set('q', q);
  if (genre) params.set('genre', genre);
  const next = params.toString() ? `#/?${params.toString()}` : '#/';
  const current = location.hash || '#/';
  if (current !== next) history.replaceState(null, '', next);
}

function fillGenres() {
  const genreOptions = meta.genres
    .map((genre) => `<option value="${escapeHtml(genre)}">${escapeHtml(genre)}</option>`)
    .join('');
  els.genre.innerHTML = `<option value="">Выберите жанр</option>${genreOptions}`;
  els.genreFilter.innerHTML = `<option value="">Все жанры</option>${genreOptions}`;
  els.year.min = String(meta.yearMin);
  els.year.max = String(meta.yearMax);
}

function renderCards(books, { q, genre }) {
  if (!books.length) {
    els.bookList.innerHTML = '';
    els.listStatus.textContent = q || genre
      ? 'Ничего не найдено. Измените запрос или выберите другой жанр.'
      : 'В каталоге пока нет книг.';
    return;
  }

  els.listStatus.textContent = `Найдено: ${books.length}`;
  els.bookList.innerHTML = books.map((book) => {
    const cover = book.coverUrl
      ? `<img src="${escapeHtml(book.coverUrl)}" alt="" data-initial="${escapeHtml(initial(book.title))}">`
      : `<div class="cover-fallback">${escapeHtml(initial(book.title))}</div>`;
    return `
      <a class="card" href="#/book/${book.id}">
        <span class="cover">${cover}</span>
        <span>
          <h2>${escapeHtml(book.title)}</h2>
          <p class="author">${escapeHtml(book.author)}</p>
          <p class="meta"><span class="badge">${escapeHtml(book.genre)}</span> ${book.year}</p>
        </span>
      </a>
    `;
  }).join('');

  els.bookList.querySelectorAll('img').forEach((img) => {
    img.addEventListener('error', () => replaceWithFallback(img));
  });
}

function replaceWithFallback(img) {
  const fallback = document.createElement('div');
  fallback.className = 'cover-fallback';
  fallback.textContent = img.dataset.initial || '?';
  img.replaceWith(fallback);
}

async function fetchList(token) {
  if (listAbort) listAbort.abort();
  const controller = new AbortController();
  listAbort = controller;
  const q = els.search.value.trim();
  const genre = els.genreFilter.value;
  writeListHash(q, genre);
  els.listStatus.textContent = 'Загрузка…';

  try {
    const data = await api.list({ q, genre, signal: controller.signal });
    if (token && token !== routeToken) return;
    renderCards(data.books, { q, genre });
  } catch (error) {
    if (error.name === 'AbortError') return;
    if (token && token !== routeToken) return;
    if (handleAuthError(error)) return;
    els.listStatus.textContent = '';
    els.bookList.innerHTML = '';
    showBanner('error', errorText(error));
  }
}

function scheduleList() {
  clearTimeout(listTimer);
  listTimer = setTimeout(() => { void fetchList(); }, 250);
}

function clearFieldErrors(root = document) {
  root.querySelectorAll('.field-error').forEach((item) => {
    item.textContent = '';
  });
  root.querySelectorAll('[aria-invalid="true"]').forEach((item) => {
    item.removeAttribute('aria-invalid');
  });
}

function showFieldErrors(details, root = document) {
  for (const detail of details || []) {
    if (!detail || typeof detail.field !== 'string') continue;
    const message = root.querySelector(`[data-error-for="${CSS.escape(detail.field)}"]`);
    const field = root.querySelector(`#field-${CSS.escape(detail.field)}`)
      || root.querySelector(`[name="${CSS.escape(detail.field)}"]`);
    if (message) message.textContent = detail.message;
    if (field) field.setAttribute('aria-invalid', 'true');
  }
}

function hidePreview() {
  if (previewUrl) {
    URL.revokeObjectURL(previewUrl);
    previewUrl = null;
  }
  els.preview.hidden = true;
  els.preview.removeAttribute('src');
}

function setPreview(url, isBlob) {
  hidePreview();
  if (isBlob) previewUrl = url;
  els.preview.src = url;
  els.preview.hidden = false;
}

function readPayload() {
  const rawYear = els.year.value.trim();
  return {
    title: els.title.value.trim(),
    author: els.author.value.trim(),
    year: /^-?\d+$/.test(rawYear) ? Number(rawYear) : rawYear,
    genre: els.genre.value,
    description: els.description.value.trim(),
  };
}

function validateForm(payload) {
  const details = [];
  if (!payload.title) details.push({ field: 'title', message: 'Укажите название' });
  else if (payload.title.length > 200) details.push({ field: 'title', message: 'Название не длиннее 200 символов' });

  if (!payload.author) details.push({ field: 'author', message: 'Укажите автора' });
  else if (payload.author.length > 200) details.push({ field: 'author', message: 'Имя автора не длиннее 200 символов' });

  if (typeof payload.year !== 'number') {
    details.push({ field: 'year', message: 'Укажите год издания целым числом' });
  } else if (payload.year < meta.yearMin || payload.year > meta.yearMax) {
    details.push({ field: 'year', message: `Год должен быть от ${meta.yearMin} до ${meta.yearMax}` });
  }

  if (!meta.genres.includes(payload.genre)) {
    details.push({ field: 'genre', message: 'Выберите жанр из списка' });
  }

  if (payload.description.length > 4000) {
    details.push({ field: 'description', message: 'Описание не длиннее 4000 символов' });
  }
  return details;
}

function validateFile(file) {
  const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
  if (file.type && !allowed.includes(file.type)) {
    return { field: 'cover', message: 'Допустимы только изображения JPEG, PNG, WEBP и GIF' };
  }
  if (file.size === 0) return { field: 'cover', message: 'Файл пустой' };
  if (file.size > meta.maxCoverBytes) {
    return { field: 'cover', message: 'Максимальный размер обложки — 5 МБ' };
  }
  return null;
}

function setBusy(busy) {
  els.submit.disabled = busy;
  els.cancel.disabled = busy;
  els.submit.textContent = busy
    ? 'Сохранение…'
    : (els.form.dataset.id ? 'Сохранить' : 'Добавить');
}

async function showList(route, token) {
  show('list');
  if (document.activeElement !== els.search) els.search.value = route.q;
  if (els.genreFilter.value !== route.genre) els.genreFilter.value = route.genre;
  await fetchList(token);
}

async function showForm(id, token) {
  show('form');
  clearFieldErrors(els.form);
  els.form.reset();
  hidePreview();
  els.form.dataset.id = id ? String(id) : '';
  els.formTitle.textContent = id ? 'Редактирование' : 'Новая книга';
  els.submit.textContent = id ? 'Сохранить' : 'Добавить';
  els.submit.disabled = false;
  els.cancel.disabled = false;
  els.removeCoverWrap.hidden = true;
  if (!id) {
    els.title.focus();
    return;
  }

  els.submit.disabled = true;
  try {
    const { book } = await api.get(id);
    if (token !== routeToken) return;
    els.title.value = book.title;
    els.author.value = book.author;
    els.year.value = String(book.year);
    els.genre.value = book.genre;
    els.description.value = book.description;
    if (book.coverUrl) {
      els.removeCoverWrap.hidden = false;
      setPreview(book.coverUrl, false);
    }
  } catch (error) {
    if (token !== routeToken) return;
    if (handleAuthError(error)) return;
    const notFound = error.status === 404;
    showMissing(
      notFound ? 'Книга не найдена' : 'Не удалось открыть форму',
      errorText(error),
    );
  } finally {
    if (token === routeToken) els.submit.disabled = false;
  }
}

function renderDetail(book) {
  const cover = book.coverUrl
    ? `<img class="detail-cover" src="${escapeHtml(book.coverUrl)}" alt="Обложка: ${escapeHtml(book.title)}" data-initial="${escapeHtml(initial(book.title))}">`
    : `<div class="cover-fallback detail-cover">${escapeHtml(initial(book.title))}</div>`;
  const description = book.description
    ? `<p class="description">${escapeHtml(book.description)}</p>`
    : '<p class="muted">Описание не указано</p>';
  const edit = roleCan('books:write')
    ? `<a class="button" href="#/book/${book.id}/edit">Изменить</a>`
    : '';
  const remove = roleCan('books:delete')
    ? '<button class="button danger" id="delete-book" type="button">Удалить</button>'
    : '';

  els.detail.innerHTML = `
    <div class="detail-layout">
      <div>${cover}</div>
      <div>
        <p class="eyebrow">${escapeHtml(book.genre)} · ${book.year}</p>
        <h1>${escapeHtml(book.title)}</h1>
        <p class="author">${escapeHtml(book.author)}</p>
        ${description}
        <p class="muted">Обновлено: ${escapeHtml(formatDate(book.updatedAt))}</p>
        <div class="actions">
          <a class="button secondary" href="#/">К каталогу</a>
          ${edit}
          ${remove}
        </div>
      </div>
    </div>
  `;

  const image = els.detail.querySelector('img');
  if (image) {
    image.addEventListener('error', () => {
      const fallback = document.createElement('div');
      fallback.className = 'cover-fallback detail-cover';
      fallback.textContent = image.dataset.initial || '?';
      image.replaceWith(fallback);
    });
  }
  const deleteButton = els.detail.querySelector('#delete-book');
  if (deleteButton) {
    deleteButton.addEventListener('click', () => {
      void onDelete(book);
    });
  }
}

async function showDetail(id, token) {
  show('detail');
  els.detail.innerHTML = '<p class="muted">Загрузка…</p>';
  try {
    const { book } = await api.get(id);
    if (token !== routeToken) return;
    renderDetail(book);
  } catch (error) {
    if (token !== routeToken) return;
    if (handleAuthError(error)) return;
    const notFound = error.status === 404;
    showMissing(
      notFound ? 'Книга не найдена' : 'Не удалось открыть книгу',
      errorText(error),
    );
  }
}

function showAuth(name, route) {
  show('auth');
  els.loginForm.hidden = name !== 'login';
  els.registerForm.hidden = name !== 'register';
  els.forgotForm.hidden = name !== 'forgot';
  els.resetForm.hidden = name !== 'reset';
  els.loginEvict.hidden = true;
  if (name !== 'forgot') {
    els.mailPreview.hidden = true;
    els.forgotResult.textContent = '';
  }
  if (name === 'reset') {
    const token = route?.token || '';
    if (document.activeElement !== els.resetToken) els.resetToken.value = token;
  }
}

async function ensureUser() {
  const data = await api.me();
  currentUser = data.user;
  currentAuth = data;
  renderSession();
}

function handleAuthError(error) {
  if (error?.status !== 401 || error.code === 'invalid_credentials') return false;
  setToken(null);
  currentUser = null;
  currentAuth = null;
  renderSession();
  flash = { kind: 'error', text: 'Сеанс недействителен или срок ключа истёк. Войдите снова.' };
  if (parseRoute().name !== 'login') {
    location.hash = '#/login';
    return true;
  }
  showBanner('error', flash.text);
  flash = null;
  return true;
}

function rememberReturn() {
  const route = parseRoute();
  if (!PUBLIC_ROUTES.has(route.name)) {
    sessionStorage.setItem('library.next', location.hash || '#/');
  }
}

function consumeNext() {
  const next = sessionStorage.getItem('library.next') || '#/';
  sessionStorage.removeItem('library.next');
  if (!next.startsWith('#/') || next.startsWith('#/login') || next.startsWith('#/register')) return '#/';
  return next;
}

async function renderRoute() {
  const token = ++routeToken;
  const message = flash;
  flash = null;
  clearFieldErrors();
  if (message) showBanner(message.kind, message.text);
  else clearBanner();

  try {
    if (getToken()) await ensureUser();
    else {
      currentUser = null;
      currentAuth = null;
      renderSession();
    }
  } catch (error) {
    if (token !== routeToken) return;
    if (error.status === 401) {
      setToken(null);
      currentUser = null;
      currentAuth = null;
      renderSession();
      if (parseRoute().name !== 'login') {
        flash = { kind: 'error', text: 'Сеанс недействителен или срок ключа истёк. Войдите снова.' };
        location.hash = '#/login';
        return;
      }
      showBanner('error', 'Сеанс недействителен или срок ключа истёк. Войдите снова.');
    } else {
      showMissing('Сервер недоступен', errorText(error), true);
      return;
    }
  }

  if (token !== routeToken) return;
  const route = parseRoute();
  if (!currentUser && !PUBLIC_ROUTES.has(route.name)) {
    rememberReturn();
    location.hash = '#/login';
    return;
  }
  if (currentUser && (route.name === 'login' || route.name === 'register')) {
    location.hash = consumeNext();
    return;
  }

  if (route.name === 'list') await showList(route, token);
  else if (route.name === 'create') await showForm(null, token);
  else if (route.name === 'edit') await showForm(route.id, token);
  else if (route.name === 'detail') await showDetail(route.id, token);
  else if (route.name === 'users') await showUsers(token);
  else if (route.name === 'login') showAuth('login');
  else if (route.name === 'register') showAuth('register');
  else if (route.name === 'forgot') showAuth('forgot');
  else if (route.name === 'reset') showAuth('reset', route);
  else showMissing('Страница не найдена', 'Такого адреса в приложении нет.');
}

function askDelete(title) {
  els.confirmText.textContent = `Удалить книгу «${title}»? Это действие нельзя отменить.`;
  els.dialog.showModal();
  return new Promise((resolve) => {
    els.dialog.addEventListener('close', () => {
      resolve(els.dialog.returnValue === 'confirm');
    }, { once: true });
  });
}

async function onDelete(book) {
  const confirmed = await askDelete(book.title);
  if (!confirmed) return;
  try {
    await api.remove(book.id);
    flash = { kind: 'ok', text: 'Книга удалена' };
    location.hash = '#/';
  } catch (error) {
    if (handleAuthError(error)) return;
    showBanner('error', errorText(error));
  }
}

async function onSubmit(event) {
  event.preventDefault();
  clearFieldErrors(els.form);
  clearBanner();
  const payload = readPayload();
  const details = validateForm(payload);
  const file = els.cover.files[0];
  if (file) {
    const fileError = validateFile(file);
    if (fileError) details.push(fileError);
  }
  if (details.length) {
    showFieldErrors(details, els.form);
    showBanner('error', 'Проверьте введённые данные');
    return;
  }

  const editingId = els.form.dataset.id;
  setBusy(true);
  try {
    const saved = editingId
      ? await api.update(editingId, payload)
      : await api.create(payload);
    let book = saved.book;

    if (file) {
      try {
        book = (await api.uploadCover(book.id, file)).book;
      } catch (error) {
        flash = {
          kind: 'error',
          text: `Книга сохранена, но обложку загрузить не удалось. ${errorText(error)}`,
        };
        location.hash = `#/book/${book.id}`;
        return;
      }
    } else if (editingId && els.removeCover.checked) {
      book = (await api.removeCover(book.id)).book;
    }

    flash = { kind: 'ok', text: editingId ? 'Изменения сохранены' : 'Книга добавлена' };
    location.hash = `#/book/${book.id}`;
  } catch (error) {
    if (handleAuthError(error)) return;
    showBanner('error', errorText(error));
    showFieldErrors(error.details, els.form);
  } finally {
    setBusy(false);
  }
}

async function onLogin(event, revokeOldest = false) {
  event?.preventDefault();
  clearFieldErrors(els.loginForm);
  clearBanner();
  els.loginEvict.hidden = true;
  els.loginSubmit.disabled = true;
  try {
    const result = await api.login({
      email: els.loginEmail.value.trim(),
      password: els.loginPassword.value,
      revokeOldest,
    });
    setToken(result.token);
    flash = { kind: 'ok', text: `Вход выполнен. Ключ действует до ${formatDate(result.expiresAt)}.` };
    location.hash = consumeNext();
  } catch (error) {
    showBanner('error', errorText(error));
    showFieldErrors(error.details, els.loginForm);
    els.loginEvict.hidden = error.code !== 'too_many_sessions';
  } finally {
    els.loginSubmit.disabled = false;
  }
}

async function onRegister(event) {
  event.preventDefault();
  clearFieldErrors(els.registerForm);
  clearBanner();
  els.registerSubmit.disabled = true;
  try {
    const result = await api.register({
      name: els.registerName.value.trim(),
      email: els.registerEmail.value.trim(),
      password: els.registerPassword.value,
    });
    setToken(result.token);
    flash = { kind: 'ok', text: 'Учётная запись создана. Назначена роль «Читатель».' };
    location.hash = '#/';
  } catch (error) {
    showBanner('error', errorText(error));
    showFieldErrors(error.details, els.registerForm);
  } finally {
    els.registerSubmit.disabled = false;
  }
}

async function onForgot(event) {
  event.preventDefault();
  clearFieldErrors(els.forgotForm);
  clearBanner();
  els.mailPreview.hidden = true;
  els.forgotResult.textContent = '';
  els.forgotSubmit.disabled = true;
  try {
    const data = await api.forgot({ email: els.forgotEmail.value.trim() });
    els.forgotResult.textContent = data.message;
    if (data.previewUrl) {
      els.mailPreview.hidden = false;
      els.mailLink.href = data.previewUrl;
      els.mailLink.textContent = data.previewUrl;
    }
  } catch (error) {
    showBanner('error', errorText(error));
    showFieldErrors(error.details, els.forgotForm);
  } finally {
    els.forgotSubmit.disabled = false;
  }
}

async function onReset(event) {
  event.preventDefault();
  clearFieldErrors(els.resetForm);
  clearBanner();
  if (els.resetPassword.value !== els.resetPassword2.value) {
    showFieldErrors([{ field: 'passwordConfirm', message: 'Пароли не совпадают' }], els.resetForm);
    showBanner('error', 'Проверьте введённые данные');
    return;
  }
  els.resetSubmit.disabled = true;
  try {
    const data = await api.reset({
      token: els.resetToken.value.trim(),
      password: els.resetPassword.value,
    });
    setToken(null);
    currentUser = null;
    currentAuth = null;
    flash = { kind: 'ok', text: data.message };
    location.hash = '#/login';
  } catch (error) {
    showBanner('error', errorText(error));
    showFieldErrors(error.details, els.resetForm);
  } finally {
    els.resetSubmit.disabled = false;
  }
}

async function onLogout() {
  try {
    await api.logout();
  } catch {
    // локальный ключ всё равно удаляем
  }
  setToken(null);
  currentUser = null;
  currentAuth = null;
  if (els.sessionsDialog.open) els.sessionsDialog.close();
  flash = { kind: 'ok', text: 'Вы вышли из системы' };
  location.hash = '#/login';
}

async function openSessions() {
  try {
    const data = await api.sessions();
    currentAuth = {
      ...(currentAuth || {}),
      activeSessions: data.sessions.length,
      sessionLimit: data.limit,
      session: currentAuth?.session,
    };
    renderSession();
    els.sessionsList.innerHTML = data.sessions.map((session) => `
      <div class="session-item">
        <p>
          ${escapeHtml(formatDate(session.createdAt))} · ${escapeHtml(session.ip || 'неизвестный адрес')}
          <br>
          <span class="muted">до ${escapeHtml(formatDate(session.expiresAt))}${session.current ? ' · этот сеанс' : ''}</span>
        </p>
        <button class="button danger" type="button" data-session-id="${escapeHtml(session.id)}">Завершить</button>
      </div>
    `).join('') || '<p class="muted">Активных сеансов нет.</p>';
    if (!els.sessionsDialog.open) els.sessionsDialog.showModal();
  } catch (error) {
    if (handleAuthError(error)) return;
    showBanner('error', errorText(error));
  }
}

async function revokeSession(id) {
  try {
    await api.revokeSession(id);
    if (currentAuth?.session?.id === id) {
      setToken(null);
      currentUser = null;
      currentAuth = null;
      if (els.sessionsDialog.open) els.sessionsDialog.close();
      flash = { kind: 'ok', text: 'Сеанс завершён' };
      location.hash = '#/login';
      return;
    }
    await openSessions();
  } catch (error) {
    if (handleAuthError(error)) return;
    showBanner('error', errorText(error));
  }
}

function renderUsers(users) {
  const options = (meta.roles || []).map((role) => (
    `<option value="${escapeHtml(role.id)}">${escapeHtml(role.label)}</option>`
  )).join('');
  els.userList.innerHTML = users.map((user) => {
    const self = user.id === currentUser?.id;
    return `
      <div class="user-row">
        <div>
          <strong>${escapeHtml(user.name)}</strong>
          ${self ? '<span class="muted"> · это вы</span>' : ''}
        </div>
        <span>${escapeHtml(user.email)}</span>
        <select data-role-for="${user.id}" ${self ? 'disabled' : ''}>${options}</select>
        <button class="button secondary" type="button" data-user-id="${user.id}" ${self ? 'disabled' : ''}>Сохранить</button>
      </div>
    `;
  }).join('');
  for (const user of users) {
    const select = els.userList.querySelector(`[data-role-for="${user.id}"]`);
    if (select) select.value = user.role;
  }
}

async function showUsers(token) {
  show('users');
  els.userList.innerHTML = '<p class="muted">Загрузка…</p>';
  try {
    const data = await api.users();
    if (token !== routeToken) return;
    renderUsers(data.users);
  } catch (error) {
    if (token !== routeToken) return;
    if (handleAuthError(error)) return;
    showMissing(error.status === 403 ? 'Недостаточно прав' : 'Не удалось открыть список', errorText(error));
  }
}

async function saveRole(button) {
  const id = button.dataset.userId;
  const select = els.userList.querySelector(`[data-role-for="${CSS.escape(id)}"]`);
  button.disabled = true;
  try {
    await api.setRole(id, select.value);
    showBanner('ok', 'Роль обновлена. Она применится к уже открытым сеансам со следующего запроса.');
    const data = await api.users();
    renderUsers(data.users);
  } catch (error) {
    button.disabled = false;
    if (handleAuthError(error)) return;
    showBanner('error', errorText(error));
  }
}

function bindClearOnInput(form) {
  const clearTarget = (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    target.removeAttribute('aria-invalid');
    const name = target.getAttribute('name');
    if (!name) return;
    const message = form.querySelector(`[data-error-for="${CSS.escape(name)}"]`);
    if (message) message.textContent = '';
  };
  form.addEventListener('input', clearTarget);
  form.addEventListener('change', clearTarget);
}

function bind() {
  els.addBtn.addEventListener('click', () => {
    if (location.hash === '#/new') void renderRoute();
    else location.hash = '#/new';
  });

  els.brand.addEventListener('click', (event) => {
    if (!currentUser) return;
    if ((location.hash || '#/') === '#/') {
      event.preventDefault();
      els.search.value = '';
      els.genreFilter.value = '';
      clearBanner();
      void fetchList();
    }
  });

  els.filters.addEventListener('submit', (event) => {
    event.preventDefault();
    clearBanner();
    void fetchList();
  });
  els.search.addEventListener('input', () => {
    clearBanner();
    scheduleList();
  });
  els.genreFilter.addEventListener('change', () => {
    clearBanner();
    void fetchList();
  });

  els.form.addEventListener('submit', (event) => { void onSubmit(event); });
  els.cancel.addEventListener('click', () => {
    const id = els.form.dataset.id;
    location.hash = id ? `#/book/${id}` : '#/';
  });
  els.cover.addEventListener('change', () => {
    const file = els.cover.files[0];
    const message = document.querySelector('[data-error-for="cover"]');
    if (message) message.textContent = '';
    els.cover.removeAttribute('aria-invalid');
    if (!file) return;
    const fileError = validateFile(file);
    if (fileError) {
      showFieldErrors([fileError], els.form);
      els.cover.value = '';
      return;
    }
    els.removeCover.checked = false;
    setPreview(URL.createObjectURL(file), true);
  });

  bindClearOnInput(els.form);
  bindClearOnInput(els.loginForm);
  bindClearOnInput(els.registerForm);
  bindClearOnInput(els.forgotForm);
  bindClearOnInput(els.resetForm);

  els.loginForm.addEventListener('submit', (event) => { void onLogin(event, false); });
  els.loginEvict.addEventListener('click', () => { void onLogin(null, true); });
  els.registerForm.addEventListener('submit', (event) => { void onRegister(event); });
  els.forgotForm.addEventListener('submit', (event) => { void onForgot(event); });
  els.resetForm.addEventListener('submit', (event) => { void onReset(event); });
  els.logoutBtn.addEventListener('click', () => { void onLogout(); });
  els.sessionsBtn.addEventListener('click', () => { void openSessions(); });
  els.sessionsClose.addEventListener('click', () => { els.sessionsDialog.close(); });
  els.sessionsList.addEventListener('click', (event) => {
    const button = event.target.closest('[data-session-id]');
    if (!button) return;
    void revokeSession(button.dataset.sessionId);
  });
  els.userList.addEventListener('click', (event) => {
    const button = event.target.closest('[data-user-id]');
    if (!button || button.disabled) return;
    void saveRole(button);
  });

  els.retry.addEventListener('click', () => { void boot(); });
  window.addEventListener('hashchange', () => { void renderRoute(); });
}

async function boot() {
  try {
    meta = await api.meta();
    fillGenres();
    fillPolicy();
    if (!booted) {
      booted = true;
      bind();
    }
    if (!location.hash) location.hash = getToken() ? '#/' : '#/login';
    else await renderRoute();
  } catch (error) {
    showMissing('Сервер недоступен', errorText(error), true);
  }
}

void boot();
