import { HttpError } from './errors.js';

export const GENRES = [
  'Роман',
  'Фантастика',
  'Детектив',
  'Поэзия',
  'Научная',
  'Учебная',
  'Биография',
  'Другое',
];

export const YEAR_MIN = 1450;

export function yearMax() {
  return new Date().getFullYear() + 1;
}

const BOOK_FIELDS = new Set(['title', 'author', 'year', 'genre', 'description']);

export function validateBook(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new HttpError(400, 'Ожидается объект с полями книги');
  }

  const details = [];

  for (const key of Object.keys(input)) {
    if (!BOOK_FIELDS.has(key)) {
      details.push({ field: key, message: 'Неизвестное поле' });
    }
  }

  const title = readString(input.title, 'title', {
    empty: 'Укажите название',
    type: 'Название должно быть строкой',
    max: 200,
    maxMessage: 'Название не длиннее 200 символов',
    required: true,
  }, details);

  const author = readString(input.author, 'author', {
    empty: 'Укажите автора',
    type: 'Имя автора должно быть строкой',
    max: 200,
    maxMessage: 'Имя автора не длиннее 200 символов',
    required: true,
  }, details);

  let year = null;
  if (typeof input.year === 'number' && Number.isInteger(input.year)) {
    year = input.year;
  } else if (typeof input.year === 'string' && /^-?\d+$/.test(input.year.trim())) {
    year = Number(input.year.trim());
  } else {
    details.push({ field: 'year', message: 'Укажите год издания целым числом' });
  }

  if (year !== null && (year < YEAR_MIN || year > yearMax())) {
    details.push({
      field: 'year',
      message: `Год должен быть от ${YEAR_MIN} до ${yearMax()}`,
    });
  }

  let genre = '';
  if (typeof input.genre !== 'string') {
    details.push({ field: 'genre', message: 'Выберите жанр из списка' });
  } else {
    genre = input.genre.trim();
    if (!GENRES.includes(genre)) {
      details.push({ field: 'genre', message: 'Выберите жанр из списка' });
    }
  }

  const description = readString(input.description, 'description', {
    empty: '',
    type: 'Описание должно быть строкой',
    max: 4000,
    maxMessage: 'Описание не длиннее 4000 символов',
    required: false,
  }, details);

  if (details.length > 0) {
    throw new HttpError(400, 'Проверьте введённые данные', details);
  }

  return { title, author, year, genre, description };
}

export function validateListQuery(query) {
  const details = [];
  let q = '';
  let genre = '';

  if (query.q !== undefined) {
    if (typeof query.q !== 'string') {
      details.push({ field: 'q', message: 'Параметр q должен быть строкой' });
    } else {
      q = query.q.trim();
      if (q.length > 200) {
        details.push({ field: 'q', message: 'Поисковый запрос не длиннее 200 символов' });
      }
    }
  }

  if (query.genre !== undefined && query.genre !== '') {
    if (typeof query.genre !== 'string') {
      details.push({ field: 'genre', message: 'Параметр genre должен быть строкой' });
    } else {
      genre = query.genre.trim();
      if (!GENRES.includes(genre)) {
        details.push({ field: 'genre', message: 'Выберите жанр из списка' });
      }
    }
  }

  if (details.length > 0) {
    throw new HttpError(400, 'Некорректные параметры запроса', details);
  }

  return { q, genre };
}

export function toLikePattern(value) {
  return `%${value.replace(/[\\%_]/g, (char) => `\\${char}`)}%`;
}

export function parseId(value) {
  if (!/^\d+$/.test(String(value))) {
    throw new HttpError(400, 'Некорректный идентификатор');
  }
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id < 1) {
    throw new HttpError(400, 'Некорректный идентификатор');
  }
  return id;
}

function readString(value, field, rules, details) {
  if (value === undefined || value === null) {
    if (rules.required) details.push({ field, message: rules.empty });
    return '';
  }
  if (typeof value !== 'string') {
    details.push({ field, message: rules.type });
    return '';
  }
  const trimmed = value.trim();
  if (rules.required && trimmed.length === 0) {
    details.push({ field, message: rules.empty });
  } else if (trimmed.length > rules.max) {
    details.push({ field, message: rules.maxMessage });
  }
  return trimmed;
}
