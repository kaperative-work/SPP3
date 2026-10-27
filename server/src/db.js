import pg from 'pg';
import { logger } from './logger.js';
import { hashPassword } from './passwords.js';
import { GENRES, YEAR_MIN } from './validate.js';

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  logger.error('config_error', { reason: 'Не задана переменная DATABASE_URL' });
  process.exit(1);
}

export const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const SEED_BOOKS = [
  ['Мастер и Маргарита', 'Михаил Булгаков', 1967, 'Роман', 'Роман о визите Воланда в Москву и о судьбе Мастера.'],
  ['Преступление и наказание', 'Фёдор Достоевский', 1866, 'Роман', 'История Родиона Раскольникова и последствий его теории.'],
  ['1984', 'Джордж Оруэлл', 1949, 'Фантастика', 'Антиутопия о тотальном контроле над языком и памятью.'],
  ['Убийство в Восточном экспрессе', 'Агата Кристи', 1934, 'Детектив', 'Расследование Эркюля Пуаро в остановившемся поезде.'],
  ['Краткая история времени', 'Стивен Хокинг', 1988, 'Научная', 'Популярное введение в космологию и природу времени.'],
];

const SEED_USERS = [
  { email: 'admin@library.local', name: 'Администратор', role: 'admin', password: 'Admin123!' },
  { email: 'librarian@library.local', name: 'Библиотекарь', role: 'librarian', password: 'Librarian123!' },
  { email: 'reader@library.local', name: 'Читатель', role: 'reader', password: 'Reader123!' },
];

export async function withTransaction(work) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // транзакция уже завершена
    }
    throw error;
  } finally {
    client.release();
  }
}

export async function waitForDb() {
  for (let attempt = 1; attempt <= 30; attempt += 1) {
    try {
      await pool.query('SELECT 1');
      return;
    } catch (error) {
      logger.info('db_unavailable', { attempt, limit: 30, message: error.message });
      if (attempt === 30) throw error;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
}

export async function initDb() {
  const genreSql = GENRES.map((genre) => `'${genre.replaceAll("'", "''")}'`).join(', ');
  await withTransaction(async (client) => {
    await client.query(`
      CREATE TABLE IF NOT EXISTS books (
        id SERIAL PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        author VARCHAR(200) NOT NULL,
        year INTEGER NOT NULL,
        genre VARCHAR(100) NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        cover_filename VARCHAR(255),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT books_title_len CHECK (char_length(title) BETWEEN 1 AND 200),
        CONSTRAINT books_author_len CHECK (char_length(author) BETWEEN 1 AND 200),
        CONSTRAINT books_year_chk CHECK (year BETWEEN ${YEAR_MIN} AND 2100),
        CONSTRAINT books_genre_chk CHECK (genre IN (${genreSql})),
        CONSTRAINT books_description_len CHECK (char_length(description) <= 4000)
      );

      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(254) NOT NULL UNIQUE,
        name VARCHAR(100) NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(20) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT users_role_chk CHECK (role IN ('reader', 'librarian', 'admin')),
        CONSTRAINT users_name_len CHECK (char_length(name) BETWEEN 1 AND 100),
        CONSTRAINT users_email_len CHECK (char_length(email) BETWEEN 3 AND 254)
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id UUID PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ,
        ip VARCHAR(64) NOT NULL DEFAULT '',
        user_agent VARCHAR(300) NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);

      CREATE TABLE IF NOT EXISTS password_resets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash CHAR(64) NOT NULL UNIQUE,
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS auth_guards (
        guard_key VARCHAR(320) PRIMARY KEY,
        failed_count INTEGER NOT NULL,
        window_started_at TIMESTAMPTZ NOT NULL,
        locked_until TIMESTAMPTZ,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    const { rows } = await client.query('SELECT COUNT(*)::int AS count FROM books');
    if (rows[0].count === 0) {
      for (const row of SEED_BOOKS) {
        await client.query(
          `INSERT INTO books (title, author, year, genre, description)
           VALUES ($1, $2, $3, $4, $5)`,
          row,
        );
      }
    }

    const emails = SEED_USERS.map((user) => user.email);
    const existing = await client.query(
      'SELECT email FROM users WHERE email = ANY($1::text[])',
      [emails],
    );
    const have = new Set(existing.rows.map((row) => row.email));
    for (const user of SEED_USERS) {
      if (have.has(user.email)) continue;
      const passwordHash = await hashPassword(user.password);
      await client.query(
        `INSERT INTO users (email, name, role, password_hash)
         VALUES ($1, $2, $3, $4)`,
        [user.email, user.name, user.role, passwordHash],
      );
    }
  });
  logger.info('db_ready');
}
