import { randomUUID } from 'node:crypto';
import { mkdir, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { HttpError } from './errors.js';
import { logger } from './logger.js';

export const uploadDir = path.resolve(process.env.UPLOAD_DIR || path.join(process.cwd(), 'uploads'));

export async function ensureUploadDir() {
  await mkdir(uploadDir, { recursive: true });
}

export function sniffImage(buffer) {
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return '.jpg';
  }
  if (
    buffer.length >= 8
    && buffer[0] === 0x89
    && buffer[1] === 0x50
    && buffer[2] === 0x4e
    && buffer[3] === 0x47
    && buffer[4] === 0x0d
    && buffer[5] === 0x0a
    && buffer[6] === 0x1a
    && buffer[7] === 0x0a
  ) {
    return '.png';
  }
  if (
    buffer.length >= 12
    && buffer.toString('ascii', 0, 4) === 'RIFF'
    && buffer.toString('ascii', 8, 12) === 'WEBP'
  ) {
    return '.webp';
  }
  if (buffer.length >= 6) {
    const sign = buffer.toString('ascii', 0, 6);
    if (sign === 'GIF87a' || sign === 'GIF89a') return '.gif';
  }
  return null;
}

export async function saveImage(buffer) {
  const extension = sniffImage(buffer);
  if (!extension) {
    throw new HttpError(400, 'Недопустимый файл обложки', [
      { field: 'cover', message: 'Допустимы только изображения JPEG, PNG, WEBP и GIF' },
    ]);
  }

  const filename = `${randomUUID()}${extension}`;
  await ensureUploadDir();
  await writeFile(path.join(uploadDir, filename), buffer);
  return filename;
}

export async function removeImage(filename) {
  if (!filename || !/^[\w.-]+$/.test(filename)) return;
  const root = path.resolve(uploadDir);
  const full = path.resolve(root, filename);
  if (full !== path.join(root, filename)) return;
  try {
    await unlink(full);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      logger.error('file_delete_failed', { filename, message: error.message });
    }
  }
}
