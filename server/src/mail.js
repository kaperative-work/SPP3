import nodemailer from 'nodemailer';
import { mailMode } from './config.js';
import { HttpError } from './errors.js';
import { logger } from './logger.js';

export async function deliverMail({ to, subject, text, resetUrl }) {
  if (mailMode() === 'smtp') {
    if (!process.env.SMTP_HOST) {
      logger.error('mail_not_configured', { to, subject });
      throw new HttpError(500, 'Почтовый сервер не настроен');
    }
    const port = Number(process.env.SMTP_PORT) || 587;
    const transport = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port,
      secure: process.env.SMTP_SECURE === 'true' || port === 465,
      auth: process.env.SMTP_USER
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD || '' }
        : undefined,
    });
    try {
      await transport.sendMail({
        from: process.env.MAIL_FROM || 'library@localhost',
        to,
        subject,
        text,
      });
    } catch (error) {
      logger.error('mail_failed', { to, subject, message: error.message });
      throw new HttpError(502, 'Не удалось отправить письмо');
    }
    logger.info('mail_sent', { to, subject, transport: 'smtp' });
    return { transport: 'smtp', previewUrl: null };
  }

  logger.info('mail_sent', {
    to,
    subject,
    transport: 'log',
    text,
    resetUrl,
  });
  return { transport: 'log', previewUrl: resetUrl || null };
}
