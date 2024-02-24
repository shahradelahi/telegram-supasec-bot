import { bot } from '@/bot';
import { env } from '@/env';
import { logger } from '@/logger';
import path from 'node:path';

export async function getTelegramFileUrl(fileId: string): Promise<URL | undefined> {
  const fileLink = await bot.telegram.getFile(fileId);
  if (!fileLink.file_path) {
    logger.debug(`Could not get the file path for the file.`);
    return;
  }

  // If the path was absolute, remove the first 5 segments of the pathname, because of
  // were using the local bot api server, and the file path is relative to the bot api server.
  if (path.isAbsolute(fileLink.file_path)) {
    const segments = fileLink.file_path.split('/');
    segments.splice(0, 5);
    return new URL(segments.join('/'), `${env.TG_API_BASE_URL}/file/bot${env.TG_TOKEN}/`);
  }

  return new URL(fileLink.file_path, `${env.TG_API_BASE_URL}/file/bot${env.TG_TOKEN}/`);
}
