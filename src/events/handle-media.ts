import { bot } from '@/bot';
import { env } from '@/env';
import { scanRemoteFile } from '@/helpers/scan-remote-file';
import { logger } from '@/logger';
import { parseInline } from '@/utils/markdown';
import path from 'node:path';
import type { Context } from 'telegraf';
import type { Message, Update } from 'telegraf/types';

export async function handleDocument(ctx: Context<Update.MessageUpdate<Message.DocumentMessage>>) {
  const { document } = ctx.message;
  if (!document) {
    return;
  }

  const message = await ctx.replyWithHTML(await parseInline(`_Processing the file..._`), {
    disable_web_page_preview: true,
    reply_to_message_id: ctx.message.message_id
  });

  if (document.file_size && document.file_size > 500 * 1024 * 1024) {
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      message.message_id,
      undefined,
      await parseInline(`File is too large. The maximum file size is **500 MB**.`),
      {
        parse_mode: 'HTML'
      }
    );
    return;
  }

  // reply to message and say wait were downloading the file
  await ctx.telegram.editMessageText(
    ctx.chat.id,
    message.message_id,
    undefined,
    await parseInline(`\
🚀 File initialized.

      ⏳ _Downloading the file..._`),
    {
      parse_mode: 'HTML'
    }
  );

  const fileLink = await getFileLink(document.file_id);
  if (!fileLink) {
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      message.message_id,
      undefined,
      `Could not download the file.`
    );
    return;
  }

  await scanRemoteFile(ctx, message.message_id, {
    url: fileLink.toString(),
    filename: document.file_name!,
    mimetype: document.mime_type!
  });
}

async function getFileLink(fileId: string): Promise<URL | undefined> {
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

export async function handleSticker(ctx: Context<Update.MessageUpdate<Message.StickerMessage>>) {
  const { sticker } = ctx.message;

  if (!sticker) {
    return;
  }

  const message = await ctx.replyWithHTML(await parseInline(`_Processing the sticker..._`), {
    disable_web_page_preview: true,
    reply_to_message_id: ctx.message.message_id
  });

  // check if the file size is too large. MAx 500 MB
  if (sticker.file_size && sticker.file_size > 500 * 1024 * 1024) {
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      message.message_id,
      undefined,
      await parseInline(`\
The sticker is too large. The maximum file size is **500 MB**.`),
      {
        parse_mode: 'HTML'
      }
    );
    return;
  }

  await ctx.telegram.editMessageText(
    ctx.chat.id,
    message.message_id,
    undefined,
    `Downloading the sticker...`
  );

  const fileLink = await getFileLink(sticker.file_id);
  if (!fileLink) {
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      message.message_id,
      undefined,
      `Could not download the sticker.`
    );
    return;
  }

  await scanRemoteFile(ctx, message.message_id, {
    url: fileLink.toString(),
    filename: sticker.file_id,
    mimetype: 'image/webp'
  });
}
