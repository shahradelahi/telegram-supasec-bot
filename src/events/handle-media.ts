import { editResultMessage } from '@/helpers/edit-result-message';
import { getTelegramFileUrl } from '@/helpers/get-telegram-file-url';
import { scanRemoteFile } from '@/helpers/scan-remote-file';
import { Scanner } from '@/lib/scanner';
import { logger } from '@/logger';
import { parseInline } from '@/utils/markdown';
import { sum } from '@/utils/number';
import { sendError } from '@/utils/send-error';
import type { Context } from 'telegraf';
import type { Message, Update } from 'telegraf/types';

export async function sendNotSupported(ctx: Context<Update.MessageUpdate>, messageId: number) {
  await ctx.telegram.editMessageText(
    ctx.chat.id,
    messageId,
    undefined,
    `🙅‍♂ This bot does not support this file type.`
  );
}

export function getMediaSize(ctx: Context<Update.MessageUpdate>) {
  if ('document' in ctx.message) {
    return ctx.message.document.file_size;
  }

  if ('sticker' in ctx.message) {
    return ctx.message.sticker.file_size;
  }

  if ('photo' in ctx.message) {
    return ctx.message.photo[0].file_size;
  }

  if ('video' in ctx.message) {
    return ctx.message.video.file_size;
  }

  if ('voice' in ctx.message) {
    return ctx.message.voice.file_size;
  }

  if ('audio' in ctx.message) {
    return ctx.message.audio.file_size;
  }

  if ('animation' in ctx.message) {
    return (ctx as Context<Update.MessageUpdate<Message.AnimationMessage>>).message.animation
      .file_size;
  }

  if ('video_note' in ctx.message) {
    return ctx.message.video_note.file_size;
  }
}

export async function handleDocument(ctx: Context<Update.MessageUpdate>, messageId: number) {
  if (!('document' in ctx.message)) {
    return;
  }

  const { document } = ctx.message;

  const scanner = new Scanner(document.file_unique_id, document.file_id);

  scanner.on('database', async () => {
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      messageId,
      undefined,
      await parseInline(`\
🚀 File initialized.

    🔍 _Searching in the database..._`),
      {
        parse_mode: 'HTML'
      }
    );
  });

  scanner.on('download', async ({ state, progress }) => {
    if (state === 'STARTED') {
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        messageId,
        undefined,
        await parseInline(`\
🚀 File initialized.

      ⏳ _Downloading the file..._`),
        {
          parse_mode: 'HTML'
        }
      );
    }

    if (state === 'DONE') {
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        messageId,
        undefined,
        await parseInline(`\
🚀 File initialized.

    ✅ _File downloaded._
    🔍 _Searching in the database..._`),
        {
          parse_mode: 'HTML'
        }
      );
    }

    if (state === 'IN_PROGRESS') {
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        messageId,
        undefined,
        await parseInline(`\
🚀 File initialized.

    ⏳ _Downloading the file: ${(progress * 100).toFixed(2)}%_`),
        {
          parse_mode: 'HTML'
        }
      );
    }
  });

  scanner.on('upload', async (status) => {
    if (status === 'STARTED') {
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        messageId,
        undefined,
        await parseInline(`\
🚀 File initialized.

    ✅ _File downloaded._
    ?? _Uploading a file to VirusTotal..._`),
        {
          parse_mode: 'HTML'
        }
      );
    }

    if (status === 'DONE') {
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        messageId,
        undefined,
        await parseInline(`\
🚀 File initialized.

  ✅ _File downloaded._
  ✅ _File uploaded to VirusTotal._`),
        {
          parse_mode: 'HTML'
        }
      );
    }
  });

  scanner.on('analyze', async ({ sha256, stats, status }) => {
    if (status === 'queued') {
      return await ctx.telegram.editMessageText(
        ctx.chat.id,
        messageId,
        undefined,
        await parseInline(`\
🚀 File initialized.

  ✅ _File downloaded._
  ✅ _File uploaded to VirusTotal._
  🔮 _Queued for analysis..._

[⚜️ Link to VirusTotal](https://www.virustotal.com/gui/file/${sha256})`),
        {
          parse_mode: 'HTML',
          disable_web_page_preview: true
        }
      );
    }

    if (status === 'in-progress') {
      const totalFinished = sum(...Object.values(stats));
      return await ctx.telegram.editMessageText(
        ctx.chat.id,
        messageId,
        undefined,
        await parseInline(`\
🚀 File initialized.

  ✅ _File downloaded._
  ✅ _File uploaded to VirusTotal._
  🔮 _File analysing: ${totalFinished}..._

[⚜️ Link to VirusTotal](https://www.virustotal.com/gui/file/${sha256})`),
        {
          parse_mode: 'HTML'
        }
      );
    }
  });

  scanner.on('complete', async ({ result }) => {
    await editResultMessage(ctx, messageId, document.file_name, result);
  });

  await scanner.scan().catch(sendError);
}

export async function handleSticker(ctx: Context<Update.MessageUpdate>, messageId: number) {
  if (!('sticker' in ctx.message)) {
    return;
  }

  const { sticker } = ctx.message;

  await ctx.telegram.editMessageText(
    ctx.chat.id,
    messageId,
    undefined,
    `Downloading the sticker...`
  );

  const fileLink = await getTelegramFileUrl(sticker.file_id);
  if (!fileLink) {
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      messageId,
      undefined,
      `Could not download the sticker.`
    );
    return;
  }

  await scanRemoteFile(ctx, messageId, {
    url: fileLink.toString(),
    filename: sticker.file_id,
    mimetype: 'image/webp'
  });
}
