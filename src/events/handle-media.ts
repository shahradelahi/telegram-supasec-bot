import { scanRemoteFile } from '@/helpers/scan-remote-file';
import { parseInline } from '@/utils/markdown';
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

  if (document.file_size && document.file_size > 300 * 1024 * 1024) {
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      message.message_id,
      undefined,
      `The file size is too large. The maximum file size is 300 MB.`
    );
    return;
  }

  // reply to message and say wait were downloading the file
  await ctx.telegram.editMessageText(
    ctx.chat.id,
    message.message_id,
    undefined,
    `Downloading the file...`
  );

  console.log(document.file_id);
  const fileLink = await ctx.telegram.getFileLink(document.file_id);
  console.log(fileLink.toString());

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

export async function handleSticker(ctx: Context<Update.MessageUpdate<Message.StickerMessage>>) {
  const { sticker } = ctx.message;

  if (!sticker) {
    return;
  }

  const message = await ctx.replyWithHTML(await parseInline(`_Processing the sticker..._`), {
    disable_web_page_preview: true,
    reply_to_message_id: ctx.message.message_id
  });

  // check if the file size is too large
  if (sticker.file_size && sticker.file_size > 300 * 1024 * 1024) {
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      message.message_id,
      undefined,
      `The sticker size is too large. The maximum file size is 300 MB.`
    );
    return;
  }

  await ctx.telegram.editMessageText(
    ctx.chat.id,
    message.message_id,
    undefined,
    `Downloading the sticker...`
  );

  const fileLink = await ctx.telegram.getFileLink(sticker.file_id);
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
