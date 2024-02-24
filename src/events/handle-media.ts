import { getTelegramFileUrl } from '@/helpers/get-telegram-file-url';
import { scanRemoteFile } from '@/helpers/scan-remote-file';
import { Scanner } from '@/lib/scanner';
import { FileReport } from '@/lib/virustotal';
import { parseInline } from '@/utils/markdown';
import { sum } from '@/utils/number';
import { DateTime } from 'luxon';
import prettyBytes from 'pretty-bytes';
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

  const scanner = new Scanner(document.file_unique_id, document.file_id);

  scanner.on('database', async () => {
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      message.message_id,
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
        message.message_id,
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
        message.message_id,
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
        message.message_id,
        undefined,
        await parseInline(`\
🚀 File initialized.

    ⏳ _Downloading the file: ${progress.toFixed(2)}%_`),
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
        message.message_id,
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
        message.message_id,
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
        message.message_id,
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
        message.message_id,
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
    await updateMessageWithResult(
      ctx,
      message.message_id,
      {
        filename: document.file_name,
        mimetype: document.mime_type
      },
      result
    );
  });

  await scanner.scan();
}

async function updateMessageWithResult(
  ctx: Context<Update.MessageUpdate<any>>,
  messageID: number,
  file: {
    filename: string | undefined;
    mimetype: string | undefined;
  },
  data: FileReport['data']
) {
  await ctx.telegram.editMessageText(
    ctx.chat.id,
    messageID,
    undefined,
    await parseInline(
      `\
🧬 **Detections**: **${data.attributes.last_analysis_stats.malicious}** / **${data.attributes.last_analysis_stats.malicious + data.attributes.last_analysis_stats.undetected}**
${file.filename ? `\n📜 _**File name**_: _${file.filename}_` : ''}
🔒 _**File type**_: _${data.attributes.type_description}_
📁 _**File size**_: _${prettyBytes(data.attributes.size)}_

🔬 _**First analysis**_
• _${DateTime.fromSeconds(data.attributes.first_submission_date).setZone('UTC').toFormat('yyyy-MM-dd HH:mm:ss ZZZ')}_

🔭 _**Last analysis**_
• _${DateTime.fromSeconds(data.attributes.last_analysis_date).setZone('UTC').toFormat('yyyy-MM-dd HH:mm:ss ZZZ')}_

🎉 _**Magic**_
• _${data.attributes.magic}_

[⚜️ Link to VirusTotal](https://www.virustotal.com/gui/file/${data.attributes.md5})`
    ),
    {
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [
          [
            {
              text: `🧪 Detections`,
              callback_data: `detections:${data.attributes.md5}`
            },
            {
              text: `🔐 Signature`,
              callback_data: `signature:${data.attributes.md5}`
            }
          ],
          [
            {
              text: `❌ Close`,
              callback_data: `delete:${messageID}`
            }
          ]
        ]
      },
      disable_web_page_preview: true
    }
  );
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

  const fileLink = await getTelegramFileUrl(sticker.file_id);
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
