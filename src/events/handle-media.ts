import { editResultMessage } from '@/helpers/edit-result-message';
import { getTelegramFileUrl } from '@/helpers/get-telegram-file-url';
import { scanRemoteFile } from '@/helpers/scan-remote-file';
import { prisma } from '@/lib/prisma';
import { getReport, Scanner } from '@/lib/scanner';
import { rescanFile } from '@/lib/virustotal';
import { logger } from '@/logger';
import { parseInline } from '@/utils/markdown';
import { sum } from '@/utils/number';
import { sendError } from '@/utils/send-error';
import { DateTime } from 'luxon';
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

  const scanner = new Scanner(document.file_unique_id, document.file_id, document.file_name);

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
    🛡 Uploading a file to VirusTotal...`),
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

  scanner.on('analyze', async ({ startTime, sha256, stats, status }) => {
    if (status === 'in-progress' || status === 'queued') {
      // Count of finished engines
      const results = sum(...Object.values(stats));

      // Calc seconds passed
      const elapsed = DateTime.now().diff(DateTime.fromMillis(startTime), 'seconds').seconds;

      return await ctx.telegram.editMessageText(
        ctx.chat.id,
        messageId,
        undefined,
        await parseInline(`\
🚀 File initialized.

  ✅ _File downloaded._
  ✅ _File uploaded to VirusTotal._
  ${results !== 0 ? `🔮 _File analysing: ${results}..._` : `🔮 _Queued for analysis: ${elapsed}..._`}

[⚜️ Link to VirusTotal](https://www.virustotal.com/gui/file/${sha256})`),
        {
          parse_mode: 'HTML'
        }
      );
    }

    if (status === 'completed') {
      return await ctx.telegram.editMessageText(
        ctx.chat.id,
        messageId,
        undefined,
        await parseInline(`\
🚀 File initialized.

  ✅ _File downloaded._
  ✅ _File uploaded to VirusTotal._
  ✅ _File analysed._

[⚜️ Link to VirusTotal](https://www.virustotal.com/gui/file/${sha256})`),
        {
          parse_mode: 'HTML'
        }
      );
    }
  });

  scanner.on('complete', async ({ result }) => {
    await editResultMessage(ctx, messageId, document.file_name, result);

    const { last_analysis_date, sha256 } = result.attributes;

    await checkLastAnalysisDate(sha256, last_analysis_date);
  });

  scanner.on('error', async (error) => {
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      messageId,
      undefined,
      // a sad face and the error message
      `☹️ ${error.message}`
    );
  });

  await scanner.scan().catch(sendError);
}

async function checkLastAnalysisDate(sha256: string, lastAnalysisDate: number | undefined) {
  // This means, this is the first time the file is being scanned
  if (!lastAnalysisDate) {
    return;
  }

  function pfs(value: number) {
    return Number((value < 0 ? value * -1 : value).toFixed(0));
  }

  // Log the last analysis date
  const d = DateTime.fromSeconds(lastAnalysisDate).diffNow(['days', 'hours', 'minute']).toObject();
  const diffString = `${pfs(d.days || 0)} day, ${pfs(d.hours || 0)} hr, ${pfs(d.minutes || 0)} min`;
  logger.debug(
    `Last analysis date: ${DateTime.fromSeconds(lastAnalysisDate).toISODate()}. It was ${diffString} ago.`
  );

  // If report last analysis was older than 60 days, request a new analysis
  if (DateTime.fromSeconds(lastAnalysisDate).diffNow('days').days < -60) {
    const { data, error } = await rescanFile(sha256);
    if (error) {
      logger.error(error);
      return;
    }

    logger.debug(`file ${sha256} submitted for rescanning.`);

    // Update analysis_id in the database
    await prisma.file.update({
      where: { sha256 },
      data: {
        analysis_id: data.id,
        has_scan_result: false
      }
    });

    // Create a timeout for 1 minute for requesting for new analysis
    setTimeout(async () => {
      const file = await prisma.file.findFirst({
        where: { sha256 }
      });

      if (!file) {
        logger.debug(
          `File not found in the database. Cannot request for new analysis. sha256: ${sha256}`
        );
        return;
      }

      const result = await getReport(file.id, sha256);
      if (!result.data) {
        return;
      }

      logger.debug(`The file has been rescanned.`);
    }, 60 * 1000);
  }
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
