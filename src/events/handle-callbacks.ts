import { editResultMessage } from '@/helpers/edit-result-message';
import { CallbackStack } from '@/lib/callback-stack';
import { prisma } from '@/lib/prisma';
import { ScannerResult } from '@/lib/scanner';
import { logger } from '@/logger';
import { parseInline } from '@/utils/markdown';

export const Callbacks = new CallbackStack();

Callbacks.on('delete', async (ctx) => {
  const { message } = ctx.callbackQuery;
  if (message) {
    await ctx.telegram.deleteMessage(message.chat.id, message.message_id);
  }
  await ctx.answerCbQuery();
});

Callbacks.on(['detections', 'signature'], async (ctx, ...args) => {
  const [md5] = args;
  if (!md5) {
    logger.warn(`No md5 provided for detections action.`);
    return;
  }

  // Get file from the database
  const file = await prisma.file.findUnique({ where: { md5 } });
  if (!file) {
    return ctx.editMessageText(await parseInline(`☹️ Could not find the file in the database.`));
  }

  // Get report from the database
  const report = (await prisma.scanResult.findFirst({ where: { file_id: file?.id } })) as
    | ScannerResult
    | undefined;

  if (!report) {
    return ctx.editMessageText(await parseInline(`☹️ Could not find the report in the database.`));
  }

  const { result } = report;

  const { callbackQuery } = ctx;

  if (callbackQuery.data.includes('signature')) {
    const isMalware = report.result.attributes.last_analysis_stats.malicious > 0;

    if (!isMalware) {
      return ctx.answerCbQuery('💚 No threats detected.', { show_alert: true });
    }

    // 🧬 Detections: 1 / 55
    //
    // ⛔️ TrendMicro-HouseCall
    //   ╰ TROJ_GEN.R002V01J323
    //
    // ⚜️ Link to VirusTotal (https://virustotal.com/gui/file/3b37ad1ba8b960e4780d69582cad54af355807f98fc2f5a6a831e096ab0d2185)

    const message = Object.values(report.result.attributes.last_analysis_results)
      .filter(({ result }) => typeof result === 'string' && result !== '')
      .map(({ engine_name, category, result }) => {
        const emoji = category === 'malicious' ? '⛔️' : '⚠️';
        return `${emoji}️ **${engine_name}**
  ╰ \`${result}\``;
      })
      .join('\n\n');

    return ctx.editMessageText(
      await parseInline(`\
🧬 **Detections**: **${report.result.attributes.last_analysis_stats.malicious}** / **${report.result.attributes.last_analysis_stats.malicious + report.result.attributes.last_analysis_stats.undetected}**


${message}


[⚜️ Link to VirusTotal](https://www.virustotal.com/gui/file/${report.result.attributes.md5})`),
      {
        parse_mode: 'HTML',
        reply_markup: {
          inline_keyboard: [
            [
              {
                text: '➥ Back',
                callback_data: `result:${file.md5}`
              }
            ]
          ]
        }
      }
    );
  }

  if (callbackQuery.data.includes('detections')) {
    const detections = result.attributes.last_analysis_results;

    const malicious = Object.values(detections).filter((result) => result.category === 'malicious');

    const detectionsText = Object.values(detections)
      .filter((result) =>
        ['malicious', 'suspicious', 'harmless', 'undetected'].includes(result.category)
      )
      // Sort by alphabetical order
      .sort((a, b) => a.engine_name.localeCompare(b.engine_name))
      .map((result) => {
        const category =
          result.category === 'malicious'
            ? '⛔️'
            : result.category === 'suspicious' || result.category === 'harmless'
              ? '⚠️'
              : '✅';
        return `${category} ${result.engine_name}`;
      })
      .join('\n');

    await ctx.editMessageText(
      await parseInline(`\
🧬 **Detections**: **${malicious.length}** / **${report.result.attributes.last_analysis_stats.malicious + report.result.attributes.last_analysis_stats.undetected}**

${detectionsText}

⚜️ [Link to VirusTotal](https://virustotal.com/gui/file/${file.sha256})`),
      {
        parse_mode: 'HTML',
        reply_markup: {
          inline_keyboard: [
            [
              {
                text: '➥ Back',
                callback_data: `result:${file.md5}`
              }
            ]
          ]
        }
      }
    );
  }
});

Callbacks.on('result', async (ctx, ...args) => {
  const [md5] = args;
  if (!md5) {
    logger.warn(`No md5 provided for result action.`);
    return;
  }

  // Get file from the database
  const file = await prisma.file.findUnique({ where: { md5 } });

  if (!file) {
    return ctx.editMessageText(await parseInline(`☹️ Could not find the file in the database.`));
  }

  // Get report from the database
  const report = (await prisma.scanResult.findFirst({ where: { file_id: file?.id } })) as
    | ScannerResult
    | undefined;

  if (!report) {
    return ctx.editMessageText(await parseInline(`☹️ Could not find the report in the database.`));
  }

  return editResultMessage(ctx, undefined, undefined, report.result);
});
