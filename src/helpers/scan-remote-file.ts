import { FileReport, getAnalysisURL, getFileReport, uploadFile } from '@/lib/virustotal';
import { logger } from '@/logger';
import { downloadFile } from '@/utils/download-file';
import { parseInline } from '@/utils/markdown';
import { sum } from '@/utils/number';
import { wait } from '@/utils/wait';
import { hash } from '@litehex/node-checksum';
import prettyBytes from 'pretty-bytes';
import type { Context } from 'telegraf';
import type { Update } from 'telegraf/types';

export interface RemoteFile {
  url: string;
  filename: string;
  mimetype: string;
}

export async function scanRemoteFile(
  ctx: Context<Update.MessageUpdate<any>>,
  messageID: number,
  file: RemoteFile
) {
  logger.debug(`Scanning remote file: ${file.url}`);

  // Update the progress every 3 seconds
  let timeSinceLastUpdate = Date.now();
  const fileBuffer = await downloadFile(file.url, async (progress) => {
    if (Date.now() - timeSinceLastUpdate < 3000) {
      return;
    }
    timeSinceLastUpdate = Date.now();
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      messageID,
      undefined,
      await parseInline(`\
🚀 File initialized.

    ⏳ _Downloading the file: ${progress.toFixed(2)}%_`),
      {
        parse_mode: 'HTML'
      }
    );
  });

  if (!fileBuffer) {
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      messageID,
      undefined,
      `An error occurred while downloading the file.`
    );
    return;
  }

  await ctx.telegram.editMessageText(
    ctx.chat.id,
    messageID,
    undefined,
    await parseInline(`\
🚀 File initialized.

    ✅ _File downloaded._`),
    {
      parse_mode: 'HTML'
    }
  );

  // update the message to say were processing the file
  await ctx.telegram.editMessageText(ctx.chat.id, messageID, undefined, `Processing the file...`);

  const sha256 = hash('sha256', fileBuffer);

  logger.debug('Scanning file with sha256: %s', sha256);

  // Update message to say searching in database
  await ctx.telegram.editMessageText(
    ctx.chat.id,
    messageID,
    undefined,
    await parseInline(`\
🚀 File initialized.

    ✅ _File downloaded._
    🔍 _Searching in the database..._`),
    {
      parse_mode: 'HTML'
    }
  );

  const report = await getFileReport(sha256);
  if ('data' in report) {
    await updateMessageWithResult(ctx, messageID, file, report);
    return;
  }

  // At this point we know that the file is not in the database and we need to upload it to VirusTotal
  logger.debug(`File not found in the database, uploading to VirusTotal...`);
  logger.debug(report);

  if (report.error.code === 'NotFoundError') {
    // Update message to say uploading the file to virus total
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      messageID,
      undefined,
      await parseInline(`\
🚀 File initialized.

    ✅ _File downloaded._
    ?? _Uploading a file to VirusTotal..._`),
      {
        parse_mode: 'HTML'
      }
    );

    const uploadRes = await uploadFile(file.filename, fileBuffer);
    if ('error' in uploadRes) {
      logger.error(`An error occurred while uploading the file to VirusTotal.`);
      logger.error(uploadRes);
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        messageID,
        undefined,
        `An error occurred while uploading the file to VirusTotal.`
      );
      return;
    }

    logger.debug(
      `File uploaded to VirusTotal, waiting for %s analysis results...`,
      uploadRes.data.id
    );

    // Create a loop to wait for the analysis to be complete
    let analysisRes = await getAnalysisURL(uploadRes.data.id);
    while (true) {
      if ('error' in analysisRes) {
        logger.error(`An error occurred while waiting for the analysis results.`);
        logger.error(analysisRes);
        await ctx.telegram.editMessageText(
          ctx.chat.id,
          messageID,
          undefined,
          `An error occurred while waiting for the analysis results.`
        );
        return;
      }

      if (analysisRes.data.attributes.status === 'completed') {
        break;
      }

      if (analysisRes.data.attributes.status === 'queued') {
        await ctx.telegram.editMessageText(
          ctx.chat.id,
          messageID,
          undefined,
          await parseInline(`\
🚀 File initialized.

  ✅ _File downloaded._
  ✅ _File uploaded to VirusTotal._
  🔮 _Queued for analysis..._  
  
[⚜️ Link to VirusTotal](https://www.virustotal.com/gui/file/${uploadRes.data.id})`),
          {
            parse_mode: 'HTML',
            disable_web_page_preview: true
          }
        );
      }

      // Update message to say the analysis is in progress
      const totalFinished = sum(...Object.values(analysisRes.data.attributes.stats));
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        messageID,
        undefined,
        await parseInline(`\
🚀 File initialized.

  ✅ _File downloaded._
  ✅ _File uploaded to VirusTotal._
  🔮 _File analysing: ${totalFinished}..._
  
[⚜️ Link to VirusTotal](https://www.virustotal.com/gui/file/${uploadRes.data.id})`),
        {
          parse_mode: 'HTML'
        }
      );

      // Wait 15 seconds before checking again
      logger.debug(`Analysis not completed yet, waiting 15 seconds...`);
      await wait(15 * 1000);
      analysisRes = await getAnalysisURL(uploadRes.data.id);
    }

    await ctx.telegram.editMessageText(
      ctx.chat.id,
      messageID,
      undefined,
      await parseInline(`\
🚀 File initialized.

  ✅ _File downloaded._
  ✅ _File uploaded to VirusTotal._
  ✅ _File analysed._`),
      {
        parse_mode: 'HTML'
      }
    );

    await wait(2 * 1000);

    const fileReport = await getFileReport(sha256);
    if ('error' in fileReport) {
      logger.error(`An error occurred while getting the file report.`);
      logger.error(fileReport);
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        messageID,
        undefined,
        `An error occurred while getting the file report.`
      );
      return;
    }

    await updateMessageWithResult(ctx, messageID, file, fileReport);
  }

  // Update message to say an error occurred
  await ctx.telegram.editMessageText(
    ctx.chat.id,
    messageID,
    undefined,
    `An error occurred while processing the file.`
  );
}

async function updateMessageWithResult(
  ctx: Context<Update.MessageUpdate<any>>,
  messageID: number,
  file: RemoteFile,
  { data }: FileReport
) {
  await ctx.telegram.editMessageText(
    ctx.chat.id,
    messageID,
    undefined,
    await parseInline(
      `\
🧬 **Detections**: **${data.attributes.last_analysis_stats.malicious}** / **${data.attributes.last_analysis_stats.malicious + data.attributes.last_analysis_stats.undetected}**

🔖 _**File name**_: _${file.filename}_
🔒 _**File type**_: _${data.attributes.type_description}_
📁 _**File size**_: _${prettyBytes(data.attributes.size)}_

🔬 _**First analysis**_
• _${new Date(data.attributes.last_analysis_date * 1000).toLocaleString()}_

🔭 _**Last analysis**_
• _${new Date(data.attributes.last_analysis_date * 1000).toLocaleString()}_

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
          // [
          //   {
          //     text: `🔗 Open in VirusTotal`,
          //     url: `https://www.virustotal.com/gui/file/${data.attributes.md5}`
          //   }
          // ],
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
