import { getFileReport } from '@/lib/virustotal';
import { downloadFile } from '@/utils/download-file';
import { parseInline } from '@/utils/markdown';
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
  const fileBuffer = await downloadFile(file.url);
  if (!fileBuffer) {
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      messageID,
      undefined,
      `An error occurred while downloading the file, please try again in 60 seconds.`
    );
    return;
  }

  // update the message to say were processing the file
  await ctx.telegram.editMessageText(ctx.chat.id, messageID, undefined, `Processing the file...`);

  const sha256 = hash('sha256', fileBuffer);

  // update message to say uploading the file to virus total
  await ctx.telegram.editMessageText(
    ctx.chat.id,
    messageID,
    undefined,
    `Uploading the file to VirusTotal...`
  );

  const report = await getFileReport(sha256);

  if ('error' in report) {
    // Update message to say an error occurred
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      messageID,
      undefined,
      `An error occurred while processing the file.`
    );
    return;
  }

  const { data } = report;
  await ctx.telegram.editMessageText(
    ctx.chat.id,
    messageID,
    undefined,
    await parseInline(
      `\
🧬 **Detections**: **${data.attributes.last_analysis_stats.malicious}** / **${data.attributes.last_analysis_stats.malicious + report.data.attributes.last_analysis_stats.undetected}**

🔖 _**File name**_: _${file.filename}_
🔒 _**File type**_: _${data.attributes.type_description}_
📁 _**File size**_: _${prettyBytes(data.attributes.size)}_

🔬 _**First analysis**_
• _${new Date(data.attributes.last_analysis_date * 1000).toLocaleString()}_

🔭 _**Last analysis**_
• _${new Date(data.attributes.last_analysis_date * 1000).toLocaleString()}_

🎉 _**Magic**_
• _${data.attributes.magic}_`
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
              text: `🔗 Open in VirusTotal`,
              url: `https://www.virustotal.com/gui/file/${data.attributes.md5}/detection`
            }
          ]
        ]
      },
      disable_web_page_preview: true
    }
  );
}
