import { FileReport } from '@/lib/virustotal';
import { parseInline } from '@/utils/markdown';
import { DateTime } from 'luxon';
import prettyBytes from 'pretty-bytes';
import type { Context } from 'telegraf';
import type { Update } from 'telegraf/types';

export async function editResultMessage(
  ctx: Context<Update.MessageUpdate> | Context<Update.CallbackQueryUpdate>,
  messageID: number | undefined,
  filename: string | undefined,
  data: FileReport['data']
) {
  const hasName = filename || data.attributes.meaningful_name || data.attributes.names.length > 0;

  const message = await parseInline(
    `\
🧬 **Detections**: **${data.attributes.last_analysis_stats.malicious}** / **${data.attributes.last_analysis_stats.malicious + data.attributes.last_analysis_stats.undetected}**
${hasName ? `\n📜 _**File name**_: _${filename || data.attributes.meaningful_name || data.attributes.names[0]}_` : ''}
🔒 _**File type**_: _${data.attributes.type_description}_
📁 _**File size**_: _${prettyBytes(data.attributes.size)}_

🔬 _**First analysis**_
• _${DateTime.fromSeconds(data.attributes.first_submission_date).setZone('UTC').toFormat('yyyy-MM-dd HH:mm:ss')}_

🔭 _**Last analysis**_
• _${DateTime.fromSeconds(data.attributes.last_analysis_date).setZone('UTC').toFormat('yyyy-MM-dd HH:mm:ss')}_

🎉 _**Magic**_
• _${data.attributes.magic}_

[⚜️ Link to VirusTotal](https://www.virustotal.com/gui/file/${data.attributes.md5})`
  );

  return ctx.telegram.editMessageText(
    ctx.callbackQuery?.message?.chat.id || ctx.message?.chat.id,
    messageID || ctx.callbackQuery?.message?.message_id || ctx.message?.message_id,
    undefined,
    message,
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
              text: `🦠 Signature`,
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
