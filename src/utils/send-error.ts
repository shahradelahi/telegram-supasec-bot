/* eslint-disable no-console */

import { bot } from '@/bot';
import { env } from '@/env';

export function sendError(error: any) {
  console.log();
  console.log('--------------------ERROR--------------------');
  console.log(error);
  console.log('--------------------ERROR--------------------');
  console.log();

  (async () => {
    if (typeof bot === 'undefined' || typeof env.TG_ADMIN_ID === 'undefined') {
      return;
    }

    const chatId = env.TG_ADMIN_ID;
    const fileName = `error-${Date.now()}.log`;
    await bot.telegram.sendDocument(chatId, {
      source: Buffer.from(error.stack ?? error.message ?? error),
      filename: fileName
    });
  })().catch();
}
