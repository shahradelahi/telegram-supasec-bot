import { bot } from '@/bot';
import { logger } from '@/logger';
import { sendError } from '@/utils/send-error';

bot.launch().catch((error) => {
  sendError(error);
  process.exit(1);
});

// Enable graceful stop
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));

console.log();
logger.info('Bot is running');
// console.log('Bot is running');
