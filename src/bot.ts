import { env } from '@/env';
import { handleDeleteMessage } from '@/events/handle-callbacks';
import { handleDocument, handleSticker } from '@/events/handle-media';
import { logger } from '@/logger';
import { parseInline } from '@/utils/markdown';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { Context, Telegraf } from 'telegraf';
import { anyOf, callbackQuery, message } from 'telegraf/filters';
import { Update } from 'telegraf/types';
import validator from 'validator';

const bot: Telegraf<Context> = new Telegraf(env.TG_TOKEN, {
  telegram: {
    apiRoot: env.TG_API_BASE_URL,
    agent: env.TG_PROXY_URL ? new HttpsProxyAgent(env.TG_PROXY_URL) : undefined
  }
});

bot.command('start', async (ctx) => {
  const { first_name } = ctx.from;
  await ctx.replyWithHTML(
    await parseInline(
      `\
👋🏻 Hello, [${first_name}](tg://user?id=${ctx.from.id})!

I am a bot based on [VT-API](https://developers.virustotal.com/).

• _You can send a file to the bot or forward it from another channel, and it will check the file on [VirusTotal](https://virustotal.com/) with over **70** different antiviruses._

• _To receive scan results, send me any file up to **500 MB** in size, and you will get a detailed analysis of it._

• _With the help of this bot, you can analyze suspicious files to identify viruses and other malicious programs._

• _You can also add me to your chats, and I will be able to analyze the files sent by participants._`
    ),
    {
      disable_web_page_preview: true
    }
  );
});

bot.on(message('text'), async (ctx) => {
  if (validator.isURL(ctx.message.text)) {
    await ctx.reply(`Not supported yet.`);
  }

  await ctx.reply(`\
I don't understand you. Please send me a file or forward it from another channel, or use the /help command.`);
});

bot.on(
  anyOf(
    message('document'),
    message('sticker'),
    message('photo'),
    message('video'),
    message('voice'),
    message('audio'),
    message('animation'),
    message('video_note')
  ),
  async (ctx: Context<Update>) => {
    if (ctx.has(message('document'))) {
      await handleDocument(ctx);
      return;
    }

    if (ctx.has(message('sticker'))) {
      await handleSticker(ctx);
      return;
    }

    // Not supported yet
    await ctx.reply(`🙅‍♂ This bot does not support this file type.`, {
      reply_to_message_id: ctx.message?.message_id
    });
  }
);

bot.on(callbackQuery('data'), async (ctx) => {
  const [action, ...args] = ctx.callbackQuery.data.split(':');
  if (action === 'delete') {
    await handleDeleteMessage(ctx);
    return;
  }

  logger.debug(`Unhandled callback query: ${ctx.callbackQuery.data}`);
  await ctx.answerCbQuery();
});

bot.use(async (ctx, next) => {
  if (env.NODE_ENV === 'development') console.log(ctx.update);
  next();
});

export { bot };
