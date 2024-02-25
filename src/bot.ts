import { env } from '@/env';
import { Callbacks } from '@/events/handle-callbacks';
import {
  getMediaSize,
  handleDocument,
  handleSticker,
  sendNotSupported
} from '@/events/handle-media';
import { prisma } from '@/lib/prisma';
import { logger } from '@/logger';
import { parseInline } from '@/utils/markdown';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { Context, Telegraf } from 'telegraf';
import { anyOf, callbackQuery, message } from 'telegraf/filters';
import validator from 'validator';

const bot: Telegraf<Context> = new Telegraf(env.TG_TOKEN, {
  telegram: {
    apiRoot: env.TG_API_BASE_URL,
    agent: env.TG_PROXY_URL ? new HttpsProxyAgent(env.TG_PROXY_URL) : undefined
  }
});

// Add the user to the database if they are not already there
bot.use(async (ctx, next) => {
  // user must be present in the context and chat must be private
  if (!ctx.from || !ctx.chat || ctx.chat.type !== 'private') {
    logger.debug(`No user found in the context.`);
    return next();
  }

  const { id, first_name, last_name, username } = ctx.from;

  const user = await prisma.user.upsert({
    where: { id },
    update: { first_name, last_name, username, seen_at: new Date(), is_active: true },
    create: { id, first_name, last_name, username }
  });

  ctx.state.user = user;

  return next();
});

// On user left the chat update is_active to false
bot.on('my_chat_member', async (ctx) => {
  const { my_chat_member } = ctx.update;

  if (
    ctx.chat.type === 'private' &&
    my_chat_member.old_chat_member.status === 'member' &&
    my_chat_member.new_chat_member.status === 'kicked'
  ) {
    logger.debug(`User left the chat: ${ctx.from.id}`);
    await prisma.user.update({
      where: { id: ctx.from.id },
      data: { is_active: false }
    });
  }
});

bot.command('start', async (ctx) => {
  const { first_name } = ctx.from;
  await ctx.replyWithHTML(
    await parseInline(
      `\
👋🏻 Hello, [${first_name}](tg://user?id=${ctx.from.id})!

I am a bot based on [VT-API](https://developers.virustotal.com/).

• _You can send a file to the bot or forward it from another channel, and it will check the file on [VirusTotal](https://virustotal.com/) with over **70** different scanners._

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
  async (ctx) => {
    const { message_id } = await ctx.replyWithHTML(await parseInline(`_Processing the file..._`), {
      disable_web_page_preview: true,
      reply_to_message_id: ctx.message.message_id
    });

    const mediaSize = getMediaSize(ctx);

    if (!mediaSize || mediaSize === -1) {
      await sendNotSupported(ctx, message_id);
      return;
    }

    if (mediaSize > 500 * 1024 * 1024) {
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        message_id,
        undefined,
        await parseInline(`😨 File is too large. The maximum file size is **500 MB**.`),
        { parse_mode: 'HTML' }
      );
      return;
    }

    if ('document' in ctx.message) {
      await handleDocument(ctx, message_id);
      return;
    }

    if ('sticker' in ctx.message) {
      await handleSticker(ctx, message_id);
      return;
    }

    // Not supported yet
    await sendNotSupported(ctx, message_id);
  }
);

bot.on(callbackQuery('data'), async (ctx) => {
  const [action, ...args] = ctx.callbackQuery.data.split(':');
  await Callbacks.send(ctx, action, ...args);
});

export { bot };
