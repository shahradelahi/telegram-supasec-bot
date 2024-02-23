import { Context } from 'telegraf';
import { Update } from 'telegraf/types';

export async function handleDeleteMessage(ctx: Context<Update.CallbackQueryUpdate>) {
  const { message } = ctx.callbackQuery;
  if (message) {
    await ctx.telegram.deleteMessage(message.chat.id, message.message_id);
  }
  await ctx.answerCbQuery();
}
