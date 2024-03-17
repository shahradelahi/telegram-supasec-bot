import { logger } from '@/logger';
import { Context } from 'telegraf';
import { CallbackQuery, Update } from 'telegraf/types';

export type CallbackStackFn = (
  ctx: Context<Update.CallbackQueryUpdate<CallbackQuery.DataQuery>>,
  ...args: string[]
) => Promise<any>;

export class CallbackStack {
  private _actions: Map<string, CallbackStackFn>;

  constructor() {
    this._actions = new Map();
  }

  on(action: string | string[], callback: CallbackStackFn) {
    action = Array.isArray(action) ? action : [action];
    for (const a of action) {
      this._actions.set(a, callback);
    }
  }

  async send(
    ctx: Context<Update.CallbackQueryUpdate<CallbackQuery.DataQuery>>,
    action: string,
    ...args: string[]
  ) {
    const callback = this._actions.get(action);
    if (!callback) {
      logger.debug(`Unknown action: ${action}`);
      return ctx.answerCbQuery();
    }

    await callback(ctx, ...args);
  }
}
