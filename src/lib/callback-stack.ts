import { logger } from '@/logger';
import { Context } from 'telegraf';
import { Update } from 'telegraf/types';

export type CallbackStackFn = (
  ctx: Context<Update.CallbackQueryUpdate>,
  ...args: string[]
) => Promise<any>;

export class CallbackStack {
  private _actions: Map<string, CallbackStackFn>;

  constructor() {
    this._actions = new Map();
  }

  on(action: string, callback: CallbackStackFn) {
    this._actions.set(action, callback);
  }

  async send(ctx: Context<Update.CallbackQueryUpdate>, action: string, ...args: string[]) {
    const callback = this._actions.get(action);
    if (!callback) {
      logger.debug(`Unknown action: ${action}`);
      return ctx.answerCbQuery();
    }

    await callback(ctx, ...args);
  }
}
