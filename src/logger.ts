import { env } from '@/env';
import pino, { type LoggerOptions } from 'pino';
import pretty from 'pino-pretty';

const options: LoggerOptions = {
  level: env.LOG_LEVEL,
  customLevels: {
    trace: 10,
    debug: 20,
    info: 30,
    warn: 40,
    error: 50,
    fatal: 60
  },
  useOnlyCustomLevels: true
};

const jsonLevels = JSON.stringify(options.customLevels);
const levelsInString = jsonLevels.replace(/"/g, '').slice(0, -1).slice(1);

const prettyStream = pretty({
  colorize: env.LOG_COLORS === 'true',
  customLevels: levelsInString
});

const logger = pino(options, pino.multistream([prettyStream]));

export { logger };
