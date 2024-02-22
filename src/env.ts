import { createEnv } from '@t3-oss/env-core';
import { z } from 'zod';

import 'dotenv/config';

export const env = createEnv({
  server: {
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    PROXY_URL: z.string().optional(),
    LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('trace'),
    LOG_COLORS: z.string().default('true'),
    // Telegram
    TG_API_BASE_URL: z.string().default('https://api.telegram.org'),
    TG_TOKEN: z.string(),
    TG_PROXY_URL: z.string().optional(),
    // VirusTotal
    VT_API_BASE_URL: z.string().default('https://www.virustotal.com/api/'),
    VT_API_KEY: z.string()
  },

  /**
   * What object holds the environment variables at runtime. This is usually
   * `process.env` or `import.meta.env`.
   */
  runtimeEnv: process.env,

  /**
   * By default, this library will feed the environment variables directly to
   * the Zod validator.
   *
   * This means that if you have an empty string for a value that is supposed
   * to be a number (e.g. `PORT=` in a ".env" file), Zod will incorrectly flag
   * it as a type mismatch violation. Additionally, if you have an empty string
   * for a value that is supposed to be a string with a default value (e.g.
   * `DOMAIN=` in an ".env" file), the default value will never be applied.
   *
   * In order to solve these issues, we recommend that all new projects
   * explicitly specify this option as true.
   */
  emptyStringAsUndefined: true
});
