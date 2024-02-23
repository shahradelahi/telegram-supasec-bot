import { configDotenv } from 'dotenv';
import '@/env';

process.env.NODE_ENV = 'test';
configDotenv({ path: '.env.test.local', override: true });
