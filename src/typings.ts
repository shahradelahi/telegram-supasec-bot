import type { PrismaClient, Prisma } from '@prisma/client';

type ModelName = Prisma.ModelName;

export type PrismaModel = {
  [M in ModelName]: Exclude<Awaited<ReturnType<PrismaClient[Uncapitalize<M>]['findUnique']>>, null>;
};

export type DbFile = PrismaModel['File'];
export type DbScanResult = PrismaModel['ScanResult'];
export type DbUser = PrismaModel['User'];

export type LeastOne<T, U = { [K in keyof T]: Pick<T, K> }> = Partial<T> & U[keyof U];

export type SafeReturn<T, K = any> = Partial<{
  data: T;
  error: K;
}> &
  (
    | {
        data: T;
        error?: never;
      }
    | {
        data?: never;
        error: K;
      }
  );
