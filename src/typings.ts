import type { PrismaClient, Prisma } from '@prisma/client';

type ModelName = Prisma.ModelName;

export type PrismaModel = {
  [M in ModelName]: Exclude<Awaited<ReturnType<PrismaClient[Uncapitalize<M>]['findUnique']>>, null>;
};

export type DbFile = PrismaModel['File'];
export type DbScanResult = PrismaModel['ScanResult'];
export type DbUser = PrismaModel['User'];
