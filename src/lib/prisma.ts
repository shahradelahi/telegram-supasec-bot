import { PrismaClient, Prisma } from '@prisma/client';

const prisma = new PrismaClient();

export { prisma };

type ModelName = Prisma.ModelName;

export type PrismaModel = {
  [M in ModelName]: Exclude<Awaited<ReturnType<PrismaClient[Uncapitalize<M>]['findUnique']>>, null>;
};

export type DbFile = PrismaModel['File'];
export type DbScanResult = PrismaModel['ScanResult'];
export type DbUser = PrismaModel['User'];
