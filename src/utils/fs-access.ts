import { promises, accessSync } from 'node:fs';

export async function fsAccess(path: string) {
  try {
    await promises.access(path);
    return true;
  } catch (_) {
    return false;
  }
}

export function fsAccessSync(path: string) {
  try {
    accessSync(path);
    return true;
  } catch (_) {
    return false;
  }
}
