export function getByteSize(data: string | Buffer) {
  if (typeof data === 'string') {
    return Buffer.byteLength(data, 'utf-8');
  }

  return data.byteLength;
}
