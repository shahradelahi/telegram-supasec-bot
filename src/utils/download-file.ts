export async function downloadFile(fileLink: string): Promise<ArrayBuffer | null> {
  const response = await fetch(fileLink);
  if (!response.ok) {
    return null;
  }
  const buffer = await response.arrayBuffer();
  return buffer;
}
