export async function downloadFile(
  fileLink: string,
  onProgress?: (progress: number) => void
): Promise<ArrayBuffer | null> {
  const fileSize = await getFileSize(fileLink);
  if (!fileSize) {
    return null;
  }

  let progress = 0;

  const res = new Response(
    new ReadableStream({
      async start(controller) {
        const response = await fetch(fileLink);
        const reader = response.body!.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) {
            controller.close();
            break;
          }
          if (value) {
            progress += value.byteLength;
            if (onProgress) {
              onProgress((progress / fileSize) * 100);
            }
            controller.enqueue(value);
          }
        }
      }
    })
  );

  return await res.arrayBuffer();
}

export async function getFileSize(fileLink: string): Promise<number | null> {
  const response = await fetch(fileLink, {
    method: 'HEAD'
  });
  if (!response.ok) {
    return null;
  }
  const size = response.headers.get('content-length');
  if (!size) {
    return null;
  }
  return parseInt(size, 10);
}
