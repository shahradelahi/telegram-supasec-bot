import { wait } from '@/utils/wait';
import { expect } from 'chai';
import { promises } from 'node:fs';
import { fetch } from 'zod-request';
import { resolve } from 'node:path';
import { z } from 'zod';

describe('Upload File with FormData', () => {
  const packageJson = resolve(process.cwd(), 'package.json');

  const schema = {
    response: z.object({
      files: z.record(z.any()),
      form: z.record(z.any()),
      headers: z.record(z.string())
    })
  };

  it('should upload a file to HttpBin', async () => {
    const buffer = await promises.readFile(packageJson);
    const content = new Blob([buffer]);

    const formData = new FormData();
    formData.append('file', content, 'package.json');

    const response = await fetch('https://httpbin.org/post', {
      method: 'POST',
      headers: {
        'Content-Type': 'multipart/form-data'
      },
      body: formData,
      schema: schema
    });
    console.log(await response.json());
  });
});
