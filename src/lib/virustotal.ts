import { env } from '@/env';
import { logger } from '@/logger';
import { z } from 'zod';
import { fetch } from 'zod-request';

const ErrorSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string()
  })
});

const FileReportSchema = z.object({
  data: z.object({
    id: z.string(),
    type: z.string(),
    links: z.object({ self: z.string() }),
    attributes: z.object({
      ssdeep: z.string().optional(),
      tlsh: z.string().optional(),
      sha1: z.string(),
      last_analysis_stats: z.object({
        malicious: z.number(),
        suspicious: z.number(),
        undetected: z.number(),
        harmless: z.number(),
        timeout: z.number(),
        'confirmed-timeout': z.number(),
        failure: z.number(),
        'type-unsupported': z.number()
      }),
      unique_sources: z.number(),
      size: z.number(),
      last_analysis_date: z.number().optional(),
      type_description: z.string(),
      trid: z.array(z.object({ file_type: z.string(), probability: z.number() })).optional(),
      type_tags: z.array(z.string()),
      md5: z.string(),
      last_analysis_results: z.record(
        z.object({
          method: z.string(),
          engine_name: z.string(),
          engine_version: z.string().nullable(),
          engine_update: z.string().nullable(),
          category: z.enum([
            'harmless',
            'malicious',
            'suspicious',
            'undetected',
            'timeout',
            'confirmed-timeout',
            'failure',
            'type-unsupported'
          ]),
          result: z.string().nullable()
        })
      ),
      tags: z.array(z.string()),
      total_votes: z.object({ harmless: z.number(), malicious: z.number() }),
      times_submitted: z.number(),
      meaningful_name: z.string().optional(),
      sha256: z.string(),
      names: z.array(z.string()),
      type_tag: z.string().optional(),
      type_extension: z.string().optional(),
      first_submission_date: z.number(),
      last_modification_date: z.number(),
      last_submission_date: z.number(),
      reputation: z.number(),
      magic: z.string().optional()
    })
  })
});

export type FileReport = z.infer<typeof FileReportSchema>;

export async function getFileReport(hash: string) {
  const url = new URL(`/api/v3/files/${hash}`, env.VT_API_BASE_URL);
  const response = await fetch(url, {
    headers: {
      'X-Apikey': env.VT_API_KEY,
      Accept: 'application/json'
    },
    schema: {
      headers: z.object({
        Accept: z.string(),
        'X-Apikey': z.string()
      }),
      response: z.union([
        // error
        ErrorSchema,
        // success
        FileReportSchema
      ])
    }
  });

  logger.debug('GET %s %s', url, response.status);

  const data = await response.json();
  return data;
}

/**
 * Upload a file to VirusTotal. The file must be less than 32MB
 *
 *  Curl example:
 *
 *  ```sh
 *    curl --request POST \
 *      --url https://www.virustotal.com/api/v3/files \
 *      --header 'accept: application/json' \
 *      --header 'content-type: multipart/form-data'
 *  ```
 *
 * @param filename
 * @param content
 * @param password
 */
export async function uploadFile(
  filename: string,
  content: string | ArrayBuffer,
  password?: string
) {
  const body = new FormData();
  const blob = new Blob([content]);
  body.set('file', blob, filename);
  if (password) body.set('password', password);

  let url = new URL('/api/v3/files', env.VT_API_BASE_URL).toString();

  // if the file is larger than 32MB, get a special URL to upload the file
  if (blob.size > 32 * 1024 * 1024) {
    const res = await getUploadURL();
    if (!('data' in res)) {
      logger.error(res);
      throw new Error('Failed to get the special URL to upload the file');
    }
    url = res.data
      // replace the base URL with the special URL
      .replace('https://www.virustotal.com/api/', env.VT_API_BASE_URL);
  }

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'X-Apikey': env.VT_API_KEY,
      Accept: 'application/json'
    },
    body,
    schema: {
      headers: z.object({
        'X-Apikey': z.string(),
        Accept: z.string()
      }),
      response: z.union([
        // error
        ErrorSchema,
        // success
        z.object({
          data: z.object({
            type: z.string(),
            id: z.string(),
            links: z.object({ self: z.string() })
          })
        })
      ])
    }
  });

  const data = await response.json();
  return data;
}

/**
 * Get a special URL to upload a large file to VirusTotal
 *
 * ```sh
 *    curl --request GET \
 *   --url https://www.virustotal.com/api/v3/files/upload_url \
 *   --header 'x-apikey: <your API key>'
 *  ```
 */
export async function getUploadURL() {
  const response = await fetch(new URL('/api/v3/files/upload_url', env.VT_API_BASE_URL), {
    headers: {
      'X-Apikey': env.VT_API_KEY,
      Accept: 'application/json'
    },
    schema: {
      headers: z.object({
        'X-Apikey': z.string(),
        Accept: z.string()
      }),
      response: z.union([
        // error
        ErrorSchema,
        // success
        z.object({
          data: z.string().url()
        })
      ])
    }
  });

  const data = await response.json();
  return data;
}

const AnalysisSchema = z.object({
  data: z.object({
    id: z.string(),
    type: z.string(),
    links: z.object({ self: z.string(), item: z.string() }),
    attributes: z.object({
      stats: z.object({
        malicious: z.number(),
        suspicious: z.number(),
        undetected: z.number(),
        harmless: z.number(),
        timeout: z.number(),
        'confirmed-timeout': z.number(),
        failure: z.number(),
        'type-unsupported': z.number()
      }),
      results: z.record(
        z.object({
          method: z.string(),
          engine_name: z.string(),
          engine_version: z.string().nullable(),
          engine_update: z.string().nullable(),
          category: z.enum([
            'harmless',
            'malicious',
            'suspicious',
            'undetected',
            'timeout',
            'confirmed-timeout',
            'failure',
            'type-unsupported'
          ]),
          result: z.string().nullable()
        })
      ),
      date: z.number(),
      status: z.enum(['queued', 'completed', 'in-progress', 'failed'])
    })
  })
});

export type Analysis = z.infer<typeof AnalysisSchema>;

/**
 * Get a URL / file analysis
 *
 * ```sh
 *    curl --request GET \
 *   --url https://www.virustotal.com/api/v3/analyses/{id} \
 *   --header 'x-apikey: <your API key>'
 *  ```
 */
export async function getAnalysisURL(id: string) {
  const response = await fetch(new URL(`/api/v3/analyses/${id}`, env.VT_API_BASE_URL), {
    headers: {
      'X-Apikey': env.VT_API_KEY,
      Accept: 'application/json'
    },
    schema: {
      headers: z.object({
        'X-Apikey': z.string(),
        Accept: z.string()
      }),
      response: z.union([
        // error
        ErrorSchema,
        // success
        AnalysisSchema
      ])
    }
  });

  const data = await response.json();
  return data;
}

export async function rescanFile(id: string) {
  const response = await fetch(new URL(`/api/v3/files/${id}/analyse`, env.VT_API_BASE_URL), {
    method: 'POST',
    headers: {
      'X-Apikey': env.VT_API_KEY,
      Accept: 'application/json'
    },
    schema: {
      headers: z.object({
        'X-Apikey': z.string(),
        Accept: z.string()
      }),
      response: z.union([
        // error
        ErrorSchema,
        // success
        z.object({
          data: z.object({
            id: z.string(),
            type: z.string(),
            links: z.object({ self: z.string() })
          })
        })
      ])
    }
  });

  const data = await response.json();
  return data;
}
