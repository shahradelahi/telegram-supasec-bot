import { env } from '@/env';
import { z } from 'zod';
import { fetch } from 'zod-request';

export async function getFileReport(hash: string) {
  const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
    headers: {
      'X-Apikey': env.VT_API_KEY,
      'Content-Type': 'application/json'
    },
    schema: {
      headers: z.object({
        'Content-Type': z.string(),
        'X-Apikey': z.string()
      }),
      response: z.union([
        // error
        z.object({
          error: z.object({
            code: z.string(),
            message: z.string()
          })
        }),
        // success
        z.object({
          data: z.object({
            id: z.string(),
            type: z.string(),
            links: z.object({ self: z.string() }),
            attributes: z.object({
              ssdeep: z.string(),
              tlsh: z.string(),
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
              last_analysis_date: z.number(),
              type_description: z.string(),
              trid: z
                .array(z.object({ file_type: z.string(), probability: z.number() }))
                .optional(),
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
                  result: z.null()
                })
              ),
              tags: z.array(z.string()),
              total_votes: z.object({ harmless: z.number(), malicious: z.number() }),
              times_submitted: z.number(),
              meaningful_name: z.string(),
              sha256: z.string(),
              names: z.array(z.string()),
              type_tag: z.string(),
              type_extension: z.string(),
              first_submission_date: z.number(),
              last_modification_date: z.number(),
              last_submission_date: z.number(),
              reputation: z.number(),
              magic: z.string()
            })
          })
        })
      ])
    }
  });

  const data = await response.json();
  return data;
}
