import { getTelegramFileUrl } from '@/helpers/get-telegram-file-url';
import { prisma } from '@/lib/prisma';
import {
  Analysis,
  ErrorResponse,
  FileReport,
  getAnalysisURL,
  getFileReport,
  uploadFile
} from '@/lib/virustotal';
import { logger } from '@/logger';
import type { DbFile, DbScanResult, SafeReturn } from '@/typings';
import { wait } from '@/utils/wait';
import { hash } from '@litehex/node-checksum';
import lodash from 'lodash';

export class Scanner {
  private callbacks: Map<ScannerEvent, Callback<ScannerEvent>[]> = new Map();

  constructor(
    private uniqueId: string,
    private fileId: string,
    private filename: string | undefined
  ) {}

  on<E extends ScannerEvent>(event: E, callback: Callback<E>) {
    const current = this.callbacks.get(event) || [];
    current.push(callback as Callback<ScannerEvent>);
    this.callbacks.set(event, current);
  }

  async scan() {
    logger.debug(`Scanning the file with the unique id: ${this.uniqueId}`);
    this.sendEvent(SCANNER_EVENT.DATABASE, undefined);
    const file = await this.getFile();

    // Get the scan result from the database
    if (file) {
      logger.debug(`The file has a scan result.`);

      const scan = (await prisma.scanResult.findFirst({ where: { file_id: file.id } })) as
        | ScannerResult
        | undefined;

      if (
        scan &&
        scan.result &&
        scan.result.attributes &&
        scan.result.attributes.last_analysis_date
      ) {
        return this.sendEvent(SCANNER_EVENT.COMPLETE, scan as ScannerResult);
      }
    }

    if (file) {
      logger.debug(`Requesting the file report from VirusTotal.`);
      const { data, error } = await getReport(file.id, file.sha256);
      if (data) {
        return this.sendEvent(SCANNER_EVENT.COMPLETE, data);
      }

      if (error.code !== 'NotFoundError') {
        logger.error(error);
        return this.sendEvent(SCANNER_EVENT.error, new Error('Sorry, something went wrong.'));
      }
    }

    // If we have no file, we gonna download it from Telegram
    if (!file) {
      logger.debug(`The file does not exist in the database. Downloading the file from Telegram.`);
      const { data: downloadedFile, error: dlError } = await this.download();
      if (dlError) {
        logger.error(dlError);
        return this.sendEvent(SCANNER_EVENT.error, dlError);
      }

      // Check again with VirusTotal for the file existence
      logger.debug(`Checking if the file exists in VirusTotal.`);
      const { data, error } = await getReport(downloadedFile.id, downloadedFile.sha256);
      if (data) {
        logger.debug(`The file exists in VirusTotal.`);
        return this.sendEvent(SCANNER_EVENT.COMPLETE, data);
      }

      if (error?.code !== 'NotFoundError') {
        logger.error(error);
        return this.sendEvent(SCANNER_EVENT.error, new Error('Sorry, something went wrong.'));
      }
    }

    // At this point VirusTotal does not have the file and we need to upload it
    const { data: downloadedFile, error } = await this.download();
    if (error) {
      logger.error(error);
      return this.sendEvent(SCANNER_EVENT.error, error);
    }

    // Check if the file hash exists VirusTotal
    logger.debug(`Checking if the file exists in VirusTotal.`);
    const report = await getReport(downloadedFile.id, downloadedFile.sha256);
    if (report.data) {
      return this.sendEvent(SCANNER_EVENT.COMPLETE, report.data);
    }

    if (report.error?.code === 'Forbidden') {
      return this.sendEvent(
        SCANNER_EVENT.error,
        new Error('Failed to gain access to VirusTotal API.')
      );
    }

    // If error was NotFoundError, continue to upload the file, otherwise we can proceed
    if (report.error?.code !== 'NotFoundError') {
      return this.sendEvent(SCANNER_EVENT.error, new Error('Sorry, something went wrong.'));
    }

    // Upload the file to VirusTotal
    logger.debug(`Uploading the file to VirusTotal.`);
    this.sendEvent(SCANNER_EVENT.UPLOAD, 'STARTED');
    const analysisId = await this.upload(downloadedFile.buffer);
    if (!analysisId) {
      return;
    }
    this.sendEvent(SCANNER_EVENT.UPLOAD, 'DONE');

    // Update the file in db that it has analysis id
    await prisma.file.update({
      where: {
        id: downloadedFile.id
      },
      data: {
        analysis_id: analysisId
      }
    });

    // Wait for the file to be analyzed
    logger.debug(`Waiting for the file to be analyzed.`);
    const { error: analyzeError } = await this.analyze(
      downloadedFile.id,
      downloadedFile.sha256,
      analysisId
    );
    if (analyzeError) {
      logger.error(error);
      return this.sendEvent(
        SCANNER_EVENT.error,
        new Error('An error occurred while getting the file report.')
      );
    }

    // Wait 2 second as a Cool down
    await wait(2000);

    // Get the file report from the database
    const { data: final, error: finalError } = await getReport(
      downloadedFile.id,
      downloadedFile.sha256
    );
    if (finalError) {
      logger.error(finalError);
      return this.sendEvent(
        SCANNER_EVENT.error,
        new Error('Sorry, something went wrong. Try to resend the file.')
      );
    }

    // Send the final report
    this.sendEvent(SCANNER_EVENT.COMPLETE, final);
  }

  private async getFile(): Promise<DbFile | null> {
    // Search in the database for the file with the telegram file id
    const file = await prisma.file.findFirst({
      where: { telegram_file_id: this.uniqueId }
    });

    return file;
  }

  private async download(): Promise<SafeReturn<DownloadedFile, Error>> {
    this.sendEvent(SCANNER_EVENT.DOWNLOAD, { progress: 0, state: 'STARTED' });

    const url = await getTelegramFileUrl(this.fileId);
    if (!url) {
      return { error: new Error('Could not retrieve the file link from Telegram.') };
    }

    const response = await fetch(url);
    if (!response.ok) {
      return { error: new Error('Could not download the file. status: ' + response.status) };
    }

    const contentLength = response.headers.get('content-length');
    if (!contentLength) {
      return { error: new Error('Could not get the content length of the file.') };
    }

    const buffer = new ArrayBuffer(parseInt(contentLength));
    const view = new Uint8Array(buffer);
    let offset = 0;

    let finished = false;

    const throttled = lodash.throttle((progress: number) => {
      if (!finished) this.sendEvent(SCANNER_EVENT.DOWNLOAD, { progress, state: 'IN_PROGRESS' });
    }, 2000);

    const reader = response.body!.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }

      view.set(value, offset);
      offset += value.length;
      const progress = offset / buffer.byteLength;
      throttled(progress);
    }

    finished = true;

    const sha256 = hash('sha256', buffer);
    const sha1 = hash('sha1', buffer);
    const md5 = hash('md5', buffer);

    this.sendEvent(SCANNER_EVENT.DOWNLOAD, { progress: 100, state: 'DONE' });

    const file = await prisma.file.findFirst({ where: { sha256 } });

    if (file) {
      return {
        data: {
          id: file.id,
          sha256,
          buffer
        }
      };
    }

    const { id } = await prisma.file.create({
      data: {
        sha256,
        sha1,
        md5,
        has_scan_result: false,
        telegram_file_id: this.uniqueId,
        size: buffer.byteLength
      }
    });

    return {
      data: {
        id,
        sha256,
        buffer
      }
    };
  }

  private async upload(buffer: ArrayBuffer): Promise<string | undefined> {
    try {
      const fileReport = await uploadFile(this.filename, buffer);
      if ('error' in fileReport) {
        logger.error(`An error occurred while uploading the file.`);
        logger.error(fileReport);
        this.sendEvent(
          SCANNER_EVENT.error,
          new Error('An error occurred while uploading the file.')
        );
        return;
      }

      return fileReport.data.id;
    } catch (error: any) {
      logger.error(error);
      this.sendEvent(SCANNER_EVENT.error, error);
    }
  }

  private async analyze(
    fileId: string,
    sha256: string,
    analysisId: string
  ): Promise<SafeReturn<Analysis, ErrorResponse>> {
    const startTime = Date.now();
    const timeout = Date.now() + 50 * 1000; // 50 seconds
    while (Date.now() < timeout) {
      const { data, error } = await getAnalysisURL(analysisId);
      if (error) {
        return { error };
      }

      const elapsed = Date.now() - startTime;
      logger.debug(`Analysis status: ${data.attributes.status} (elapsed: ${elapsed}ms)`);

      this.sendEvent(SCANNER_EVENT.ANALYZE, {
        startTime,
        sha256,
        stats: data.attributes.stats,
        status: data.attributes.status
      });

      if (data.attributes.status === 'completed') {
        return { data };
      }

      await wait(15 * 1000); // Wait 15 seconds for next check
    }

    // If the analysis took too long, return a timeout error
    return {
      error: {
        code: 'TimeoutError',
        message: 'The file analysis took too long.'
      }
    };
  }

  private sendEvent<E extends ScannerEvent, D extends CallbackData[E]>(event: E, data: D) {
    const callbacks = this.callbacks.get(event) || [];
    for (const callback of callbacks) {
      callback(data);
    }
  }
}

export async function getReport(
  fileId: string,
  sha256: string
): Promise<SafeReturn<ScannerResult, ErrorResponse>> {
  const { data, error } = await getFileReport(sha256);
  if (error) {
    logger.error(error);

    if (error.code === 'NotFoundError') {
      logger.debug(`The file report was not found in VirusTotal.`);
    }

    if (error.code === 'Forbidden') {
      logger.error(`Access is forbidden to VirusTotal.`);
    }

    logger.error(`An error occurred while getting the file report.`);
    return { error };
  }

  // Insert the file report into the database
  const scanResult = await prisma.scanResult.upsert({
    where: {
      file_id: fileId
    },
    update: {
      result: data
    },
    create: {
      file_id: fileId,
      result: data
    }
  });

  // Update the file to have a scan result
  await prisma.file.update({
    where: {
      id: fileId
    },
    data: {
      has_scan_result: true
    }
  });

  return {
    data: {
      ...scanResult,
      result: data
    }
  };
}

type DownloadedFile = {
  id: string;
  sha256: string;
  buffer: ArrayBuffer;
};

const SCANNER_EVENT = <const>{
  DATABASE: 'database',
  DOWNLOAD: 'download',
  UPLOAD: 'upload',
  ANALYZE: 'analyze',
  COMPLETE: 'complete',
  error: 'error'
};

type CallbackData = {
  [SCANNER_EVENT.DATABASE]: undefined;
  [SCANNER_EVENT.DOWNLOAD]: {
    progress: number;
    state: 'STARTED' | 'IN_PROGRESS' | 'DONE';
  };
  [SCANNER_EVENT.UPLOAD]: 'STARTED' | 'DONE';
  [SCANNER_EVENT.ANALYZE]: {
    startTime: number;
    sha256: string;
    stats: Analysis['attributes']['stats'];
    status: Analysis['attributes']['status'];
  };
  [SCANNER_EVENT.COMPLETE]: ScannerResult;
  error: Error;
};

type Callback<T extends ScannerEvent> = (data: CallbackData[T]) => void;

export type ScannerResult = Omit<DbScanResult, 'result'> & {
  result: FileReport;
};

type ScannerEvent = (typeof SCANNER_EVENT)[keyof typeof SCANNER_EVENT];
