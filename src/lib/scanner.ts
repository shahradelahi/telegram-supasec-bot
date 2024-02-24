import { getTelegramFileUrl } from '@/helpers/get-telegram-file-url';
import { DbFile, DbScanResult, prisma } from '@/lib/prisma';
import { Analysis, FileReport, getAnalysisURL, getFileReport, uploadFile } from '@/lib/virustotal';
import { logger } from '@/logger';
import { wait } from '@/utils/wait';
import { hash } from '@litehex/node-checksum';
import lodash from 'lodash';

export class Scanner {
  private callbacks: Map<ScannerEvent, Callback<ScannerEvent>[]> = new Map();

  constructor(
    private uniqueId: string,
    private fileId: string
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
    if (file && file.has_scan_result) {
      logger.debug(`The file has a scan result.`);

      const scanResult = await prisma.scanResult.findFirst({
        where: {
          file_id: file.id
        }
      });

      if (scanResult) {
        this.sendEvent(SCANNER_EVENT.COMPLETE, {
          ...scanResult,
          result: scanResult.result as FileReport['data']
        });
        return;
      }

      logger.debug(`Result not found in the database.`);
    }

    // Download file from telegram
    logger.debug(`Downloading the file.`);
    const downloadedFile = await this.download();
    if (!downloadedFile) {
      return;
    }

    // Check if the file hash exists VirusTotal
    logger.debug(`Checking if the file exists in VirusTotal.`);
    const report = await this.getReport(downloadedFile.id, downloadedFile.sha256);
    if (report) {
      this.sendEvent(SCANNER_EVENT.COMPLETE, report);
      return;
    }

    // Upload the file to VirusTotal
    logger.debug(`Uploading the file to VirusTotal.`);
    const analysisId = await this.upload(downloadedFile.buffer);
    if (!analysisId) {
      return;
    }

    // Wait for the file to be analyzed
    logger.debug(`Waiting for the file to be analyzed.`);
    const result = await this.analyze(downloadedFile.id, downloadedFile.sha256, analysisId);
    if (!result) {
      return;
    }

    logger.debug(`The file has been analyzed.`);
    this.sendEvent(SCANNER_EVENT.COMPLETE, result);
  }

  private async getFile(): Promise<DbFile | null> {
    // Search in the database for the file with the telegram file id
    const file = await prisma.file.findFirst({
      where: {
        telegram_file_id: this.uniqueId
      }
    });

    return file;
  }

  private async download(): Promise<DownloadedFile | undefined> {
    this.sendEvent(SCANNER_EVENT.DOWNLOAD, { progress: 0, state: 'STARTED' });

    const url = await getTelegramFileUrl(this.fileId);
    if (!url) {
      const error = new Error('Could not retrieve the file link from Telegram.');
      logger.debug(error);
      this.sendEvent(SCANNER_EVENT.error, error);
      return;
    }

    const response = await fetch(url);
    if (!response.ok) {
      const error = new Error('Could not download the file. status: ' + response.status);
      logger.debug(error);
      this.sendEvent(SCANNER_EVENT.error, error);
      return;
    }

    const contentLength = response.headers.get('content-length');
    if (!contentLength) {
      const error = new Error('Could not get the content length of the file.');
      logger.debug(error);
      this.sendEvent(SCANNER_EVENT.error, error);
      return;
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

    const file = await prisma.file.findFirst({
      where: {
        sha256
      }
    });

    if (file) {
      return {
        id: file.id,
        sha256,
        buffer
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
      id,
      sha256,
      buffer
    };
  }

  private async getReport(fileId: string, sha256: string): Promise<ScannerResult | undefined> {
    const fileReport = await getFileReport(sha256);
    if ('error' in fileReport) {
      logger.error(`An error occurred while getting the file report.`);
      logger.error(fileReport);
      this.sendEvent(
        SCANNER_EVENT.error,
        new Error('An error occurred while getting the file report.')
      );
      return;
    }

    // Insert the file report into the database
    const scanResult = await prisma.scanResult.upsert({
      where: {
        file_id: fileId
      },
      update: {
        result: fileReport['data']
      },
      create: {
        file_id: fileId,
        result: fileReport['data']
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

    const result: ScannerResult = {
      ...scanResult,
      result: fileReport['data']
    };

    return result;
  }

  private async upload(buffer: ArrayBuffer): Promise<string | undefined> {
    try {
      const fileReport = await uploadFile('file', buffer);
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
  ): Promise<ScannerResult | undefined> {
    const timeout = Date.now() + 60 * 1000; // 1 minute
    while (Date.now() < timeout) {
      const analysis = await getAnalysisURL(analysisId);
      if ('error' in analysis) {
        logger.error(`An error occurred while getting the file report.`);
        logger.error(analysis);
        this.sendEvent(
          SCANNER_EVENT.error,
          new Error('An error occurred while getting the file report.')
        );
        return;
      }

      this.sendEvent(SCANNER_EVENT.ANALYZE, {
        sha256,
        stats: analysis.data.attributes.stats,
        status: analysis.data.attributes.status
      });

      if (analysis.data.attributes.status === 'completed') {
        await wait(2000); // Wait 2 second for cooldown
        return this.getReport(fileId, sha256);
      }

      await wait(15 * 1000); // Wait 15 seconds for next check
    }

    const error = new Error('The file analysis took too long.');
    logger.error(error);
    this.sendEvent(SCANNER_EVENT.error, error);
  }

  private sendEvent<E extends ScannerEvent, D extends CallbackData[E]>(event: E, data: D) {
    const callbacks = this.callbacks.get(event) || [];
    for (const callback of callbacks) {
      callback(data);
    }
  }
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
    sha256: string;
    stats: Analysis['data']['attributes']['stats'];
    status: Analysis['data']['attributes']['status'];
  };
  [SCANNER_EVENT.COMPLETE]: ScannerResult;
  error: Error;
};

type Callback<T extends ScannerEvent> = (data: CallbackData[T]) => void;

export type ScannerResult = Omit<DbScanResult, 'result'> & {
  result: FileReport['data'];
};

type ScannerEvent = (typeof SCANNER_EVENT)[keyof typeof SCANNER_EVENT];
