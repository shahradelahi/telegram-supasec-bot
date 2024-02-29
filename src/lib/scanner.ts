import { getTelegramFileUrl } from '@/helpers/get-telegram-file-url';
import { prisma } from '@/lib/prisma';
import {
  Analysis,
  ErrorResponse,
  FileReport,
  getAnalysis,
  getFileReport,
  uploadFile
} from '@/lib/virustotal';
import { logger } from '@/logger';
import type { DbFile, DbScanResult, SafeReturn } from '@/typings';
import { randomInt } from '@/utils/number';
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
      logger.debug(`The file details were found in the database.`);

      const scan = (await prisma.scanResult.findFirst({ where: { file_id: file.id } })) as
        | ScannerResult
        | undefined;

      if (scan && scan.result && scan.result.attributes) {
        if (scan.result.attributes.last_analysis_date) {
          logger.debug(`File already has a scan result. Sending it to the user.`);
          return this.sendEvent(SCANNER_EVENT.COMPLETE, scan as ScannerResult);
        }

        // If there was not a last analysis date, and we had a analysis id, we need to request the analysis
        if (!scan.result.attributes.last_analysis_date && file.analysis_id) {
          // Send it to analysis stage
          logger.debug(`The file has an analysis id. Sending it to the analysis stage.`);
          await this._stageAnalyze(file.id, file.sha256, file.analysis_id);
        }
      }
    }

    if (file) {
      logger.debug(`Requesting the file report from VirusTotal.`);
      const { data, error } = await getReport(file.id, file.sha256);
      if (data) {
        logger.debug(`File report was found in VirusTotal. Sending report to the user.`);
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

    await this._stageAnalyze(downloadedFile.id, downloadedFile.sha256, analysisId);
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

  private async _stageAnalyze(fileId: string, sha256: string, analysisId: string) {
    logger.debug('Analyzing the file. Analysis ID: %s', analysisId);
    const { error: analyzeError } = await this.analyze(sha256, analysisId);
    if (analyzeError) {
      logger.error(analyzeError);
      return this.sendEvent(
        SCANNER_EVENT.error,
        new Error('Sorry, something went wrong while analyzing the file.')
      );
    }

    // Wait 2 second as a Cool down
    await wait(2000);

    // Get the file report from the database
    const { data: final, error: finalError } = await getReport(fileId, sha256);
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

  private async analyze(
    sha256: string,
    analysisId: string
  ): Promise<SafeReturn<Analysis, ErrorResponse>> {
    let facedError = 0;
    const startTime = Date.now();
    const timeout = Date.now() + 120 * 1000; // 120 seconds

    // Test: wait 5-10 seconds before starting the analysis and also send a getReport request because
    // VirusTotal might prioritize process
    await wait(randomInt(5, 10) * 1000);
    getReport(this.fileId, sha256).finally();

    while (Date.now() < timeout) {
      // The analysis usually takes more than 30 seconds, so there is no need to wait for the first check
      // Just send pending event to keep end user updated
      if (Date.now() - startTime < 30 * 1000) {
        logger.debug(`Analysis status: paused (elapsed: ${Date.now() - startTime}ms)`);

        this.sendEvent(SCANNER_EVENT.ANALYZE, {
          startTime,
          sha256,
          stats: {
            malicious: 0,
            suspicious: 0,
            undetected: 0,
            harmless: 0,
            timeout: 0,
            'confirmed-timeout': 0,
            failure: 0,
            'type-unsupported': 0
          },
          status: 'queued'
        });
        await wait(randomInt(8, 12) * 1000);
        continue;
      }

      logger.debug(`Checking the analysis status. (elapsed: ${Date.now() - startTime}ms)`);
      const { data, error } = await getAnalysis(analysisId);
      if (error) {
        if (facedError > 3) {
          logger.error('Analysis encountered an error 3 times. Stopping the analysis.');
          return { error };
        }

        logger.warn('Analysis encountered an error but will retry. Error: %s', error.message);
        facedError++;

        await wait(20 * 1000);
        continue;
      }

      logger.debug(
        `Analysis status: ${data.attributes.status} (elapsed: ${Date.now() - startTime}ms)`
      );

      this.sendEvent(SCANNER_EVENT.ANALYZE, {
        startTime,
        sha256,
        stats: data.attributes.stats,
        status: data.attributes.status
      });

      if (data.attributes.status === 'completed') {
        return { data };
      }

      // Random between 20-25 seconds wait time
      await wait(randomInt(20, 25) * 1000);
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
