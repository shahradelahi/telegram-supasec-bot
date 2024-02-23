import { getFileReport, getUploadURL, uploadFile } from '@/lib/virustotal';
import { fsAccess } from '@/utils/fs-access';
import { expect } from 'chai';
import { promises } from 'node:fs';
import { resolve } from 'node:path';

describe('VirusTotal - Reports', () => {
  const SCANNED_SHA256 = '12b59dbcbb4ae93ec1f08b0ffa5904c14bb4ab5e2d58c36befe6fa6906114f92';

  it('should for an already scanned file, return the report from the database', async () => {
    const report = await getFileReport(SCANNED_SHA256);
    expect(report).to.be.an('object');
    expect(report).to.have.property('data');
    if ('data' in report) {
      expect(report.data).to.have.property('id');
      expect(report.data).to.have.property('type');
      expect(report.data).to.have.property('links');
      expect(report.data).to.have.property('attributes');
      expect(report.data.attributes).to.have.property('last_analysis_stats');
      expect(report.data.attributes).to.have.property('last_analysis_results');
    }
  });

  it('should return an error with code of "NotFoundError" if the file is not found in the database', async () => {
    const report = await getFileReport('this-is-a-fake-hash');
    expect(report).to.be.an('object');
    expect(report).to.have.property('error');
    if ('error' in report) {
      expect(report.error).to.have.property('code');
      expect(report.error).to.have.property('message');
      expect(report.error.code).to.equal('NotFoundError');
    }
  });
});

describe('VirusTotal - Upload', () => {
  const PACKAGE_JSON = resolve(process.cwd(), 'package.json');

  it('should upload a file current package.json to VirusTotal', async () => {
    const data = await readFile(PACKAGE_JSON);
    expect(data).to.be.a('string');
    expect(data).to.not.equal('');

    const res = await uploadFile('package.json', data);

    expect(res).to.have.property('data');
    if ('data' in res) {
      expect(res.data).to.have.property('type');
      expect(res.data).to.have.property('id');
    }
  });

  it('should get the special URL for uploading', async () => {
    const res = await getUploadURL();
    expect(res).to.be.a('object');
    expect(res).to.have.property('data');
    if ('data' in res) {
      expect(res.data).to.be.a('string');
    }
  });
});

async function readFile(filePath: string) {
  if (!filePath) throw new Error('File path is required');

  if (!(await fsAccess(filePath))) throw new Error('File does not exist');

  return await promises.readFile(filePath, { encoding: 'utf-8' });
}
