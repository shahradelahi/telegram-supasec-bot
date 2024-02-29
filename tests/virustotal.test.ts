import { getFileReport, getSpecialUploadURL, uploadFile } from '@/lib/virustotal';
import { fsAccess } from '@/utils/fs-access';
import { wait } from '@/utils/wait';
import { expect } from 'chai';
import { promises } from 'node:fs';
import { resolve } from 'node:path';

describe('VirusTotal - Reports', () => {
  const SHA256_LIST = [
    '12b59dbcbb4ae93ec1f08b0ffa5904c14bb4ab5e2d58c36befe6fa6906114f92',
    '292d637e8b52d1695cb9366698ed16080b42de8f5aae2fe053fbeb24dd9a0604'
  ];

  it('should for an already scanned file, return the report from the database', async () => {
    for (const hash of SHA256_LIST) {
      const { data, error } = await getFileReport(hash);

      expect(error, JSON.stringify(error)).to.be.undefined;
      expect(data).to.be.an('object');

      if (data) {
        expect(data).to.have.property('id');
        expect(data).to.have.property('type');
        expect(data).to.have.property('links');
        expect(data).to.have.property('attributes');

        expect(data.attributes).to.have.property('last_analysis_stats');
        expect(data.attributes).to.have.property('last_analysis_results');
      }

      await wait(1000);
    }
  });

  it('should return an error with code of "NotFoundError" if the file is not found in the database', async () => {
    const report = await getFileReport('this-is-a-fake-hash');
    expect(report).to.be.an('object');
    expect(report).to.have.property('error');
    if (report.error) {
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

    expect(res, JSON.stringify(res)).to.have.property('data');
    if (res.data) {
      expect(res.data).to.have.property('type');
      expect(res.data).to.have.property('id');
    }
  });

  it('should get the special URL for uploading', async () => {
    const res = await getSpecialUploadURL();
    expect(res).to.be.a('object');
    expect(res).to.have.property('data');
    if (res.data) {
      expect(res.data).to.be.a('string');
    }
  });
});

async function readFile(filePath: string) {
  if (!filePath) throw new Error('File path is required');

  if (!(await fsAccess(filePath))) throw new Error('File does not exist');

  return await promises.readFile(filePath, { encoding: 'utf-8' });
}
