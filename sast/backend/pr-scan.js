// SecureShip: PR scan endpoint
// Scans the changed files of a pull request, saves a summary to DynamoDB
// and the full report to S3, and returns pass/fail for the GitHub check.
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { randomUUID } from 'crypto';
import { scanCode } from './scanner.js';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const s3 = new S3Client({});
const TABLE = process.env.TABLE_NAME;
const BUCKET = process.env.BUCKET_NAME;

export const registerPrScan = (app) => {
  app.post('/scan/pr', async (req, res) => {
    try {
      const { projectId = 'demo', repo = '', pr = '', commit = '', files = [] } = req.body || {};
      if (!Array.isArray(files) || files.length === 0) {
        return res.status(400).json({ error: 'No files provided' });
      }

      // 1. Scan every changed file
      const findings = files.flatMap(f => scanCode(String(f.code || ''), String(f.filename || 'untitled.js')));
      const count = (sev) => findings.filter(v => v.severity === sev).length;
      const summary = { files: files.length, total: findings.length, high: count('HIGH'), medium: count('MEDIUM'), low: count('LOW') };
      const passed = summary.high === 0;               // the gate: any HIGH finding fails the PR

      // 2. Redact evidence so leaked secrets are never stored
      const redacted = findings.map(({ evidence, ...rest }) => rest);

      const now = new Date().toISOString();
      const scanId = randomUUID();
      const reportKey = `reports/${projectId}/${now}-${scanId}.json`;

      // 3. Full report to S3
      await s3.send(new PutObjectCommand({
        Bucket: BUCKET,
        Key: reportKey,
        ContentType: 'application/json',
        Body: JSON.stringify({ scanId, projectId, repo, pr, commit, scannedAt: now, summary, findings: redacted }, null, 2)
      }));

      // 4. Summary to DynamoDB: PK = project, SK starts with the timestamp
      await ddb.send(new PutCommand({
        TableName: TABLE,
        Item: {
          PK: `PROJECT#${projectId}`,
          SK: `SCAN#${now}#${scanId}`,
          type: 'SAST', status: 'COMPLETED', passed,
          repo, pr: String(pr), commit,
          ...summary,
          s3ReportKey: reportKey
        }
      }));

      res.json({ passed, scanId, summary, reportKey, findings: redacted.slice(0, 20) });
    } catch (error) {
      console.error('PR scan failed:', error.message);
      res.status(500).json({ error: 'Scan failed', message: error.message });
    }
  });
};