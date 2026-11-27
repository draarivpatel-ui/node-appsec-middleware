import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createZipBuffer } from 'zipcage';
import { t } from 'envcage';
import { signJwt } from '@aarivbuildz/jwtguard';
import {
  createEnvGuard,
  createJwtAuthMiddleware,
  createPathGuard,
  createWebhookMiddleware,
  createZipUploadGuard
} from '../src/index.mjs';
import {
  JWT_SECRET,
  WEBHOOK_SECRET,
  close,
  githubSignature,
  responseJson,
  startMiddlewareServer
} from './test-utils.mjs';

test('pathcage helper resolves inside root and blocks traversal', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'appsec-path-'));
  try {
    const guard = createPathGuard(root, { mustExist: true, decodeCheck: true });
    const resolved = guard.resolve('docs/readme.txt');
    assert.equal(guard.isInside(resolved), true);
    assert.equal(resolved.endsWith(path.join('docs', 'readme.txt')), true);
    assert.throws(() => guard.resolve('../outside.txt'), /ERR_PATHCAGE_TRAVERSAL/);
    assert.throws(() => guard.resolve('%2e%2e/outside.txt'), /ERR_PATHCAGE/);
    assert.equal(guard.sanitizeFilename('../bad name.txt'), 'bad name.txt');
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('envcage helper validates config and redacts secrets', () => {
  const guard = createEnvGuard({
    PORT: t.port(),
    API_SECRET: t.secret({ minLength: 16 })
  }, {
    source: { PORT: '8080', API_SECRET: 'a-secret-value-that-is-long-enough' }
  });
  assert.equal(guard.config.PORT, 8080);
  assert.equal(String(guard.config.API_SECRET), '[REDACTED]');
  assert.equal(guard.redactString('token is a-secret-value-that-is-long-enough'), 'token is [REDACTED]');
});

test('zip upload guard blocks zip slip and accepts a benign archive', async () => {
  const guard = createZipUploadGuard({ maxEntries: 10 });
  const benign = createZipBuffer([{ name: 'docs/ok.txt', data: 'safe' }]);
  assert.equal(guard.inspect(benign).safe, true);
  assert.equal(Buffer.from(await guard.readEntry(benign, 'docs/ok.txt')).toString('utf8'), 'safe');
  const target = await fs.mkdtemp(path.join(os.tmpdir(), 'appsec-zip-'));
  try {
    const extracted = await guard.extract(benign, target);
    assert.equal(extracted.entriesWritten, 1);
    assert.equal(await fs.readFile(path.join(target, 'docs', 'ok.txt'), 'utf8'), 'safe');
  } finally {
    await fs.rm(target, { recursive: true, force: true });
  }
  const evil = createZipBuffer([{ name: '../evil.txt', data: 'escape' }], { validate: false });
  const report = guard.inspect(evil);
  assert.equal(report.safe, false);
  assert.ok(report.findings.some((finding) => finding.code === 'ERR_ZIPCAGE_PATH_TRAVERSAL'));
  assert.throws(() => guard.assertSafe(evil), /ERR_ZIPCAGE_PATH_TRAVERSAL/);
});

test('jwt middleware accepts a valid token and rejects a forged signature', async () => {
  const middleware = createJwtAuthMiddleware({
    secret: JWT_SECRET,
    algorithms: ['HS256'],
    issuer: 'middleware-test',
    audience: 'api'
  });
  const { server, baseUrl } = await startMiddlewareServer(middleware, (request, response) => {
    response.end(JSON.stringify({ ok: true, sub: request.auth.sub }));
  });
  try {
    const good = signJwt({ sub: 'user-1', iss: 'middleware-test', aud: 'api' }, JWT_SECRET, {
      algorithm: 'HS256', expiresInSeconds: 300
    });
    const forged = signJwt({ sub: 'user-1', iss: 'middleware-test', aud: 'api' }, 'wrong-jwt-secret-with-at-least-32-bytes', {
      algorithm: 'HS256', expiresInSeconds: 300
    });
    const accepted = await responseJson(await fetch(`${baseUrl}/`, { headers: { authorization: `Bearer ${good}` } }));
    assert.equal(accepted.status, 200);
    assert.equal(accepted.json.sub, 'user-1');
    const rejected = await responseJson(await fetch(`${baseUrl}/`, { headers: { authorization: `Bearer ${forged}` } }));
    assert.equal(rejected.status, 401);
    assert.equal(rejected.json.error.code, 'ERR_JWTGUARD_SIGNATURE_MISMATCH');
  } finally {
    await close(server);
  }
});

test('webhook middleware verifies exact bytes and rejects forged signatures', async () => {
  const middleware = createWebhookMiddleware({ provider: 'github', secret: WEBHOOK_SECRET });
  const { server, baseUrl } = await startMiddlewareServer(middleware, (request, response) => {
    response.end(JSON.stringify({ ok: true, provider: request.webhook.provider, raw: request.rawBody.toString('utf8') }));
  });
  try {
    const payload = '{"zen":"testing"}';
    const accepted = await responseJson(await fetch(`${baseUrl}/`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-hub-signature-256': githubSignature(payload, WEBHOOK_SECRET) },
      body: payload
    }));
    assert.equal(accepted.status, 200);
    assert.equal(accepted.json.provider, 'github');
    assert.equal(accepted.json.raw, payload);

    const forgedBody = '{"zen":"forged"}';
    const rejected = await responseJson(await fetch(`${baseUrl}/`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-hub-signature-256': githubSignature(payload, WEBHOOK_SECRET) },
      body: forgedBody
    }));
    assert.equal(rejected.status, 401);
    assert.equal(rejected.json.error.code, 'SIGNATURE_MISMATCH');
  } finally {
    await close(server);
  }
});
