'use strict';

const assert = require('node:assert/strict');

async function main() {
  const cjs = require('../cjs/index.cjs');
  const esm = await import('../src/index.mjs');
  const names = [
    'createSecurityMiddleware',
    'createPathGuard',
    'createEnvGuard',
    'createZipUploadGuard',
    'createJwtAuthMiddleware',
    'createWebhookMiddleware',
    'fastifyAppsecPlugin',
    'createKoaSecurityMiddleware',
    'MemoryReplayStore'
  ];
  for (const name of names) {
    assert.equal(typeof cjs[name], 'function', `CJS export ${name} is missing`);
    assert.equal(typeof esm[name], 'function', `ESM export ${name} is missing`);
  }
  assert.equal(typeof cjs.default.createSecurityMiddleware, 'function');
  console.log(`CJS and ESM export check passed for ${names.length} entry points`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
