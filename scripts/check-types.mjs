import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const types = fs.readFileSync(path.join(root, 'types', 'index.d.ts'), 'utf8');
const required = [
  'createSecurityMiddleware',
  'createPathGuard',
  'createEnvGuard',
  'createZipUploadGuard',
  'createJwtAuthMiddleware',
  'createWebhookMiddleware',
  'fastifyAppsecPlugin',
  'createKoaSecurityMiddleware',
  'SecurityMiddlewareOptions',
  'SecurityContext',
  'NodeRequestLike',
  'NodeResponseLike',
  'MemoryReplayStore'
];
for (const token of required) {
  assert.ok(types.includes(token), `types/index.d.ts does not declare ${token}`);
}
assert.ok(types.includes("from 'headersafe'"), 'headersafe types are not linked');
assert.ok(types.includes("from 'zipcage'"), 'zipcage types are not linked');
assert.ok(!types.includes('any;'), 'types should not expose bare any properties');
console.log(`Type surface check passed for ${required.length} declarations`);
