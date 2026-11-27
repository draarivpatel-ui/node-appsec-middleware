import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const examples = ['express.mjs', 'fastify.mjs', 'koa.mjs', 'http.mjs'];
for (const name of examples) {
  const file = path.join(root, 'examples', name);
  assert.ok(fs.existsSync(file), `missing example ${name}`);
  const source = fs.readFileSync(file, 'utf8');
  assert.ok(source.includes('node-appsec-middleware'), `${name} does not import the package`);
  const checked = spawnSync(process.execPath, ['--check', file], {
    cwd: root,
    encoding: 'utf8',
    shell: false
  });
  assert.equal(checked.status, 0, `${name} failed syntax check: ${checked.stderr}`);
}
console.log(`Example syntax check passed for ${examples.length} examples`);
