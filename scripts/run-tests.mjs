import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const testDir = path.join(root, 'test');
const files = fs.readdirSync(testDir)
  .filter((name) => name.endsWith('.test.mjs'))
  .sort()
  .map((name) => path.join(testDir, name));

if (files.length === 0) {
  console.error('no test files found');
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', ...files], {
  cwd: root,
  stdio: 'inherit',
  shell: false
});
if (result.error) throw result.error;
process.exit(result.status === null ? 1 : result.status);
