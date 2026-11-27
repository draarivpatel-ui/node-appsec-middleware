import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const skipped = new Set(['.git', 'node_modules']);
const emDash = String.fromCharCode(0x2014);
const enDash = String.fromCharCode(0x2013);
const usersPrefix = '/' + 'Users' + '/';
const firstMailbox = 'someone' + '@' + 'gmail.com';
const secondMailbox = 'handle-redacted286' + '@' + 'gmail.com';
const coAuthored = 'Co-' + 'Authored-' + 'By:';

async function walk(directory) {
  const output = [];
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    if (skipped.has(entry.name)) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(full));
    else if (entry.isFile()) output.push(full);
  }
  return output;
}

test('repo hygiene has no private paths, mailbox fragments, coauthor trailers, or wide dashes', async () => {
  const files = await walk(root);
  assert.ok(files.length > 10);
  for (const file of files) {
    const content = await fs.readFile(file, 'utf8');
    const relative = path.relative(root, file);
    assert.equal(content.includes(emDash), false, `${relative} contains an em dash`);
    assert.equal(content.includes(enDash), false, `${relative} contains an en dash`);
    assert.equal(content.includes(usersPrefix), false, `${relative} contains a local user path`);
    assert.equal(content.includes(firstMailbox), false, `${relative} contains a personal mailbox`);
    assert.equal(content.includes(secondMailbox), false, `${relative} contains a personal mailbox`);
    assert.equal(content.includes(coAuthored), false, `${relative} contains a coauthor trailer`);
  }
});

test('dependency surface is exactly the thirteen live security packages', async () => {
  const packageJson = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
  const dependencies = Object.keys(packageJson.dependencies || {}).sort();
  assert.deepEqual(dependencies, [
    '@aarivbuildz/csrfshield',
    '@aarivbuildz/hookverify',
    '@aarivbuildz/jwtguard',
    '@aarivbuildz/urlguard',
    'cookiecage',
    'corscage',
    'envcage',
    'headersafe',
    'jsoncage',
    'logcage',
    'pathcage',
    'redirectcage',
    'zipcage'
  ]);
  assert.equal(Object.keys(packageJson.devDependencies || {}).length, 0);
  const lock = JSON.parse(await fs.readFile(path.join(root, 'package-lock.json'), 'utf8'));
  const installed = Object.keys(lock.packages).filter((name) => name.startsWith('node_modules/'));
  assert.equal(installed.length, 13);
});
