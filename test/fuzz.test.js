import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import fc from 'fast-check';
import { t } from 'envcage';

import { createEnvGuard, createPathGuard } from '../src/index.mjs';

const ALPHA_NUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const SECRET_ALPHABET = ALPHA_NUM + '-_';

function stringFrom(chars, minLength, maxLength) {
  return fc.array(fc.constantFrom(...chars.split('')), { minLength, maxLength }).map((items) => items.join(''));
}

const segment = stringFrom(ALPHA_NUM, 1, 12);
const relativePath = fc.array(segment, { minLength: 1, maxLength: 4 }).map((parts) => parts.join('/'));
const secretText = fc.array(fc.integer({ min: 0, max: SECRET_ALPHABET.length - 1 }), { minLength: 32, maxLength: 32 })
  .map((indexes) => indexes.map((value, index) => SECRET_ALPHABET[(value + index * 13) % SECRET_ALPHABET.length]).join(''));

let root;

before(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), 'appsec-middleware-fuzz-'));
});

after(async () => {
  if (root) await fs.rm(root, { recursive: true, force: true });
});

test('positive: benign relative paths resolve inside the configured root', () => {
  fc.assert(fc.property(relativePath, (input) => {
    const guard = createPathGuard(root, { decodeCheck: true });
    const resolved = guard.resolve(input);
    assert.doesNotThrow(() => guard.assertInside(resolved));
    assert.equal(guard.isInside(resolved), true);
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: parent traversal is rejected even when followed by a benign path', () => {
  fc.assert(fc.property(fc.integer({ min: 1, max: 4 }), relativePath, (depth, tail) => {
    const guard = createPathGuard(root, { decodeCheck: true });
    const input = '../'.repeat(depth) + tail;
    assert.throws(() => guard.resolve(input), /ERR_PATHCAGE_TRAVERSAL/);
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: encoded traversal is rejected at every encoding layer', () => {
  const encodedPrefix = fc.constantFrom('%2e%2e/', '%252e%252e/x/', '..%2f', '%2e%2e%2f');
  fc.assert(fc.property(encodedPrefix, relativePath, (prefix, tail) => {
    const guard = createPathGuard(root, { decodeCheck: true });
    assert.throws(() => guard.resolve(prefix + tail), /ERR_PATHCAGE(?:_ENCODED)?_TRAVERSAL|ERR_PATHCAGE/);
  }), { seed: 20261127, numRuns: 100 });
});

test('positive and negative: environment config accepts strong secrets while public output redacts them', () => {
  fc.assert(fc.property(secretText, (secret) => {
    const guard = createEnvGuard({
      PORT: t.port(),
      API_SECRET: t.secret({ minLength: 24 })
    }, {
      source: { PORT: '8080', API_SECRET: secret }
    });
    assert.equal(guard.config.PORT, 8080);
    assert.equal(guard.snapshot.API_SECRET, '[REDACTED]');
    const output = guard.redactString('prefix ' + secret + ' suffix');
    assert.equal(output.includes(secret), false);
    assert.equal(output, 'prefix [REDACTED] suffix');
  }), { seed: 20261127, numRuns: 100 });
});
