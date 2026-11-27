import assert from 'node:assert/strict';
import { createSecurityMiddleware } from '../src/index.mjs';
import { createHttpExample } from '../examples/http.mjs';

const server = createHttpExample(createSecurityMiddleware);

async function listenOnEphemeralLoopbackPort() {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === 'object', 'server should have a TCP address');
  return `http://127.0.0.1:${address.port}`;
}

async function closeServer() {
  if (!server.listening) return;
  server.closeAllConnections?.();
  await new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

try {
  const baseUrl = await listenOnEphemeralLoopbackPort();

  const home = await fetch(`${baseUrl}/`);
  assert.equal(home.status, 200, 'home route should respond');
  assert.equal(home.headers.get('x-content-type-options'), 'nosniff');
  const homeBody = await home.json();
  assert.equal(typeof homeBody.csrfToken, 'string');
  const cookie = home.headers.get('set-cookie')?.split(';', 1)[0];
  assert.ok(cookie, 'home route should set the CSRF cookie');

  const accepted = await fetch(`${baseUrl}/api/echo`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      cookie,
      'x-csrf-token': homeBody.csrfToken
    },
    body: JSON.stringify({ message: 'hello' })
  });
  assert.equal(accepted.status, 200, 'small JSON body should be accepted');
  assert.deepEqual(await accepted.json(), { body: { message: 'hello' } });

  const oversized = await fetch(`${baseUrl}/api/echo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ payload: 'x'.repeat(64 * 1024) })
  });
  assert.equal(oversized.status, 413, 'JSON over the configured byte limit should be rejected');
  await oversized.arrayBuffer();

  const redirect = await fetch(
    `${baseUrl}/go?to=${encodeURIComponent('https://evil.example/')}`,
    { redirect: 'manual' }
  );
  assert.equal(redirect.status, 302, 'unsafe redirect should use a redirect response');
  assert.equal(redirect.headers.get('location'), '/', 'unsafe redirect should fall back safely');
  await redirect.arrayBuffer();

  console.log('Native HTTP smoke check passed (headers, bounded JSON, safe redirect)');
} finally {
  await closeServer();
}
