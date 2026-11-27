import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createSecurityMiddleware } from '../src/index.mjs';
import { CSRF_SECRET, close, firstCookie, responseJson, startMiddlewareServer } from './test-utils.mjs';

const logs = [];
const manualLogs = [];
let server;
let baseUrl;

function route(request, response) {
  const url = new URL(request.url, 'http://middleware.test');
  if (url.pathname === '/json') {
    response.end(JSON.stringify({ ok: true, body: request.body }));
    return;
  }
  if (url.pathname === '/redirect') {
    response.safeRedirect(url.searchParams.get('to'));
    return;
  }
  if (url.pathname === '/cookie-inject') {
    try {
      response.secureCookie('session', 'x\r\ninjected');
      response.end('not-blocked');
    } catch (error) {
      response.end(String(error.code));
    }
    return;
  }
  if (url.pathname === '/cookie-ok') {
    response.secureCookie('session', 'ok', { path: '/' });
    response.end('cookie');
    return;
  }
  if (url.pathname === '/ssrf') {
    const result = request.appsec.url.validate(url.searchParams.get('target'));
    response.statusCode = result.ok ? 200 : 403;
    response.end(result.ok ? 'public' : result.code);
    return;
  }
  if (url.pathname === '/log') {
    const line = request.appsec.log.json('info', url.searchParams.get('msg'), { route: 'log' });
    manualLogs.push(line);
    response.end('logged');
    return;
  }
  if (url.pathname === '/csrf-protected') {
    response.end('csrf-ok');
    return;
  }
  response.end('ok');
}

before(async () => {
  const middleware = createSecurityMiddleware({
    cors: {
      allowedOrigins: ['https://app.example'],
      credentials: true,
      methods: ['GET', 'POST', 'OPTIONS'],
      allowedHeaders: ['content-type', 'x-csrf-token'],
      rejectDisallowedPreflight: true
    },
    redirect: { fallback: '/', allowedOrigins: ['https://app.example'] },
    json: { maxBytes: 160, maxDepth: 8, rejectUnsafeIntegers: true },
    csrf: { secrets: [CSRF_SECRET] },
    urlGuard: { allowedSchemes: ['http:', 'https:'], dns: false },
    logger: { writer: (line) => logs.push(line), includeHeaders: true }
  });
  ({ server, baseUrl } = await startMiddlewareServer(middleware, route));
});

after(async () => close(server));

test('strict response headers defend XSS and content confusion', async () => {
  const response = await fetch(`${baseUrl}/`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.match(response.headers.get('content-security-policy'), /default-src 'none'/);
  assert.match(response.headers.get('permissions-policy'), /camera=\(\)/);
});

test('cors reflects only the configured origin', async () => {
  const good = await fetch(`${baseUrl}/`, { headers: { origin: 'https://app.example' } });
  assert.equal(good.headers.get('access-control-allow-origin'), 'https://app.example');
  const evil = await fetch(`${baseUrl}/`, { headers: { origin: 'https://evil.example' } });
  assert.equal(evil.headers.get('access-control-allow-origin'), null);
});

test('cors allows a hardened preflight and rejects reflected evil preflight', async () => {
  const good = await fetch(`${baseUrl}/json`, {
    method: 'OPTIONS',
    headers: {
      origin: 'https://app.example',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'content-type'
    }
  });
  await good.arrayBuffer();
  assert.equal(good.status, 204);
  assert.equal(good.headers.get('access-control-allow-origin'), 'https://app.example');

  const evil = await fetch(`${baseUrl}/json`, {
    method: 'OPTIONS',
    headers: {
      origin: 'https://evil.example',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'content-type'
    }
  });
  await evil.arrayBuffer();
  assert.equal(evil.status, 403);
  assert.equal(evil.headers.get('access-control-allow-origin'), null);
});

test('open redirect targets fall back to the safe root', async () => {
  for (const target of ['https://evil.example/', '//evil.example/path', 'javascript:alert(1)']) {
    const response = await fetch(`${baseUrl}/redirect?to=${encodeURIComponent(target)}`, { redirect: 'manual' });
    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), '/');
  }
  const safe = await fetch(`${baseUrl}/redirect?to=${encodeURIComponent('/inside')}`, { redirect: 'manual' });
  assert.equal(safe.headers.get('location'), '/inside');
});

test('cookie helper blocks CRLF injection and emits hardened cookies', async () => {
  const attack = await fetch(`${baseUrl}/cookie-inject`);
  assert.equal(await attack.text(), 'ERR_COOKIECAGE_CRLF');
  const good = await fetch(`${baseUrl}/cookie-ok`);
  const cookie = good.headers.get('set-cookie');
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /SameSite=Lax/);
});

test('cookie tossing duplicates are rejected before the route', async () => {
  const { status, json } = await responseJson(await fetch(`${baseUrl}/`, {
    headers: { cookie: 'a=1; a=2' }
  }));
  assert.equal(status, 400);
  assert.equal(json.error.code, 'ERR_COOKIECAGE_DUPLICATE_COOKIE');
});

test('jsoncage accepts a bounded benign JSON body', async () => {
  const first = await fetch(`${baseUrl}/`);
  const cookie = firstCookie(first.headers.get('set-cookie'));
  const token = cookie.slice(cookie.indexOf('=') + 1);
  const { status, json } = await responseJson(await fetch(`${baseUrl}/json`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie, 'x-csrf-token': token },
    body: '{"user":{"name":"Ada"},"ok":true}'
  }));
  assert.equal(status, 200);
  assert.equal(json.body.user.name, 'Ada');
});

test('jsoncage blocks prototype pollution and duplicate keys', async () => {
  for (const [body, code] of [
    ['{"__proto__":{"isAdmin":true}}', 'JSONCAGE_PROTOTYPE_KEY'],
    ['{"role":"user","role":"admin"}', 'JSONCAGE_DUPLICATE_KEY']
  ]) {
    const { status, json } = await responseJson(await fetch(`${baseUrl}/json`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body
    }));
    assert.equal(status, 400);
    assert.equal(json.error.code, code);
  }
});

test('json body byte cap returns 413 for oversized input', async () => {
  const body = `{"pad":"${'x'.repeat(220)}"}`;
  const { status, json } = await responseJson(await fetch(`${baseUrl}/json`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body
  }));
  assert.equal(status, 413);
  assert.equal(json.error.code, 'ERR_APPSEC_BODY_TOO_LARGE');
});

test('urlguard blocks SSRF loopback and allows a public hostname form', async () => {
  const loopback = await fetch(`${baseUrl}/ssrf?target=${encodeURIComponent('http://127.0.0.1/')}`);
  assert.equal(loopback.status, 403);
  assert.equal(await loopback.text(), 'PRIVATE_IP');
  const publicUrl = await fetch(`${baseUrl}/ssrf?target=${encodeURIComponent('https://example.com/')}`);
  assert.equal(publicUrl.status, 200);
});

test('csrf mismatch is forbidden and a matching token passes', async () => {
  const first = await fetch(`${baseUrl}/`);
  const cookie = firstCookie(first.headers.get('set-cookie'));
  assert.match(cookie, /^__Host-csrf=/);
  const token = cookie.slice(cookie.indexOf('=') + 1);

  const missing = await fetch(`${baseUrl}/csrf-protected`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json' },
    body: '{}'
  });
  assert.equal(missing.status, 403);

  const good = await fetch(`${baseUrl}/csrf-protected`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json', 'x-csrf-token': token },
    body: '{}'
  });
  assert.equal(good.status, 200);
  assert.equal(await good.text(), 'csrf-ok');
});

test('logcage neutralizes CRLF log forging in a real request parameter', async () => {
  const before = manualLogs.length;
  const response = await fetch(`${baseUrl}/log?msg=${encodeURIComponent('first\nsecond\rthird')}`);
  assert.equal(response.status, 200);
  assert.equal(manualLogs.length, before + 1);
  const line = manualLogs.at(-1);
  assert.equal(line.includes('\n'), false);
  assert.equal(line.includes('\r'), false);
  const parsed = JSON.parse(line);
  assert.equal(parsed.msg, 'first\\nsecond\\rthird');
});

test('request logging emits redacted single line NDJSON', async () => {
  const marker = 'header-token-that-must-not-appear';
  const before = logs.length;
  const response = await fetch(`${baseUrl}/?access_token=${marker}`, { headers: { authorization: `Bearer ${marker}` } });
  assert.equal(response.status, 200);
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(logs.length > before);
  const parsed = JSON.parse(logs.at(-1));
  assert.equal(parsed.msg, 'http request');
  assert.equal(parsed.meta.headers.authorization, '[REDACTED]');
  assert.equal(logs.at(-1).includes(marker), false);
});
