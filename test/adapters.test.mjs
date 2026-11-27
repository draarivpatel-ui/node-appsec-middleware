import test from 'node:test';
import assert from 'node:assert/strict';
import { createKoaSecurityMiddleware, fastifyAppsecPlugin } from '../src/index.mjs';

function responseMock() {
  return {
    statusCode: 200,
    headers: {},
    locals: {},
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    getHeader(name) { return this.headers[name.toLowerCase()]; },
    removeHeader(name) { delete this.headers[name.toLowerCase()]; },
    once() {},
    end(chunk) { this.writableEnded = true; this.body = chunk === undefined ? '' : String(chunk); }
  };
}

test('fastify plugin registers a strict parser and bridges helpers', async () => {
  const hooks = [];
  const parsers = [];
  const fastify = {
    addHook(name, hook) {
      assert.equal(name, 'onRequest');
      hooks.push(hook);
    },
    addContentTypeParser(type, options, parser) {
      parsers.push({ type, options, parser });
    },
    removeContentTypeParser() {}
  };
  await new Promise((resolve, reject) => {
    fastifyAppsecPlugin(fastify, { logger: false }, (error) => error ? reject(error) : resolve());
  });
  assert.equal(hooks.length, 1);
  assert.equal(parsers.length, 2);
  assert.equal(parsers[0].type, 'application/json');
  assert.throws(() => {
    parsers[0].parser({}, Buffer.from('{"__proto__":{"x":1}}'), (error) => {
      if (error) throw error;
    });
  }, /JSONCAGE_PROTOTYPE_KEY/);

  const rawRequest = { method: 'GET', url: '/', headers: {} };
  const rawResponse = responseMock();
  const request = { raw: rawRequest };
  const reply = { raw: rawResponse };
  await new Promise((resolve, reject) => {
    hooks[0](request, reply, (error) => error ? reject(error) : resolve());
  });
  assert.equal(typeof reply.secureCookie, 'function');
  assert.equal(typeof reply.safeRedirect, 'function');
  assert.equal(request.appsec, reply.appsec);

  const rejectedRawRequest = { method: 'GET', url: '/', headers: { cookie: 'a=1; a=2' } };
  const rejectedRawResponse = responseMock();
  await new Promise((resolve, reject) => {
    hooks[0]({ raw: rejectedRawRequest }, { raw: rejectedRawResponse }, (error) => error ? reject(error) : resolve());
  });
  assert.equal(rejectedRawResponse.statusCode, 400);
  assert.match(rejectedRawResponse.body, /ERR_COOKIECAGE_DUPLICATE_COOKIE/);
});

function fastifyParserMock() {
  const parsers = [];
  const fastify = {
    addHook() {},
    addContentTypeParser(type, options, parser) {
      parsers.push({ type, options, parser });
    },
    removeContentTypeParser() {}
  };
  return { fastify, parsers };
}

function registerFastifyPlugin(fastify, options) {
  return new Promise((resolve, reject) => {
    fastifyAppsecPlugin(fastify, options, (error) => error ? reject(error) : resolve());
  });
}

function runFastifyParser(entry, text) {
  let result;
  entry.parser({}, Buffer.from(text), (error, value) => {
    if (error) throw error;
    result = value;
  });
  return result;
}

test('fastify plugin applies the strict parser to application/*+json media types', async () => {
  const { fastify, parsers } = fastifyParserMock();
  await registerFastifyPlugin(fastify, { logger: false, json: { maxBytes: 1024 } });
  assert.equal(parsers.length, 2);
  assert.equal(parsers[0].type, 'application/json');
  const suffix = parsers[1];
  assert.ok(suffix.type instanceof RegExp);
  assert.deepEqual(suffix.options, { parseAs: 'buffer', bodyLimit: 1024 });

  for (const mediaType of ['application/problem+json', 'application/vnd.api+json', 'application/merge-patch+json', 'Application/LD+JSON', 'application/problem+json; charset=utf-8', 'application/problem+json;charset=utf-8']) {
    assert.equal(suffix.type.test(mediaType), true, mediaType);
  }
  for (const mediaType of ['application/json', 'application/jsonx', 'application/problem+jsonx', 'text/problem+json', 'application/problem+xml', 'xapplication/problem+json', 'application/json; profile=x+json', 'application/a/b+json']) {
    assert.equal(suffix.type.test(mediaType), false, mediaType);
  }

  assert.equal(runFastifyParser(suffix, '{"title":"ok"}').title, 'ok');
  assert.throws(() => runFastifyParser(suffix, '{"__proto__":{"x":1}}'), /JSONCAGE_PROTOTYPE_KEY/);
});

test('fastify plugin keeps exact application/json parsing when allowJsonSuffix is false', async () => {
  const { fastify, parsers } = fastifyParserMock();
  await registerFastifyPlugin(fastify, { logger: false, json: { allowJsonSuffix: false } });
  assert.deepEqual(parsers.map((entry) => entry.type), ['application/json']);
});

test('koa adapter bridges context helpers without a koa dependency', async () => {
  const middleware = createKoaSecurityMiddleware({ logger: false });
  const req = { method: 'GET', url: '/', headers: {} };
  const res = responseMock();
  const ctx = { req, res, request: {}, state: {} };
  let called = false;
  await middleware(ctx, () => {
    called = true;
  });
  assert.equal(called, true);
  assert.equal(ctx.state.appsec, req.appsec);
  assert.equal(typeof ctx.secureCookie, 'function');
  assert.equal(typeof ctx.safeRedirect, 'function');
});
