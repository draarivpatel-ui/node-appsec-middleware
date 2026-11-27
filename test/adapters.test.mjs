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
  assert.equal(parsers.length, 1);
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
