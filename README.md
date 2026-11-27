# node-appsec-middleware

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/draarivpatel-ui/node-appsec-middleware/badge)](https://scorecard.dev/viewer/?uri=github.com/draarivpatel-ui/node-appsec-middleware)

Drop-in HTTP security middleware for Node.js, Express, Fastify, and Koa. It composes thirteen focused, zero dependency security packages behind one small API.

The package has no Express, Fastify, or Koa runtime dependency. It works directly with the request and response objects those frameworks already provide.

## Security controls

| Control | Powered by | What it blocks or reduces |
| --- | --- | --- |
| Response headers | `headersafe` | MIME confusion, clickjacking, unsafe referrer leakage, weak CSP defaults |
| CORS | `corscage` | origin reflection, wildcard credential mistakes, unsafe preflights |
| Cookies | `cookiecage` | CRLF injection, cookie tossing duplicates, weak cookie attributes |
| Redirects | `redirectcage` | open redirects, protocol relative redirects, dangerous schemes |
| JSON bodies | `jsoncage` | oversized bodies, duplicate keys, prototype pollution, deep objects |
| CSRF | `@aarivbuildz/csrfshield` | missing or mismatched cross-site request tokens |
| SSRF URL validation | `@aarivbuildz/urlguard` | loopback, private network, metadata IP, and scheme abuse |
| Logging | `logcage` | secret leakage and CRLF log forging |
| Paths | `pathcage` | traversal outside an approved root |
| ZIP uploads | `zipcage` | zip slip, archive bombs, path tricks |
| Environment config | `envcage` | invalid config and accidental secret exposure |
| JWT authentication | `@aarivbuildz/jwtguard` | forged tokens, algorithm confusion, missing claims |
| Webhooks | `@aarivbuildz/hookverify` | forged provider signatures and replayed deliveries |

## Install

```sh
npm install node-appsec-middleware
```

Node.js 18 or newer is required. The package ships ESM, CommonJS, and TypeScript declarations.

## Native Node.js http

```js
import http from 'node:http';
import { createSecurityMiddleware } from 'node-appsec-middleware';

const security = createSecurityMiddleware({
  cors: { allowedOrigins: ['https://app.example.com'] },
  redirect: { allowedOrigins: ['https://app.example.com'] },
  json: { maxBytes: 64 * 1024 },
  csrf: { secrets: ['replace-this-csrf-secret-with-32-plus-random-bytes'] },
  urlGuard: { allowedSchemes: ['https:'], dns: true }
});

const server = http.createServer((req, res) => {
  security(req, res, () => {
    if (req.method === 'POST' && req.url === '/api/echo') {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ body: req.body }));
      return;
    }
    if (req.url?.startsWith('/go?')) {
      const target = new URL(req.url, 'http://localhost').searchParams.get('to');
      res.safeRedirect(target);
      return;
    }
    res.end(JSON.stringify({ ok: true, csrfToken: req.csrfToken }));
  });
});

server.listen(3000);
```

## Express

```js
import express from 'express';
import { createSecurityMiddleware } from 'node-appsec-middleware';

const app = express();

app.use(createSecurityMiddleware({
  cors: {
    allowedOrigins: ['https://app.example.com'],
    credentials: true
  },
  redirect: {
    allowedOrigins: ['https://app.example.com'],
    fallback: '/'
  },
  json: {
    maxBytes: 64 * 1024,
    rejectUnsafeIntegers: true
  },
  csrf: {
    secrets: ['replace-this-csrf-secret-with-32-plus-random-bytes']
  },
  urlGuard: {
    allowedSchemes: ['https:'],
    dns: true
  }
}));

app.post('/api/echo', (req, res) => {
  res.json({ body: req.body });
});

app.get('/go', (req, res) => {
  res.safeRedirect(req.query.to);
});

app.listen(3000);
```

Do not also register `express.json()` for routes this middleware protects. `jsoncage` consumes the request stream once and applies strict limits before parsing.

## Fastify

```js
import Fastify from 'fastify';
import { fastifyAppsecPlugin } from 'node-appsec-middleware';

const fastify = Fastify();

await fastify.register(fastifyAppsecPlugin, {
  cors: {
    allowedOrigins: ['https://app.example.com'],
    credentials: true
  },
  redirect: {
    allowedOrigins: ['https://app.example.com'],
    fallback: '/'
  },
  json: {
    maxBytes: 64 * 1024
  },
  csrf: {
    secrets: ['replace-this-csrf-secret-with-32-plus-random-bytes']
  },
  urlGuard: {
    allowedSchemes: ['https:'],
    dns: true
  }
});

fastify.post('/api/echo', async (request) => ({ body: request.body }));

fastify.get('/go', async (request, reply) => {
  reply.safeRedirect(new URL(request.raw.url, 'http://localhost').searchParams.get('to'));
});

await fastify.listen({ port: 3000 });
```

The plugin installs a strict `application/json` parser. Fastify owns body parsing, while the plugin still applies headers, CORS, cookies, redirects, CSRF, URL validation, and redacted logging through `request.raw` and `reply.raw`.

## Koa

```js
import Koa from 'koa';
import { createKoaSecurityMiddleware } from 'node-appsec-middleware';

const app = new Koa();

app.use(createKoaSecurityMiddleware({
  cors: {
    allowedOrigins: ['https://app.example.com'],
    credentials: true
  },
  redirect: {
    allowedOrigins: ['https://app.example.com'],
    fallback: '/'
  },
  json: {
    maxBytes: 64 * 1024
  },
  csrf: {
    secrets: ['replace-this-csrf-secret-with-32-plus-random-bytes']
  },
  urlGuard: {
    allowedSchemes: ['https:'],
    dns: true
  }
}));

app.use((ctx) => {
  if (ctx.method === 'POST' && ctx.path === '/api/echo') {
    ctx.body = { body: ctx.req.body };
    return;
  }
  if (ctx.path === '/go') {
    ctx.safeRedirect(ctx.query.to);
    return;
  }
  ctx.body = { ok: true };
});

app.listen(3000);
```

Koa response helpers are exposed as `ctx.secureCookie`, `ctx.signSecureCookie`, and `ctx.safeRedirect`. The immutable security context is available at `ctx.state.appsec`.

## Shared middleware behavior

`createSecurityMiddleware(options)` returns an async `(req, res, next)` middleware. In normal mode it sends small JSON error responses. Set `passErrors: true` or provide `onError(error, req, res, next)` to integrate with a framework error pipeline.

Every feature can be disabled with `false` or `{ enabled: false }`. Options not related to one feature are validated by the underlying package, so misspelled security settings do not silently weaken the feature that owns them.

Request additions:

- `req.appsec`: immutable shared security context
- `req.body`: parsed bounded JSON for JSON requests
- `req.secureCookies`: validated inbound cookies when cookie parsing is enabled
- `req.csrfToken`: token issued or validated for cookie based browser flows

Response helpers:

- `res.secureCookie(name, value, options)`
- `res.signSecureCookie(name, value, options)`
- `res.safeRedirect(target, statusCode)`

`req.appsec` exposes immutable references to the underlying guards, including `validateUrl`, `assertSafeUrl`, and `safeFetch` when `urlGuard` is enabled.

## Standalone helpers

### Path guard

```js
import { createPathGuard } from 'node-appsec-middleware';

const paths = createPathGuard('/srv/uploads');
const safePath = paths.resolve(userControlledName);
```

### Environment guard

```js
import { t } from 'envcage';
import { createEnvGuard } from 'node-appsec-middleware';

const env = createEnvGuard({
  PORT: t.port(),
  API_SECRET: t.secret({ minLength: 16 })
});

console.log(env.config.PORT);
console.log(env.snapshot);
```

### ZIP upload guard

```js
import { createZipUploadGuard } from 'node-appsec-middleware';

const zip = createZipUploadGuard({ maxEntries: 100 });
const report = zip.assertSafe(uploadedZipBytes);
const result = await zip.extract(uploadedZipBytes, '/srv/extract-here');
```

### JWT authentication

```js
import { createJwtAuthMiddleware } from 'node-appsec-middleware';

const requireJwt = createJwtAuthMiddleware({
  secret: process.env.JWT_SECRET,
  algorithms: ['HS256'],
  issuer: 'https://issuer.example.com',
  audience: 'api'
});

app.use('/api/private', requireJwt);
```

Verified claims are attached to `req.auth` by default.

### Webhook verification

```js
import { createWebhookMiddleware } from 'node-appsec-middleware';

const githubWebhook = createWebhookMiddleware({
  provider: 'github',
  secret: process.env.GITHUB_WEBHOOK_SECRET
});

app.post('/webhooks/github', githubWebhook, (req, res) => {
  console.log(req.webhook.event, req.webhook.deliveryId);
  res.json({ ok: true });
});
```

The middleware stores the exact signed bytes on `req.rawBody`. Never parse the body before verification.

## Secure defaults are not universal defaults

This package is conservative by design. Before production use, configure your real origins, redirect targets, secret rotation policy, accepted webhook providers, JWT algorithms, issuer, audience, and outbound URL policy. DNS resolution in `urlguard` is explicit and bounded; review its resolver requirements if your threat model includes DNS rebinding.

## Tests and verification

```sh
npm ci
npm run verify
```

The test suite starts real `node:http` servers and exercises attack payloads covering reflected CORS origins, open redirects, CRLF cookie injection, duplicate cookie tossing, prototype pollution, duplicate JSON keys, oversized bodies, forged JWT signatures, forged webhook signatures, CSRF mismatch, SSRF loopback targets, zip slip paths, path traversal, and CRLF log forging.

## License

MIT. See [LICENSE](LICENSE).
