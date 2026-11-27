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
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ ok: true, csrfToken: req.csrfToken }));
  });
});

server.listen(3000, () => {
  console.log('secure native http server listening on http://localhost:3000');
});
