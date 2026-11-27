import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export function createHttpExample(createSecurityMiddleware) {
  const security = createSecurityMiddleware({
    cors: { allowedOrigins: ['https://app.example.com'] },
    redirect: { allowedOrigins: ['https://app.example.com'], fallback: '/' },
    json: { maxBytes: 64 * 1024 },
    csrf: { secrets: ['replace-this-csrf-secret-with-32-plus-random-bytes'] },
    urlGuard: { allowedSchemes: ['https:'], dns: true }
  });

  return http.createServer((req, res) => {
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
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  const { createSecurityMiddleware } = await import('node-appsec-middleware');
  const server = createHttpExample(createSecurityMiddleware);
  server.listen(3000, '127.0.0.1', () => {
    console.log('secure native http server listening on http://127.0.0.1:3000');
  });
}
