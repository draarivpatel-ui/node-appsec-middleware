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
    ctx.body = { body: ctx.state.appsec ? ctx.req.body : undefined };
    return;
  }
  if (ctx.path === '/go') {
    ctx.safeRedirect(ctx.query.to);
    return;
  }
  ctx.body = { ok: true };
});

app.listen(3000, () => {
  console.log('secure Koa server listening on http://localhost:3000');
});
