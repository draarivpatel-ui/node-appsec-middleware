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

app.listen(3000, () => {
  console.log('secure Express server listening on http://localhost:3000');
});
