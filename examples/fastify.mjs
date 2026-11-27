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
