import http from 'node:http';
import { createHmac } from 'node:crypto';

export const CSRF_SECRET = 'test-csrf-secret-with-at-least-32-bytes';
export const JWT_SECRET = 'test-jwt-secret-with-at-least-32-bytes';
export const WEBHOOK_SECRET = 'test-webhook-secret-with-at-least-32-bytes';
export const COOKIE_SECRET = 'test-cookie-secret-with-at-least-32-bytes';

export function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${address.port}` });
    });
  });
}

export function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

export function serverForMiddleware(middleware, route) {
  return http.createServer((request, response) => {
    middleware(request, response, () => route(request, response));
  });
}

export async function startMiddlewareServer(middleware, route) {
  return listen(serverForMiddleware(middleware, route));
}

export async function responseText(response) {
  return { status: response.status, headers: response.headers, text: await response.text() };
}

export async function responseJson(response) {
  const text = await response.text();
  try {
    return { status: response.status, headers: response.headers, json: JSON.parse(text), text };
  } catch (error) {
    throw new Error(`response was not JSON: ${text}`);
  }
}

export function githubSignature(body, secret) {
  return `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
}

export function firstCookie(setCookie) {
  return String(setCookie || '').split(';', 1)[0];
}
