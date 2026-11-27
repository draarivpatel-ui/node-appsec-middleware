import cjs from '../cjs/index.cjs';

export const createSecurityMiddleware = cjs.createSecurityMiddleware;
export const createPathGuard = cjs.createPathGuard;
export const createEnvGuard = cjs.createEnvGuard;
export const createZipUploadGuard = cjs.createZipUploadGuard;
export const createJwtAuthMiddleware = cjs.createJwtAuthMiddleware;
export const createWebhookMiddleware = cjs.createWebhookMiddleware;
export const fastifyAppsecPlugin = cjs.fastifyAppsecPlugin;
export const createKoaSecurityMiddleware = cjs.createKoaSecurityMiddleware;
export const MemoryReplayStore = cjs.MemoryReplayStore;

export default cjs;
