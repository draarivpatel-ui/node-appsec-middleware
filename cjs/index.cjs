'use strict';

const {
  createCage,
  sanitizeFilename,
  isInside
} = require('pathcage');
const {
  applyHeaderRecord,
  buildSecurityHeaders
} = require('headersafe');
const { createRedirectGuard } = require('redirectcage');
const {
  defineEnv,
  safeSnapshot,
  redact,
  redactString,
  redactObject,
  parseDotEnv,
  loadEnvFile
} = require('envcage');
const { createCookieJarGuard } = require('cookiecage');
const { createZipGuard } = require('zipcage');
const { createLogCage } = require('logcage');
const { createNodeCorsMiddleware } = require('corscage');
const { createJsonCage } = require('jsoncage');
const { createShield, nodeCrypto } = require('@aarivbuildz/csrfshield/node');
const { verifyJwt } = require('@aarivbuildz/jwtguard');
const {
  createVerifier,
  MemoryReplayStore,
  getProvider
} = require('@aarivbuildz/hookverify');
const {
  createGuard,
  createSafeFetch
} = require('@aarivbuildz/urlguard');
const { nodeResolve } = require('@aarivbuildz/urlguard/runtime/node');

const DEFAULT_CONTEXT_KEY = 'appsec';
const DEFAULT_JSON_METHODS = Object.freeze(['POST', 'PUT', 'PATCH', 'DELETE']);
const DEFAULT_JSON_CONTENT_TYPES = Object.freeze(['application/json']);
// Fastify tests RegExp parsers against the content type including parameters, so allow an
// optional parameter list after the media type while keeping both ends anchored.
const FASTIFY_JSON_SUFFIX_TYPE = /^application\/[^\s/;]+\+json\s*(?:;|$)/i;
const DEFAULT_WEBHOOK_MAX_BODY_BYTES = 262144;

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function isObject(value) {
  return value !== null && typeof value === 'object';
}

function requireOptionsObject(value, label) {
  if (value === undefined || value === true) return {};
  if (!isObject(value) || Array.isArray(value)) {
    throw appsecError('ERR_APPSEC_INVALID_OPTIONS', `${label} must be an object`, 500);
  }
  return value;
}

function appsecError(code, message, status) {
  const error = new Error(message);
  error.name = 'AppSecMiddlewareError';
  error.code = code;
  if (Number.isInteger(status)) error.status = status;
  return error;
}

function assertOnlyKeys(source, allowed, label) {
  if (!isObject(source)) return;
  for (const key of Object.keys(source)) {
    if (!allowed.has(key)) {
      throw appsecError('ERR_APPSEC_UNKNOWN_OPTION', `${label} does not support the unknown option ${key}`, 500);
    }
  }
}

function copyDefined(source, keys) {
  const output = {};
  if (!isObject(source)) return output;
  for (const key of keys) {
    if (hasOwn(source, key) && source[key] !== undefined) output[key] = source[key];
  }
  return output;
}

function copyExcept(source, excluded) {
  const output = {};
  if (!isObject(source)) return output;
  for (const key of Object.keys(source)) {
    if (!excluded.has(key) && source[key] !== undefined) output[key] = source[key];
  }
  return output;
}

function asArray(value, label) {
  if (value === undefined) return [];
  const list = Array.isArray(value) ? value : [value];
  for (const entry of list) {
    if (typeof entry !== 'string' || entry.length === 0) {
      throw appsecError('ERR_APPSEC_INVALID_OPTIONS', `${label} entries must be non-empty strings`, 500);
    }
  }
  return list;
}

function normalizeFeatureInput(value, label) {
  if (value === false) return null;
  return requireOptionsObject(value, label);
}

function buildJsonFeature(input) {
  if (input === false) {
    return { enabled: false, cage: null, methods: new Set(), contentTypes: new Set(), allowJsonSuffix: true };
  }
  const source = requireOptionsObject(input, 'json options');
  const control = new Set(['enabled', 'methods', 'contentTypes', 'allowJsonSuffix']);
  const cage = createJsonCage(copyExcept(source, control));
  const methods = new Set(
    (source.methods === undefined ? DEFAULT_JSON_METHODS : asArray(source.methods, 'json methods'))
      .map((method) => method.toUpperCase())
  );
  const contentTypes = new Set(
    (source.contentTypes === undefined ? DEFAULT_JSON_CONTENT_TYPES : asArray(source.contentTypes, 'json contentTypes'))
      .map((type) => type.toLowerCase())
  );
  return {
    enabled: source.enabled !== false,
    cage,
    methods,
    contentTypes,
    allowJsonSuffix: source.allowJsonSuffix !== false
  };
}

function buildCookieFeature(input) {
  if (input === false) return { enabled: false, guard: null, parseRequest: false };
  const source = requireOptionsObject(input, 'cookie options');
  assertOnlyKeys(source, new Set(['enabled', 'parseRequest', 'serialize', 'delete', 'parse', 'sign', 'verify', 'keyOrKeyring']), 'cookie options');
  const guardOptions = copyDefined(source, ['serialize', 'delete', 'parse', 'sign', 'verify', 'keyOrKeyring']);
  return {
    enabled: source.enabled !== false,
    guard: createCookieJarGuard(guardOptions),
    parseRequest: source.parseRequest !== false
  };
}

function buildRedirectFeature(input) {
  if (input === false) return { enabled: false, guard: null, middleware: null };
  const source = requireOptionsObject(input, 'redirect options');
  if (source.enabled === false) return { enabled: false, guard: null, middleware: null };
  const guard = createRedirectGuard(copyExcept(source, new Set(['enabled'])));
  return {
    enabled: true,
    guard,
    middleware: guard.middleware()
  };
}

function buildHeaderFeature(input) {
  if (input === false) return { enabled: false, record: null };
  const source = input === undefined || input === true ? {} : requireOptionsObject(input, 'header options');
  if (source.enabled === false) return { enabled: false, record: null };
  const headerOptions = copyExcept(source, new Set(['enabled']));
  return {
    enabled: true,
    record: buildSecurityHeaders(headerOptions)
  };
}

function buildCorsFeature(input) {
  if (input === false) return { enabled: false, middleware: null, policy: null };
  const source = requireOptionsObject(input, 'cors options');
  if (source.enabled === false) return { enabled: false, middleware: null, policy: null };
  const middleware = createNodeCorsMiddleware(copyExcept(source, new Set(['enabled'])));
  return {
    enabled: true,
    middleware,
    policy: middleware.policy
  };
}

function buildCsrfFeature(input) {
  if (input === false || input === undefined) return { enabled: false, shield: null };
  const source = requireOptionsObject(input, 'csrf options');
  if (source.enabled === false) return { enabled: false, shield: null };
  const shieldOptions = copyExcept(source, new Set(['enabled']));
  if (shieldOptions.crypto === undefined) shieldOptions.crypto = nodeCrypto;
  return {
    enabled: true,
    shield: createShield(shieldOptions)
  };
}

function buildUrlFeature(input) {
  if (input === false) return { enabled: false, guard: null, safeFetch: null };
  const source = requireOptionsObject(input, 'urlGuard options');
  const guardInput = copyExcept(source, new Set(['enabled']));
  const guard = createGuard(guardInput);
  const fetchOptions = { ...guardInput };
  if (!hasOwn(guardInput, 'dns')) fetchOptions.dns = nodeResolve;
  if (!hasOwn(guardInput, 'checkRebinding')) fetchOptions.checkRebinding = true;
  return {
    enabled: source.enabled !== false,
    guard,
    safeFetch: createSafeFetch(fetchOptions)
  };
}

function defaultLogWriter(line) {
  process.stdout.write(`${line}\n`);
}

function buildLoggerFeature(input) {
  if (input === false) {
    return { enabled: false, log: null, writer: null, logRequests: false, includeHeaders: false, includeRemoteAddress: false };
  }
  const source = requireOptionsObject(input, 'logger options');
  const control = new Set(['enabled', 'writer', 'logRequests', 'includeHeaders', 'includeRemoteAddress']);
  const log = createLogCage(copyExcept(source, control));
  const writer = source.writer === undefined ? defaultLogWriter : source.writer;
  if (typeof writer !== 'function') {
    throw appsecError('ERR_APPSEC_INVALID_OPTIONS', 'logger writer must be a function', 500);
  }
  return {
    enabled: source.enabled !== false,
    log,
    writer,
    logRequests: source.logRequests !== false,
    includeHeaders: source.includeHeaders !== false,
    includeRemoteAddress: source.includeRemoteAddress === true
  };
}

function responseEnded(response) {
  return Boolean(response && (response.writableEnded === true || response.finished === true));
}

function appendResponseHeader(response, name, value) {
  if (!response || typeof response.setHeader !== 'function') {
    throw appsecError('ERR_APPSEC_INVALID_RESPONSE', 'response must provide setHeader(name, value)', 500);
  }
  const existing = typeof response.getHeader === 'function' ? response.getHeader(name) : undefined;
  if (existing === undefined || existing === null) {
    response.setHeader(name, value);
    return response;
  }
  const values = Array.isArray(existing) ? existing.slice() : [String(existing)];
  values.push(value);
  response.setHeader(name, values);
  return response;
}

function defineResponseHelper(response, name, value) {
  if (response[name] !== undefined) {
    throw appsecError('ERR_APPSEC_HELPER_COLLISION', `response already has a ${name} property`, 500);
  }
  Object.defineProperty(response, name, {
    value,
    writable: true,
    configurable: true,
    enumerable: false
  });
}

function installCookieHelpers(response, guard) {
  defineResponseHelper(response, 'secureCookie', function secureCookie(name, value, options) {
    appendResponseHeader(response, 'Set-Cookie', guard.serialize(name, value, options));
    return response;
  });
  defineResponseHelper(response, 'clearSecureCookie', function clearSecureCookie(name, options) {
    appendResponseHeader(response, 'Set-Cookie', guard.delete(name, options));
    return response;
  });
  defineResponseHelper(response, 'signSecureCookie', function signSecureCookie(name, value, options) {
    const source = options === undefined ? {} : options;
    if (!isObject(source)) {
      throw appsecError('ERR_APPSEC_INVALID_OPTIONS', 'signSecureCookie options must be an object', 500);
    }
    const signed = guard.sign(name, value, source.sign);
    appendResponseHeader(response, 'Set-Cookie', guard.serialize(name, signed, source.serialize));
    return response;
  });
}

function installRedirectHelper(request, response, feature) {
  feature.middleware(request, response, () => {});
  if (response.secureRedirect !== undefined) {
    throw appsecError('ERR_APPSEC_HELPER_COLLISION', 'response already has a secureRedirect property', 500);
  }
  Object.defineProperty(response, 'secureRedirect', {
    value: response.safeRedirect,
    writable: true,
    configurable: true,
    enumerable: false
  });
}

function attachRequestValue(request, name, value) {
  if (request[name] !== undefined && request[name] !== value) {
    throw appsecError('ERR_APPSEC_HELPER_COLLISION', `request already has a ${name} property`, 500);
  }
  Object.defineProperty(request, name, {
    value,
    writable: true,
    configurable: true,
    enumerable: false
  });
}

function safeErrorCode(error) {
  const code = typeof error === 'object' && error !== null && typeof error.code === 'string' ? error.code : '';
  if (/^[A-Za-z0-9_.-]{3,96}$/.test(code)) return code.replaceAll('/', '_');
  return 'ERR_SECURITY_REJECTED';
}

function errorStatus(error) {
  if (Number.isInteger(error?.status) && error.status >= 400 && error.status <= 599) return error.status;
  if (Number.isInteger(error?.statusCode) && error.statusCode >= 400 && error.statusCode <= 599) return error.statusCode;
  const code = String(error?.code || '');
  if (/MAX_BYTES|TOO_LARGE|LIMIT_EXCEEDED|PAYLOAD/.test(code)) return 413;
  if (error?.name === 'JwtGuardError' || code.startsWith('ERR_JWTGUARD') || code === 'ERR_APPSEC_AUTH_TOKEN_MISSING') return 401;
  if (error?.name === 'HookVerifyError') return code === 'INVALID_BODY' ? 400 : 401;
  if (error?.name === 'CsrfShieldError') return 403;
  return 400;
}

function publicErrorMessage(status) {
  if (status === 400) return 'request rejected';
  if (status === 401) return 'authentication required';
  if (status === 403) return 'request forbidden';
  if (status === 413) return 'request body too large';
  if (status === 415) return 'unsupported media type';
  if (status >= 500) return 'internal server error';
  return 'request rejected';
}

function writeJsonResponse(response, status, payload) {
  if (!response || responseEnded(response) || response.headersSent === true) return false;
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  response.statusCode = status;
  if (typeof response.setHeader === 'function') {
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Content-Length', body.length);
  }
  if (typeof response.end === 'function') response.end(body);
  return true;
}

function writeSecurityError(response, error) {
  const status = errorStatus(error);
  return writeJsonResponse(response, status, {
    error: {
      code: safeErrorCode(error),
      message: publicErrorMessage(status)
    }
  });
}

async function handleMiddlewareError(error, request, response, next, behavior) {
  if (behavior && typeof behavior.onError === 'function') {
    await behavior.onError(error, request, response, next);
    return 'error';
  }
  if (behavior && behavior.passErrors === true && typeof next === 'function') {
    next(error);
    return 'error';
  }
  if (!writeSecurityError(response, error) && typeof next === 'function') {
    next(error);
  }
  return 'error';
}

function createBodyLimitError() {
  return appsecError('ERR_APPSEC_BODY_TOO_LARGE', 'request body exceeds the configured byte limit', 413);
}

function readRequestBody(request, maxBytes) {
  return new Promise((resolve, reject) => {
    if (!request || typeof request.on !== 'function') {
      resolve(Buffer.alloc(0));
      return;
    }
    if (request.readableEnded === true) {
      resolve(Buffer.alloc(0));
      return;
    }
    const chunks = [];
    let total = 0;
    let settled = false;

    function cleanup() {
      request.removeListener('data', onData);
      request.removeListener('end', onEnd);
      request.removeListener('error', onError);
    }

    function fail(error) {
      if (settled) return;
      settled = true;
      cleanup();
      if (typeof request.resume === 'function') request.resume();
      reject(error);
    }

    function onData(chunk) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += bytes.length;
      if (total > maxBytes) {
        fail(createBodyLimitError());
        return;
      }
      chunks.push(bytes);
    }

    function onEnd() {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Buffer.concat(chunks, total));
    }

    function onError(error) {
      fail(error);
    }

    request.on('data', onData);
    request.once('end', onEnd);
    request.once('error', onError);
  });
}

function parseContentLength(value) {
  if (value === undefined) return null;
  if (Array.isArray(value)) {
    throw appsecError('ERR_APPSEC_INVALID_CONTENT_LENGTH', 'duplicate Content-Length headers are not allowed', 400);
  }
  const text = String(value);
  if (!/^(0|[1-9][0-9]*)$/.test(text)) {
    throw appsecError('ERR_APPSEC_INVALID_CONTENT_LENGTH', 'Content-Length must be one non-negative integer', 400);
  }
  return Number(text);
}

function contentTypeMatches(value, feature) {
  const mediaType = String(value || '').split(';', 1)[0].trim().toLowerCase();
  if (mediaType.length === 0) return false;
  if (feature.contentTypes.has(mediaType)) return true;
  return feature.allowJsonSuffix && mediaType.startsWith('application/') && mediaType.endsWith('+json');
}

function shouldParseJson(request, feature) {
  if (!feature.enabled || !feature.cage) return false;
  const method = String(request.method || 'GET').toUpperCase();
  if (!feature.methods.has(method)) return false;
  if (request.body !== undefined) return true;
  return contentTypeMatches(request.headers && request.headers['content-type'], feature);
}

function normalizeExistingJsonBody(request, feature) {
  const body = request.body;
  if (typeof body === 'string') {
    request.body = feature.cage.parse(body);
    return;
  }
  if (Buffer.isBuffer(body) || body instanceof Uint8Array || body instanceof ArrayBuffer) {
    request.body = feature.cage.parseBytes(body);
    return;
  }
  const serialized = feature.cage.stringify(body);
  request.body = feature.cage.parse(serialized);
}

async function applyJsonBodyGuard(request, feature) {
  if (!shouldParseJson(request, feature)) return false;
  if (request.body !== undefined) {
    normalizeExistingJsonBody(request, feature);
    return true;
  }
  const maxBytes = feature.cage.options.maxBytes;
  const declared = parseContentLength(request.headers && request.headers['content-length']);
  if (declared !== null && declared > maxBytes) {
    if (typeof request.resume === 'function') request.resume();
    throw createBodyLimitError();
  }
  const raw = await readRequestBody(request, maxBytes);
  if (request.rawBody === undefined) {
    attachRequestValue(request, 'rawBody', raw);
  }
  request.body = feature.cage.parseBytes(raw);
  return true;
}

function emptyCookieMap() {
  return Object.create(null);
}

function applyCookieGuard(request, feature) {
  if (!feature.enabled || !feature.guard || !feature.parseRequest) return false;
  const header = request.headers && request.headers.cookie;
  let parsed;
  if (header === undefined || header === null || header === '') {
    parsed = emptyCookieMap();
  } else if (typeof header !== 'string') {
    throw appsecError('ERR_APPSEC_INVALID_COOKIE_HEADER', 'Cookie header must be a single string', 400);
  } else {
    parsed = feature.guard.parse(header);
  }
  attachRequestValue(request, 'secureCookies', parsed);
  return true;
}

function invokeCsrfMiddleware(shield, request, response) {
  if (response.locals === undefined || response.locals === null) response.locals = {};
  return new Promise((resolve, reject) => {
    let settled = false;
    function done(error) {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve();
    }
    try {
      const result = shield.middleware(request, response, done);
      if (result && typeof result.then === 'function') result.catch(done);
    } catch (error) {
      done(error);
    }
  }).then(() => {
    if (response.locals && response.locals.csrfToken !== undefined && request.csrfToken === undefined) {
      attachRequestValue(request, 'csrfToken', response.locals.csrfToken);
    }
  });
}

function requestMetaForLog(request, response, started, feature) {
  const meta = {
    method: String(request.method || 'GET'),
    url: safeUrlForLog(request.url),
    statusCode: response.statusCode,
    durationMs: Math.max(0, Date.now() - started)
  };
  if (feature.includeHeaders) {
    const headers = {};
    for (const name of ['user-agent', 'content-type', 'origin', 'referer', 'authorization', 'cookie']) {
      const value = request.headers && request.headers[name];
      if (value !== undefined) headers[name] = Array.isArray(value) ? value.join(', ') : value;
    }
    meta.headers = headers;
  }
  if (feature.includeRemoteAddress && request.socket && request.socket.remoteAddress) {
    meta.remoteAddress = request.socket.remoteAddress;
  }
  return meta;
}


function safeUrlForLog(value) {
  const text = String(value || '');
  let end = text.length;
  const query = text.indexOf('?');
  if (query !== -1) end = Math.min(end, query);
  const fragment = text.indexOf('#');
  if (fragment !== -1) end = Math.min(end, fragment);
  return text.slice(0, Math.min(end, 2048));
}

function installRequestLogging(request, response, feature, started) {
  if (!feature.enabled || !feature.logRequests || typeof response.once !== 'function') return;
  response.once('finish', () => {
    try {
      const line = feature.log.json('info', 'http request', requestMetaForLog(request, response, started, feature));
      feature.writer(line);
    } catch (_) {
      // Logging must not change the response after it has finished.
    }
  });
}

function buildErrorBehavior(source) {
  return {
    passErrors: source.passErrors === true,
    onError: typeof source.onError === 'function' ? source.onError : null
  };
}

function createSecurityMiddleware(options) {
  const source = requireOptionsObject(options, 'security middleware options');
  assertOnlyKeys(source, new Set([
    'headers', 'cors', 'cookies', 'redirect', 'json', 'csrf', 'urlGuard', 'logger',
    'contextKey', 'passErrors', 'onError'
  ]), 'security middleware options');
  const headers = buildHeaderFeature(source.headers);
  const cors = buildCorsFeature(source.cors);
  const cookies = buildCookieFeature(source.cookies);
  const redirect = buildRedirectFeature(source.redirect);
  const json = buildJsonFeature(source.json);
  const csrf = buildCsrfFeature(source.csrf);
  const url = buildUrlFeature(source.urlGuard);
  const logger = buildLoggerFeature(source.logger);
  const behavior = buildErrorBehavior(source);
  const contextKey = typeof source.contextKey === 'string' && source.contextKey.length > 0
    ? source.contextKey
    : DEFAULT_CONTEXT_KEY;

  const urlApi = url.enabled && url.guard ? Object.freeze({
    guard: url.guard,
    validate: url.guard.validate,
    assert: url.guard.assert,
    isPublicHostname: url.guard.isPublicHostname,
    safeFetch: url.safeFetch
  }) : null;

  const context = Object.freeze({
    headers: headers.record,
    cors: cors.policy,
    cookies: cookies.enabled ? cookies.guard : null,
    redirect: redirect.enabled ? redirect.guard : null,
    json: json.enabled ? json.cage : null,
    csrf: csrf.enabled ? csrf.shield : null,
    url: urlApi,
    log: logger.enabled ? logger.log : null,
    validateUrl: urlApi ? urlApi.validate : null,
    assertSafeUrl: urlApi ? urlApi.assert : null,
    safeFetch: urlApi ? urlApi.safeFetch : null
  });

  async function securityMiddleware(request, response, next) {
    const started = Date.now();
    try {
      if (!request || typeof request !== 'object') {
        throw appsecError('ERR_APPSEC_INVALID_REQUEST', 'request must be an object', 500);
      }
      if (!response || typeof response !== 'object') {
        throw appsecError('ERR_APPSEC_INVALID_RESPONSE', 'response must be an object', 500);
      }

      attachRequestValue(request, contextKey, context);
      installRequestLogging(request, response, logger, started);

      if (headers.enabled) applyHeaderRecord(response, headers.record);
      if (cookies.enabled) installCookieHelpers(response, cookies.guard);
      if (redirect.enabled) installRedirectHelper(request, response, redirect);

      if (cors.enabled) {
        let continued = false;
        cors.middleware(request, response, () => {
          continued = true;
        });
        if (!continued) return 'end';
      }

      if (cookies.enabled) applyCookieGuard(request, cookies);
      await applyJsonBodyGuard(request, json);
      if (csrf.enabled) await invokeCsrfMiddleware(csrf.shield, request, response);

      if (typeof next === 'function') next();
      return 'next';
    } catch (error) {
      return handleMiddlewareError(error, request, response, next, behavior);
    }
  }

  Object.defineProperty(securityMiddleware, 'appsec', {
    value: context,
    enumerable: false
  });
  Object.defineProperty(securityMiddleware, 'contextKey', {
    value: contextKey,
    enumerable: false
  });
  return securityMiddleware;
}

function createPathGuard(rootDir, options) {
  const source = requireOptionsObject(options, 'path guard options');
  const filenameOptions = source.filename === undefined ? undefined : requireOptionsObject(source.filename, 'filename options');
  const cageOptions = copyExcept(source, new Set(['filename']));
  const cage = createCage(rootDir, cageOptions);
  return Object.freeze({
    root: cage.root,
    rootReal: cage.rootReal,
    resolve: cage.resolve.bind(cage),
    realpathCheck: cage.realpathCheck.bind(cage),
    assertInside: cage.assertInside.bind(cage),
    validateBatch: cage.validateBatch.bind(cage),
    sanitizeFilename(input, overrides) {
      return sanitizeFilename(input, { ...(filenameOptions || {}), ...(overrides || {}) });
    },
    isInside(candidate) {
      return isInside(cage.root, candidate) || isInside(cage.rootReal, candidate);
    },
    cage
  });
}

function createEnvGuard(schema, options) {
  const source = requireOptionsObject(options, 'env guard options');
  const hasSource = hasOwn(source, 'source');
  const envSource = hasSource ? source.source : process.env;
  const defineOptions = copyExcept(source, new Set(['source']));
  const config = defineEnv(schema, envSource, defineOptions);
  return Object.freeze({
    config,
    snapshot: safeSnapshot(config),
    redact(value) {
      return redact(config, value);
    },
    redactString(value) {
      return redactString(config, value);
    },
    redactObject(value) {
      return redactObject(config, value);
    },
    parseDotEnv,
    loadEnvFile
  });
}

function createZipUploadGuard(options) {
  const source = requireOptionsObject(options, 'zip upload guard options');
  const guard = createZipGuard(source);
  return Object.freeze({
    guard,
    options: guard.options,
    inspect: guard.inspect.bind(guard),
    assertSafe: guard.assertSafe.bind(guard),
    validate: guard.assertSafe.bind(guard),
    readEntry: guard.readEntry.bind(guard),
    extract: guard.extract.bind(guard)
  });
}

function extractBearerToken(request) {
  const header = request && request.headers && request.headers.authorization;
  if (header === undefined || header === null || header === '') {
    throw appsecError('ERR_APPSEC_AUTH_TOKEN_MISSING', 'Authorization bearer token is missing', 401);
  }
  if (Array.isArray(header)) {
    throw appsecError('ERR_APPSEC_AUTH_TOKEN_INVALID', 'duplicate Authorization headers are not allowed', 401);
  }
  const match = /^Bearer ([^\s]+)$/i.exec(String(header));
  if (!match) {
    throw appsecError('ERR_APPSEC_AUTH_TOKEN_INVALID', 'Authorization header must use Bearer token syntax', 401);
  }
  return match[1];
}

function createJwtAuthMiddleware(options) {
  const source = requireOptionsObject(options, 'jwt auth options');
  const key = source.key !== undefined ? source.key : (source.keyMaterial !== undefined ? source.keyMaterial : source.secret);
  if (key === undefined) {
    throw appsecError('ERR_APPSEC_INVALID_OPTIONS', 'jwt key, keyMaterial or secret is required', 500);
  }
  if (!Array.isArray(source.algorithms) || source.algorithms.length === 0) {
    throw appsecError('ERR_APPSEC_INVALID_OPTIONS', 'jwt algorithms must be an explicit non-empty array', 500);
  }
  assertOnlyKeys(source, new Set([
    'key', 'keyMaterial', 'secret', 'algorithms', 'now', 'clockToleranceSeconds', 'requiredClaims',
    'issuer', 'audience', 'subject', 'jwtId', 'maxAgeSeconds', 'maxTokenBytes',
    'allowDangerousHeaders', 'tokenExtractor', 'attachAs', 'passErrors', 'onError', 'enabled'
  ]), 'jwt auth options');
  const verifyOptions = copyDefined(source, [
    'algorithms', 'now', 'clockToleranceSeconds', 'requiredClaims', 'issuer', 'audience',
    'subject', 'jwtId', 'maxAgeSeconds', 'maxTokenBytes', 'allowDangerousHeaders'
  ]);
  const extractor = source.tokenExtractor === undefined ? extractBearerToken : source.tokenExtractor;
  if (typeof extractor !== 'function') {
    throw appsecError('ERR_APPSEC_INVALID_OPTIONS', 'tokenExtractor must be a function', 500);
  }
  const attachAs = typeof source.attachAs === 'string' && source.attachAs.length > 0 ? source.attachAs : 'auth';
  const behavior = buildErrorBehavior(source);

  return async function jwtAuthMiddleware(request, response, next) {
    try {
      const token = extractor(request);
      if (typeof token !== 'string' || token.length === 0) {
        throw appsecError('ERR_APPSEC_AUTH_TOKEN_MISSING', 'token extractor did not return a token', 401);
      }
      const payload = verifyJwt(token, key, verifyOptions);
      attachRequestValue(request, attachAs, payload);
      if (typeof next === 'function') next();
      return 'next';
    } catch (error) {
      return handleMiddlewareError(error, request, response, next, behavior);
    }
  };
}

function webhookSecretConfigured(source) {
  return source.secret !== undefined || (Array.isArray(source.secrets) && source.secrets.length > 0);
}

function createWebhookMiddleware(options) {
  const source = requireOptionsObject(options, 'webhook middleware options');
  if (source.provider === undefined || source.provider === null) {
    throw appsecError('ERR_APPSEC_INVALID_OPTIONS', 'webhook provider is required', 500);
  }
  const provider = getProvider(source.provider);
  if (!provider.secretOptional && !webhookSecretConfigured(source)) {
    throw appsecError('ERR_APPSEC_INVALID_OPTIONS', 'webhook secret or secrets are required', 500);
  }
  const control = new Set([
    'provider', 'maxBodyBytes', 'attachAs', 'rawBodyProperty', 'passErrors', 'onError', 'enabled'
  ]);
  const verifierOptions = copyExcept(source, control);
  const verifier = createVerifier(verifierOptions);
  const maxBodyBytes = Number.isInteger(source.maxBodyBytes) && source.maxBodyBytes > 0
    ? source.maxBodyBytes
    : DEFAULT_WEBHOOK_MAX_BODY_BYTES;
  const attachAs = typeof source.attachAs === 'string' && source.attachAs.length > 0 ? source.attachAs : 'webhook';
  const rawBodyProperty = typeof source.rawBodyProperty === 'string' && source.rawBodyProperty.length > 0
    ? source.rawBodyProperty
    : 'rawBody';
  const behavior = buildErrorBehavior(source);

  return async function webhookMiddleware(request, response, next) {
    try {
      let raw;
      const existingRaw = request[rawBodyProperty];
      if (Buffer.isBuffer(existingRaw)) raw = existingRaw;
      else if (typeof existingRaw === 'string') raw = Buffer.from(existingRaw, 'utf8');
      else if (Buffer.isBuffer(request.body)) raw = request.body;
      else if (typeof request.body === 'string') raw = Buffer.from(request.body, 'utf8');
      else if (request.body !== undefined) {
        throw appsecError('ERR_APPSEC_WEBHOOK_BODY_UNAVAILABLE', 'raw webhook body is required for signature verification', 400);
      } else {
        const declared = parseContentLength(request.headers && request.headers['content-length']);
        if (declared !== null && declared > maxBodyBytes) {
          if (typeof request.resume === 'function') request.resume();
          throw createBodyLimitError();
        }
        raw = await readRequestBody(request, maxBodyBytes);
      }
      attachRequestValue(request, rawBodyProperty, raw);
      const verified = await verifier.verifyAsync(provider, raw, request.headers || {});
      attachRequestValue(request, attachAs, verified);
      if (typeof next === 'function') next();
      return 'next';
    } catch (error) {
      return handleMiddlewareError(error, request, response, next, behavior);
    }
  };
}

function appendFrameworkSetCookie(target, serialized, rawResponse) {
  if (target && typeof target.getHeader === 'function' && typeof target.header === 'function') {
    const existing = target.getHeader('Set-Cookie');
    if (existing === undefined || existing === null) target.header('Set-Cookie', serialized);
    else target.header('Set-Cookie', Array.isArray(existing) ? existing.concat(serialized) : [String(existing), serialized]);
    return;
  }
  appendResponseHeader(rawResponse || target, 'Set-Cookie', serialized);
}

function registerFastifyJsonParser(fastify, jsonInput) {
  if (!fastify || typeof fastify.addContentTypeParser !== 'function' || jsonInput === false) return false;
  const feature = buildJsonFeature(jsonInput);
  if (!feature.enabled || !feature.cage) return false;
  if (typeof fastify.removeContentTypeParser === 'function') {
    try {
      fastify.removeContentTypeParser('application/json');
    } catch (_) {
      // Older Fastify versions either do not need removal or override the default parser.
    }
  }
  const parserOptions = {
    parseAs: 'buffer',
    bodyLimit: feature.cage.options.maxBytes
  };
  function parseJsonWithCage(request, body, done) {
    try {
      done(null, feature.cage.parseBytes(body));
    } catch (error) {
      done(error);
    }
  }
  fastify.addContentTypeParser('application/json', parserOptions, parseJsonWithCage);
  if (feature.allowJsonSuffix) {
    fastify.addContentTypeParser(FASTIFY_JSON_SUFFIX_TYPE, parserOptions, parseJsonWithCage);
  }
  return true;
}

function fastifyAppsecPlugin(fastify, options, done) {
  let pluginOptions = options;
  let callback = done;
  if (typeof pluginOptions === 'function') {
    callback = pluginOptions;
    pluginOptions = {};
  }
  try {
    const source = requireOptionsObject(pluginOptions, 'fastify appsec options');
    if (!fastify || typeof fastify.addHook !== 'function') {
      throw appsecError('ERR_APPSEC_INVALID_FASTIFY', 'fastifyAppsecPlugin requires a Fastify-like instance', 500);
    }
    const parserInstalled = registerFastifyJsonParser(fastify, source.json);
    const middlewareOptions = { ...source, json: parserInstalled ? false : source.json };
    const middleware = createSecurityMiddleware(middlewareOptions);
    const contextKey = middleware.contextKey;

    fastify.addHook('onRequest', function appsecFastifyHook(request, reply, hookDone) {
      const rawRequest = request && request.raw ? request.raw : request;
      const rawResponse = reply && reply.raw ? reply.raw : reply;
      const bridge = () => {
        if (rawRequest[contextKey]) {
          request[contextKey] = rawRequest[contextKey];
          reply[contextKey] = rawRequest[contextKey];
        }
        if (rawRequest.body !== undefined) request.body = rawRequest.body;
        if (rawRequest.rawBody !== undefined) request.rawBody = rawRequest.rawBody;
        if (rawRequest.secureCookies !== undefined) request.secureCookies = rawRequest.secureCookies;
        if (rawRequest.csrfToken !== undefined) request.csrfToken = rawRequest.csrfToken;
        const context = rawRequest[contextKey];
        if (context && context.cookies) {
          reply.secureCookie = function secureCookie(name, value, cookieOptions) {
            appendFrameworkSetCookie(reply, context.cookies.serialize(name, value, cookieOptions), rawResponse);
            return reply;
          };
          reply.clearSecureCookie = function clearSecureCookie(name, cookieOptions) {
            appendFrameworkSetCookie(reply, context.cookies.delete(name, cookieOptions), rawResponse);
            return reply;
          };
          reply.signSecureCookie = function signSecureCookie(name, value, helperOptions) {
            const helper = helperOptions === undefined ? {} : helperOptions;
            const signed = context.cookies.sign(name, value, helper.sign);
            appendFrameworkSetCookie(reply, context.cookies.serialize(name, signed, helper.serialize), rawResponse);
            return reply;
          };
        }
        if (context && context.redirect) {
          reply.safeRedirect = function safeRedirect(target, status) {
            const location = context.redirect.sanitize(target);
            if (typeof reply.code === 'function') reply.code(status === undefined ? 302 : status);
            if (typeof reply.header === 'function') reply.header('Location', location);
            if (typeof reply.send === 'function') return reply.send();
            rawResponse.statusCode = status === undefined ? 302 : status;
            rawResponse.setHeader('Location', location);
            if (typeof rawResponse.end === 'function') rawResponse.end();
            return reply;
          };
          reply.secureRedirect = reply.safeRedirect;
        }
      };
      let finished = false;
      const finish = (error) => {
        if (finished) return;
        finished = true;
        if (!error) {
          try {
            bridge();
          } catch (bridgeError) {
            hookDone(bridgeError);
            return;
          }
        }
        hookDone(error);
      };
      Promise.resolve(middleware(rawRequest, rawResponse, finish)).then((state) => {
        if (finished) return;
        finished = true;
        if (state !== 'next' && reply && typeof reply.hijack === 'function') reply.hijack();
        hookDone();
      }).catch(finish);
    });

    if (typeof callback === 'function') callback();
  } catch (error) {
    if (typeof callback === 'function') callback(error);
    else throw error;
  }
}

function assignIfPossible(object, name, value) {
  if (!object || value === undefined) return;
  try {
    if (object[name] === undefined) object[name] = value;
  } catch (_) {
    // Framework request objects can be frozen. The raw request still carries the value.
  }
}

function createKoaSecurityMiddleware(options) {
  const source = requireOptionsObject(options, 'koa appsec options');
  const middleware = createSecurityMiddleware(source);
  const contextKey = middleware.contextKey;

  return async function koaSecurityMiddleware(ctx, next) {
    if (!ctx || !ctx.req || !ctx.res) {
      throw appsecError('ERR_APPSEC_INVALID_KOA_CONTEXT', 'Koa context must provide req and res', 500);
    }
    if (ctx.request && ctx.request.body !== undefined && ctx.req.body === undefined) {
      ctx.req.body = ctx.request.body;
    }
    let middlewareError = null;
    let continued = false;
    const state = await middleware(ctx.req, ctx.res, (error) => {
      if (error) middlewareError = error;
      else continued = true;
    });
    if (middlewareError) throw middlewareError;
    if (!continued || state === 'end' || state === 'error') {
      if (responseEnded(ctx.res)) ctx.respond = false;
      return;
    }

    ctx.state = ctx.state || {};
    const context = ctx.req[contextKey];
    ctx.state[contextKey] = context;
    assignIfPossible(ctx.request, 'body', ctx.req.body);
    assignIfPossible(ctx.request, 'rawBody', ctx.req.rawBody);
    assignIfPossible(ctx.request, 'secureCookies', ctx.req.secureCookies);
    assignIfPossible(ctx.request, 'csrfToken', ctx.req.csrfToken);

    if (context && context.cookies) {
      ctx.secureCookie = function secureCookie(name, value, cookieOptions) {
        const serialized = context.cookies.serialize(name, value, cookieOptions);
        if (typeof ctx.append === 'function') ctx.append('Set-Cookie', serialized);
        else appendResponseHeader(ctx.res, 'Set-Cookie', serialized);
        return ctx;
      };
      ctx.clearSecureCookie = function clearSecureCookie(name, cookieOptions) {
        const serialized = context.cookies.delete(name, cookieOptions);
        if (typeof ctx.append === 'function') ctx.append('Set-Cookie', serialized);
        else appendResponseHeader(ctx.res, 'Set-Cookie', serialized);
        return ctx;
      };
      ctx.signSecureCookie = function signSecureCookie(name, value, helperOptions) {
        const helper = helperOptions === undefined ? {} : helperOptions;
        const signed = context.cookies.sign(name, value, helper.sign);
        const serialized = context.cookies.serialize(name, signed, helper.serialize);
        if (typeof ctx.append === 'function') ctx.append('Set-Cookie', serialized);
        else appendResponseHeader(ctx.res, 'Set-Cookie', serialized);
        return ctx;
      };
    }
    if (context && context.redirect) {
      ctx.safeRedirect = function safeRedirect(target, status) {
        const location = context.redirect.sanitize(target);
        ctx.status = status === undefined ? 302 : status;
        if (typeof ctx.set === 'function') ctx.set('Location', location);
        else ctx.res.setHeader('Location', location);
        ctx.body = '';
        return location;
      };
      ctx.secureRedirect = ctx.safeRedirect;
    }

    await next();
  };
}

const api = {
  createSecurityMiddleware,
  createPathGuard,
  createEnvGuard,
  createZipUploadGuard,
  createJwtAuthMiddleware,
  createWebhookMiddleware,
  fastifyAppsecPlugin,
  createKoaSecurityMiddleware,
  MemoryReplayStore
};

module.exports = api;
module.exports.default = api;
