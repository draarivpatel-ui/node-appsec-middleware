import type {
  Cage,
  CageOptions,
  FilenameOptions,
  ArchiveEntry,
  ValidatedArchiveEntry
} from 'pathcage';
import type { SecurityHeaderOptions } from 'headersafe';
import type { CorsPolicy, CorsPolicyOptions } from 'corscage';
import type { RedirectGuard, RedirectOptions } from 'redirectcage';
import type {
  CookieJarGuard,
  CookieKeyring,
  DeleteCookieOptions,
  GuardSignOptions,
  GuardVerifyOptions,
  KeyOrKeyring,
  ParseCookieHeaderOptions,
  SerializeCookieOptions
} from 'cookiecage';
import type {
  ZipCageExtractionResult,
  ZipCageGuard,
  ZipCageInput,
  ZipCageOptions,
  ZipCageReport
} from 'zipcage';
import type {
  FormatSafeJsonLogOptions,
  LogCage
} from 'logcage';
import type { JsonCageInstance, JsonCageOptions } from 'jsoncage';
import type { Shield, ShieldOptions } from '@aarivbuildz/csrfshield';
import type {
  Guard as UrlGuardInstance,
  ValidationResult,
  ValidationSuccess,
  ValidateOptions
} from '@aarivbuildz/urlguard';
import type {
  EnvSchema,
  InferConfig,
  LoadEnvFileOptions,
  ParseDotEnvOptions,
  Redacted
} from 'envcage';
import type {
  Provider,
  ReplayStore,
  VerificationResult,
  VerifyOptions as HookVerifyOptions
} from '@aarivbuildz/hookverify';

export type JwtAlgorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'PS256' | 'ES256' | 'EdDSA';
export type JwtKeyMaterial = string | Uint8Array | object;

export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  jti?: string;
  exp?: number;
  nbf?: number;
  iat?: number;
  [key: string]: unknown;
}

export type HeaderValue = string | string[] | undefined;
export type HeaderRecord = Record<string, HeaderValue>;

export interface NodeRequestLike {
  method?: string;
  url?: string;
  headers?: HeaderRecord;
  body?: unknown;
  rawBody?: Uint8Array;
  socket?: { remoteAddress?: string };
  [key: string]: unknown;
}

export interface NodeResponseLike {
  statusCode: number;
  headersSent?: boolean;
  writableEnded?: boolean;
  finished?: boolean;
  locals?: Record<string, unknown>;
  setHeader(name: string, value: string | number | readonly string[]): unknown;
  getHeader(name: string): unknown;
  removeHeader?(name: string): unknown;
  end?(chunk?: unknown): unknown;
  once?(event: string, listener: (...args: unknown[]) => void): unknown;
  [key: string]: unknown;
}

export type NextFunction = (error?: unknown) => void;
export type SecurityMiddlewareResult = 'next' | 'end' | 'error';
export type SecurityErrorHandler = (
  error: unknown,
  request: NodeRequestLike,
  response: NodeResponseLike,
  next?: NextFunction
) => void | Promise<void>;

export interface FeatureToggle {
  /** Disable one feature without removing its configuration. Default true. */
  enabled?: boolean;
}

export interface JsonMiddlewareOptions extends JsonCageOptions, FeatureToggle {
  /** Methods whose JSON bodies are parsed. Default POST, PUT, PATCH and DELETE. */
  methods?: string | readonly string[];
  /** Exact media types to parse. Default application/json. */
  contentTypes?: string | readonly string[];
  /** Also parse application/*+json media types. Default true. */
  allowJsonSuffix?: boolean;
}

export interface CookieMiddlewareOptions extends FeatureToggle {
  /** Parse and validate the inbound Cookie header into req.secureCookies. Default true. */
  parseRequest?: boolean;
  serialize?: SerializeCookieOptions;
  delete?: DeleteCookieOptions;
  parse?: ParseCookieHeaderOptions;
  sign?: GuardSignOptions;
  verify?: GuardVerifyOptions;
  keyOrKeyring?: KeyOrKeyring;
}

export interface LoggerMiddlewareOptions extends FormatSafeJsonLogOptions, FeatureToggle {
  /** Receives one complete NDJSON line. Default writes to stdout. */
  writer?: (line: string) => void;
  /** Log one redacted NDJSON entry when each response finishes. Default true. */
  logRequests?: boolean;
  /** Include selected request headers. Sensitive values are redacted by logcage. Default true. */
  includeHeaders?: boolean;
  /** Include the socket remote address. Default false. */
  includeRemoteAddress?: boolean;
}

export interface SecurityMiddlewareOptions {
  headers?: (SecurityHeaderOptions & FeatureToggle) | false;
  cors?: (CorsPolicyOptions & FeatureToggle) | false;
  cookies?: CookieMiddlewareOptions | false;
  redirect?: (RedirectOptions & FeatureToggle) | false;
  json?: JsonMiddlewareOptions | false;
  csrf?: (ShieldOptions & FeatureToggle) | false;
  urlGuard?: (ValidateOptions & FeatureToggle) | false;
  logger?: LoggerMiddlewareOptions | false;
  /** Request property that receives the shared security context. Default appsec. */
  contextKey?: string;
  /** Pass validation failures to next(error) instead of sending a safe JSON error. Default false. */
  passErrors?: boolean;
  /** Custom error hook. It is responsible for calling next or ending the response. */
  onError?: SecurityErrorHandler;
}

export interface SecureUrlApi {
  readonly guard: UrlGuardInstance;
  validate(input: string): ValidationResult;
  assert(input: string): ValidationSuccess;
  isPublicHostname(hostname: string): boolean;
  safeFetch(input: string | { url: string }, init?: unknown): Promise<unknown>;
}

export interface SecurityContext {
  readonly headers: Readonly<Record<string, string>> | null;
  readonly cors: CorsPolicy | null;
  readonly cookies: CookieJarGuard | null;
  readonly redirect: RedirectGuard | null;
  readonly json: JsonCageInstance | null;
  readonly csrf: Shield | null;
  readonly url: SecureUrlApi | null;
  readonly log: LogCage | null;
  readonly validateUrl: ((input: string) => ValidationResult) | null;
  readonly assertSafeUrl: ((input: string) => ValidationSuccess) | null;
  readonly safeFetch: ((input: string | { url: string }, init?: unknown) => Promise<unknown>) | null;
}

export interface SecurityMiddleware {
  (request: NodeRequestLike, response: NodeResponseLike, next?: NextFunction): Promise<SecurityMiddlewareResult>;
  readonly appsec: SecurityContext;
  readonly contextKey: string;
}

export declare function createSecurityMiddleware(options?: SecurityMiddlewareOptions): SecurityMiddleware;

export interface PathGuard {
  readonly root: string;
  readonly rootReal: string;
  resolve(input: string, options?: Partial<CageOptions>): string;
  realpathCheck(candidate: string, options?: Partial<CageOptions>): string;
  assertInside(candidate: string, options?: Partial<CageOptions>): string;
  validateBatch(inputs: readonly string[], options?: Partial<CageOptions>): string[];
  sanitizeFilename(input: string, overrides?: FilenameOptions): string;
  isInside(candidate: string): boolean;
  readonly cage: Cage;
}

export interface PathGuardOptions extends CageOptions {
  filename?: FilenameOptions;
}

export declare function createPathGuard(rootDir: string, options?: PathGuardOptions): PathGuard;

export interface EnvGuardOptions {
  source?: Record<string, unknown>;
  maxValueLength?: number;
  allowMultiline?: boolean;
}

export interface EnvGuard<S extends EnvSchema> {
  readonly config: InferConfig<S>;
  readonly snapshot: Redacted<InferConfig<S>>;
  redact<T>(value: T): Redacted<T>;
  redactString(value: string): string;
  redactObject<T>(value: T): Redacted<T>;
  parseDotEnv(text: string, options?: ParseDotEnvOptions): Readonly<Record<string, string>>;
  loadEnvFile(filePath: string, options?: LoadEnvFileOptions): Readonly<Record<string, string>>;
}

export declare function createEnvGuard<S extends EnvSchema>(schema: S, options?: EnvGuardOptions): EnvGuard<S>;

export interface ZipUploadGuard {
  readonly guard: ZipCageGuard;
  readonly options: ZipCageGuard['options'];
  inspect(input: ZipCageInput, overrides?: ZipCageOptions): ZipCageReport;
  assertSafe(input: ZipCageInput, overrides?: ZipCageOptions): ZipCageReport;
  validate(input: ZipCageInput, overrides?: ZipCageOptions): ZipCageReport;
  readEntry(input: ZipCageInput, entryName: string, overrides?: ZipCageOptions): Promise<Uint8Array>;
  extract(input: ZipCageInput, targetDir: string, overrides?: ZipCageOptions): Promise<ZipCageExtractionResult>;
}

export declare function createZipUploadGuard(options?: ZipCageOptions): ZipUploadGuard;

export interface JwtAuthMiddlewareOptions {
  key?: JwtKeyMaterial;
  keyMaterial?: JwtKeyMaterial;
  secret?: JwtKeyMaterial;
  algorithms: readonly JwtAlgorithm[];
  now?: number | (() => number);
  clockToleranceSeconds?: number;
  requiredClaims?: readonly string[];
  issuer?: string | readonly string[];
  audience?: string | readonly string[];
  subject?: string;
  jwtId?: string;
  maxAgeSeconds?: number;
  maxTokenBytes?: number;
  allowDangerousHeaders?: readonly ('jku' | 'x5u' | 'jwk' | 'x5c')[];
  tokenExtractor?: (request: NodeRequestLike) => string | null | undefined;
  /** Request property for verified claims. Default auth. */
  attachAs?: string;
  passErrors?: boolean;
  onError?: SecurityErrorHandler;
}

export declare function createJwtAuthMiddleware(
  options: JwtAuthMiddlewareOptions
): (request: NodeRequestLike, response: NodeResponseLike, next?: NextFunction) => Promise<SecurityMiddlewareResult>;

export interface WebhookMiddlewareOptions extends HookVerifyOptions {
  provider: string | Provider;
  maxBodyBytes?: number;
  /** Request property for the verification result. Default webhook. */
  attachAs?: string;
  /** Request property for the byte exact body. Default rawBody. */
  rawBodyProperty?: string;
  passErrors?: boolean;
  onError?: SecurityErrorHandler;
}

export declare function createWebhookMiddleware(
  options: WebhookMiddlewareOptions
): (request: NodeRequestLike, response: NodeResponseLike, next?: NextFunction) => Promise<SecurityMiddlewareResult>;

export interface FastifyRequestLike {
  raw?: NodeRequestLike;
  body?: unknown;
  rawBody?: Uint8Array;
  secureCookies?: Record<string, string>;
  csrfToken?: string;
  [key: string]: unknown;
}

export interface FastifyReplyLike {
  raw?: NodeResponseLike;
  code?(status: number): unknown;
  header?(name: string, value: unknown): unknown;
  getHeader?(name: string): unknown;
  send?(payload?: unknown): unknown;
  [key: string]: unknown;
}

export interface FastifyLike {
  addHook(name: 'onRequest', hook: (request: FastifyRequestLike, reply: FastifyReplyLike, done: (error?: unknown) => void) => void): unknown;
  addContentTypeParser?(type: string | RegExp, options: Record<string, unknown>, parser: (request: unknown, body: unknown, done: (error?: unknown, value?: unknown) => void) => void): unknown;
  removeContentTypeParser?(type: string): unknown;
}

export declare function fastifyAppsecPlugin(
  fastify: FastifyLike,
  options: SecurityMiddlewareOptions,
  done: (error?: unknown) => void
): void;
export declare function fastifyAppsecPlugin(
  fastify: FastifyLike,
  done: (error?: unknown) => void
): void;

export interface KoaContextLike {
  req: NodeRequestLike;
  res: NodeResponseLike;
  request?: Record<string, unknown>;
  state?: Record<string, unknown>;
  status?: number;
  body?: unknown;
  respond?: boolean;
  append?(name: string, value: string): unknown;
  set?(name: string, value: string): unknown;
  [key: string]: unknown;
}

export type KoaNextFunction = () => unknown | Promise<unknown>;

export declare function createKoaSecurityMiddleware(
  options?: SecurityMiddlewareOptions
): (ctx: KoaContextLike, next: KoaNextFunction) => Promise<void>;

export { MemoryReplayStore } from '@aarivbuildz/hookverify';
export type { ReplayStore, VerificationResult };
