import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomUUID } from 'node:crypto'
import { isIP } from 'node:net'
import { z } from 'zod'
import { deviceRegistrationRequestSchema, deviceRefreshRequestSchema } from '@dsh-remote/protocol'
import { ApiError, Store, equal, hash, secret } from './store.js'
import type { AuthOutcome, AuthProvider } from './auth/logto.js'
import { interpret, verifySignature, type WebhookPayload } from './auth/webhook.js'
import { LoginLockout } from './auth/lockout.js'
import { Gateway } from './gateway.js'
import { buildIceServers, parseIceConfig, type IceConfig } from './ice.js'
import { Logger, type LogLevel } from './logger.js'
import {
  FORCE_TERMINATE_GRACE_MS_RANGE,
  HEARTBEAT_DISCONNECT_MS_MAX,
  HELLO_TIMEOUT_MS_RANGE,
  HEARTBEAT_INTERVAL_MS_RANGE,
  normalizeForceTerminateGraceMs,
  normalizeGatewayOptions,
  normalizeHeartbeatDisconnectMs,
  normalizeHeartbeatIntervalMs,
  normalizeHelloTimeoutMs,
} from './config.js'

export interface Config {
  account: string
  password: string
  dataFile: string
  publicUrl: string
  trustedProxyIps?: readonly string[]
  helloTimeoutMs?: number
  heartbeatIntervalMs?: number
  heartbeatDisconnectMs?: number
  forceTerminateGraceMs?: number
  logLevel?: LogLevel
  ice?: IceConfig
  /**
   * When set, `POST /api/v1/auth/login` verifies credentials through this
   * provider instead of comparing against `password`. The environment-variable
   * single-account check stays as the fallback so a self-hosting operator who
   * has not configured Logto keeps working unchanged.
   */
  auth?: AuthProvider
  /**
   * Signing key for Logto webhooks. When present, `POST /api/v1/hooks/logto`
   * accepts user-lifecycle events and revokes sessions for deleted or suspended
   * accounts immediately instead of waiting for tokens to expire.
   */
  webhookSigningKey?: string
  /**
   * Tuning for the consecutive-failure login lockout. Exposed mainly so tests can
   * reach the threshold without making 25 real requests; production uses the
   * defaults, which sit above the per-address rate limit on purpose.
   */
  lockout?: { threshold?: number; lockMs?: number; streakMs?: number }
}

/**
 * Timing configuration is normalized in one place (`config.ts`) so the CLI and
 * programmatic callers share the same bounds and fallbacks. These wrappers keep
 * the env-var parsing API used by `main.ts` and the tests, and never echo the
 * offending input in their warnings.
 */
export function parseHelloTimeout(val: string | undefined): number {
  return normalizeHelloTimeoutMs(val)
}

export function parseHeartbeatInterval(val: string | undefined): number {
  return normalizeHeartbeatIntervalMs(val)
}

export function parseHeartbeatDisconnect(val: string | undefined, heartbeatIntervalMs: number = HEARTBEAT_INTERVAL_MS_RANGE.fallback): number {
  return normalizeHeartbeatDisconnectMs(val, heartbeatIntervalMs)
}

export function parseForceTerminateGrace(val: string | undefined): number {
  return normalizeForceTerminateGraceMs(val)
}

export {
  normalizeGatewayOptions,
  normalizeHelloTimeoutMs,
  normalizeHeartbeatIntervalMs,
  normalizeHeartbeatDisconnectMs,
  normalizeForceTerminateGraceMs,
  HELLO_TIMEOUT_MS_RANGE,
  HEARTBEAT_INTERVAL_MS_RANGE,
  HEARTBEAT_DISCONNECT_MS_MAX,
  FORCE_TERMINATE_GRACE_MS_RANGE,
}
export type { GatewayTimingOptions, NormalizedGatewayOptions } from './config.js'

const loginSchema = z.object({ email: z.string().min(1).max(254), password: z.string().min(1).max(1024) }).strict()
const publicDir = fileURLToPath(new URL('../dist/public/', import.meta.url))
function readAssets(): Map<string, Buffer> {
  if (!existsSync(publicDir)) return new Map()
  const assets = new Map<string, Buffer>()
  for (const entry of readdirSync(publicDir, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue
    const file = join(entry.parentPath, entry.name)
    const path = file.slice(publicDir.length).replaceAll('\\', '/')
    assets.set(path, readFileSync(file))
  }
  return assets
}
async function body(req: IncomingMessage): Promise<unknown> {
  if (!req.headers['content-type']?.toLowerCase().startsWith('application/json')) throw new ApiError('INVALID_MESSAGE', 415)
  return JSON.parse(await rawBody(req).then(buffer => buffer.toString('utf8'))) as unknown
}
/**
 * Read the request body as bytes. Webhook signatures are computed over the raw
 * bytes, so this must not be replaced with a parsed round-trip.
 */
async function rawBody(req: IncomingMessage, limit = 16384): Promise<Buffer> {
  let length = 0
  const chunks: Buffer[] = []
  for await (const chunk of req) {
    length += chunk.length
    if (length > limit) throw new ApiError('FRAME_TOO_LARGE', 413)
    chunks.push(chunk)
  }
  return Buffer.concat(chunks)
}
/**
 * Normalize one bare IPv4/IPv6 literal to a single canonical form. IPv4-mapped
 * IPv6 addresses (e.g. ::ffff:127.0.0.1) collapse to plain IPv4, so a peer
 * observed through a dual-stack socket and a config entry compare equal.
 * Returns null for anything that is not a single IP literal: hostnames, ports,
 * CIDR ranges, comma-separated lists, bracketed hosts and zone identifiers.
 */
export function normalizeIp(value: string): string | null {
  const family = isIP(value)
  if (family === 4) return value.toLowerCase()
  if (family !== 6) return null
  let canonical: string
  try {
    canonical = new URL(`http://[${value}]/`).hostname.slice(1, -1)
  } catch { return null }
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(canonical)
  if (!mapped) return canonical
  const high = Number.parseInt(mapped[1]!, 16), low = Number.parseInt(mapped[2]!, 16)
  return `${high >>> 8}.${high & 0xff}.${low >>> 8}.${low & 0xff}`
}
/** Validate and normalize the trusted proxy list at startup. Empty means disabled. */
export function normalizeTrustedProxyIps(values: readonly string[] = []): ReadonlySet<string> {
  const result = new Set<string>()
  for (const raw of values) {
    const value = raw.trim()
    const normalized = value === '' ? null : normalizeIp(value)
    if (normalized === null) throw new Error(`Invalid DSH_SERVER_TRUSTED_PROXY_IPS entry "${raw}": expected a bare IPv4/IPv6 address (no port, CIDR or hostname).`)
    result.add(normalized)
  }
  return result
}
function readSingleForwardedFor(req: IncomingMessage): string {
  let value: string | undefined
  let count = 0
  const raw = req.rawHeaders
  for (let i = 0; i + 1 < raw.length; i += 2) {
    if (raw[i]!.toLowerCase() !== 'x-forwarded-for') continue
    count++
    value = raw[i + 1]
  }
  if (count !== 1) throw new ApiError('INVALID_MESSAGE')
  return value!
}
/**
 * Resolve the address used for rate limiting. X-Forwarded-For is honored only
 * when the socket peer is a configured trusted proxy; that peer must send one
 * header holding exactly one IP literal, otherwise the request is rejected.
 */
export function clientAddress(req: IncomingMessage, trustedProxyIps: ReadonlySet<string>): string {
  const peer = normalizeIp(req.socket.remoteAddress ?? '')
  if (peer === null) throw new ApiError('INVALID_MESSAGE')
  if (!trustedProxyIps.has(peer)) return peer
  const forwarded = normalizeIp(readSingleForwardedFor(req))
  if (forwarded === null) throw new ApiError('INVALID_MESSAGE')
  return forwarded
}
/**
 * Who the caller is, in the terms the login response needs. `externalId` is the
 * identity-provider subject when a provider is configured, and is what ties a
 * device to its owner; it is absent for the environment single account.
 */
interface LoginIdentity { account: string; displayName: string; isAdmin: boolean; externalId?: string }

/** Environment-variable single account: the original behaviour. */
function verifyWithConfig(config: Config, credentials: { email: string; password: string }): LoginIdentity {
  if (!equal(credentials.email.trim(), config.account) || !equal(credentials.password, config.password)) {
    throw new ApiError('AUTH_INVALID', 401)
  }
  return { account: config.account, displayName: config.account, isAdmin: false }
}

/**
 * Provider-backed login. Logto is the only source of truth here: the provider
 * has already applied its own suspension check, so this only translates the
 * outcome into the wire error codes the clients already understand.
 */
async function verifyWithProvider(
  auth: AuthProvider,
  email: string,
  password: string,
): Promise<LoginIdentity> {
  const outcome: AuthOutcome = await auth.authenticate(email, password)
  if (!outcome.ok) {
    if (outcome.reason === 'suspended') throw new ApiError('ACCOUNT_SUSPENDED', 403)
    // 'invalid' and 'ambiguous' deliberately collapse to one response: telling a
    // caller that an address is ambiguous would confirm it exists.
    if (outcome.reason === 'invalid' || outcome.reason === 'ambiguous') throw new ApiError('AUTH_INVALID', 401)
    throw new ApiError('AUTH_SERVICE_UNAVAILABLE', 503)
  }
  return { account: outcome.email, displayName: outcome.email, isAdmin: outcome.isAdmin, externalId: outcome.externalId }
}

export function createRemoteServer(config: Config) {
  if (!config.account.trim() || config.password.length < 12) throw new Error('DSH_SERVER_ACCOUNT and DSH_SERVER_PASSWORD (at least 12 characters) are required.')
  const url = new URL(config.publicUrl)
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('DSH_SERVER_PUBLIC_URL must be an HTTP(S) origin.')
  const trustedProxyIps = normalizeTrustedProxyIps(config.trustedProxyIps)
  const ice = config.ice ?? parseIceConfig({})
  const store = new Store(config.dataFile, config.account.trim(), config.password)
  const assets = readAssets()
  const sessions = new Map<string, number>()
  const limits = new Map<string, { count: number; until: number }>()
  /** Consecutive-failure lockout, independent of the fixed-window rate limits. */
  const lockout = new LoginLockout(config.lockout)
  /**
   * Fixed-window counter. Evicting expired buckets on every call keeps the map
   * bounded, and the ceiling is a safety net for a flood of distinct keys rather
   * than a fairness mechanism — fairness comes from keying per client and per
   * account rather than from the number of buckets.
   */
  function rate(key: string, max: number) {
    for (const [k, v] of limits) if (v.until < Date.now()) limits.delete(k)
    let entry = limits.get(key)
    if (!entry) { if (limits.size >= 16384) throw new ApiError('RATE_LIMITED', 429); entry = { count: 0, until: Date.now() + 60_000 }; limits.set(key, entry) }
    if (++entry.count > max) throw new ApiError('RATE_LIMITED', 429)
  }
  function token(req: IncomingMessage): string {
    const authorization = req.headers.authorization
    if (authorization) return authorization.startsWith('Bearer ') ? authorization.slice(7) : ''
    return /(?:^|;\s*)dsh_session=([A-Za-z0-9_-]+)/.exec(req.headers.cookie ?? '')?.[1] ?? ''
  }
  function accountAuth(req: IncomingMessage) {
    const key = hash(token(req))
    if ((sessions.get(key) ?? 0) <= Date.now()) { sessions.delete(key); throw new ApiError('ACCOUNT_AUTH_REQUIRED', 401) }
  }
  function deviceAuth(req: IncomingMessage) {
    if (!req.headers.authorization?.startsWith('Bearer ')) throw new ApiError('AUTH_REQUIRED', 401)
    return store.authenticate(req.headers.authorization.slice(7))
  }
  function cookie(value: string, age: number): string { return `dsh_session=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${url.protocol === 'https:' ? '; Secure' : ''}` }
  /**
   * Identity per web session, so `/auth/me` reflects who actually signed in
   * rather than echoing the environment-variable account. Keyed by the same
   * session digest as `sessions` and evicted with it.
   */
  const sessionIdentities = new Map<string, LoginIdentity>()
  const profileFor = (digest: string): LoginIdentity =>
    sessionIdentities.get(digest) ?? { account: store.account, displayName: store.account, isAdmin: false }
  const server = createServer({ requestTimeout: 15000, headersTimeout: 10000 }, (req, res) => {
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'no-referrer')
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
    void route(req, res).catch(error => {
      if (res.headersSent || res.destroyed) return
      const e = error instanceof ApiError ? error : error instanceof z.ZodError ? new ApiError('INVALID_MESSAGE') : new ApiError('INTERNAL_ERROR', 500)
      if (e.status === 429) res.setHeader('Retry-After', '60')
      json(res, e.status, { error: { code: e.code, message: e.code, requestId: randomUUID(), retryable: e.status === 429 || e.status >= 500 } })
    })
  })
  const logger = new Logger('server', config.logLevel ?? 'info')
  // Normalize at this boundary as well: a programmatic caller may pass NaN,
  // Infinity or a negative value straight through the Config object.
  const timing = normalizeGatewayOptions({
    helloTimeoutMs: config.helloTimeoutMs,
    heartbeatIntervalMs: config.heartbeatIntervalMs,
    heartbeatDisconnectMs: config.heartbeatDisconnectMs,
    forceTerminateGraceMs: config.forceTerminateGraceMs,
  })
  const gateway = new Gateway(server, store, url.origin, {
    ...timing,
    logLevel: config.logLevel,
    logger: logger.child('gateway'),
    turnEnabled: ice.turnUrls.length > 0,
  })
  function descriptor(d: ReturnType<Store['get']>) {
    return { ...d.descriptor, membershipId: store.accountId, online: gateway.peers.has(d.descriptor.deviceId), lastSeenAt: d.lastSeenAt }
  }
  async function route(req: IncomingMessage, res: ServerResponse) {
    const requestUrl = new URL(req.url ?? '/', url)
    const path = requestUrl.pathname
    const method = req.method
    if (req.headers.origin && req.headers.origin !== url.origin) throw new ApiError('AUTH_INVALID', 403)
    if (req.headers['sec-fetch-site'] === 'cross-site') throw new ApiError('AUTH_INVALID', 403)
    const staticAsset = path.startsWith('/assets/') || ['/icon.png', '/brand-whale.webp', '/landing-atmosphere.webp'].includes(path)
    // SPA fallback: any GET that is not API / WebSocket / health-check returns index.html.
    // Without this, refreshing a client route such as /app/remote hits the unknown-method branch and yields METHOD_NOT_FOUND.
    const spaRoute = method === 'GET' && !staticAsset && !path.startsWith('/api/') && !path.startsWith('/ws/') && !['/health', '/healthz', '/ready'].includes(path)
    if (method === 'GET' && (spaRoute || staticAsset)) {
      const name = staticAsset ? path.slice(1) : 'index.html'
      const asset = assets.get(name)
      if (!asset) throw new ApiError('METHOD_NOT_FOUND', 404)
      const contentType = name.endsWith('.js') ? 'text/javascript; charset=utf-8' : name.endsWith('.css') ? 'text/css; charset=utf-8' : name.endsWith('.png') ? 'image/png' : name.endsWith('.webp') ? 'image/webp' : 'text/html; charset=utf-8'
      if (!staticAsset) res.setHeader('Cache-Control', 'no-cache')
      res.setHeader('Content-Type', contentType)
      res.end(asset); return
    }
    if (method === 'GET' && (path === '/health' || path === '/healthz' || path === '/ready')) { json(res, 200, { status: 'ok' }); return }
    const client = clientAddress(req, trustedProxyIps)
    rate(`api:${client}`, 240)
    if (method === 'POST' && path === '/api/v1/hooks/logto') {
      // Webhooks bypass the account-session and device checks: they authenticate
      // by signature. They are rate limited like any other request so a flood
      // cannot hammer the revocation path.
      const signingKey = config.webhookSigningKey
      if (!signingKey) throw new ApiError('METHOD_NOT_FOUND', 404)
      const raw = await rawBody(req)
      const signature = req.headers['logto-signature-sha-256']
      if (!verifySignature(signingKey, raw, typeof signature === 'string' ? signature : undefined)) {
        // 401 without detail: a probing caller learns nothing about the key.
        throw new ApiError('AUTH_INVALID', 401)
      }
      let payload: WebhookPayload
      try {
        payload = JSON.parse(raw.toString('utf8')) as WebhookPayload
      } catch {
        // The signature already proved this came from Logto, so it is not an
        // attack; a malformed body is a bug we cannot fix by asking for a retry.
        // Ack it so Logto does not re-deliver the same broken payload forever.
        json(res, 200, { status: 'ok', ignored: 'malformed' }); return
      }
      const outcome = interpret(payload)
      if (outcome.handled && outcome.revoke && outcome.userId !== null) {
        store.revokeAccountSessions(outcome.userId)
      }
      // Always 200 once the signature is good: a non-2xx makes Logto retry, and a
      // malformed-but-authentic event is not something retrying will fix.
      json(res, 200, { status: 'ok' }); return
    }
    if (method === 'POST' && path === '/api/v1/auth/login') {
      rate(`login:${client}`, 20)
      const credentials = loginSchema.parse(await body(req))
      // A per-account login budget on top of the per-address one. Without it an
      // attacker with many addresses gets 20 attempts per address against one
      // account; with it, the account itself is also capped. The key is derived
      // from the submitted address rather than read from storage, so a rejected
      // attempt does not reveal whether the account exists.
      //
      // Deliberately looser than the per-address budget (20/min): the address
      // limit is what stops a single source, and this one only has to stop a
      // source rotating addresses. Setting it lower would make the address limit
      // unreachable and change the documented behaviour.
      rate(`login-account:${hash(credentials.email.trim().toLowerCase())}`, 60)
      // Lockout is a separate signal from the fixed-window rate limits: those
      // forgive a patient attacker every minute, this one accumulates. Keyed by
      // the submitted address so a lockout never reveals whether it exists.
      const lockKey = hash(credentials.email.trim().toLowerCase())
      const locked = lockout.check(lockKey)
      if (locked.locked) {
        res.setHeader('Retry-After', String(Math.ceil(locked.retryAfterMs / 1000)))
        throw new ApiError('ACCOUNT_LOCKED', 429)
      }
      // With a provider configured, Logto decides whether the credentials are
      // good and whether the account may sign in. Without one, fall back to the
      // environment-variable single account so existing deployments are unchanged.
      let identity: LoginIdentity
      try {
        identity = config.auth
          ? await verifyWithProvider(config.auth, credentials.email, credentials.password)
          : verifyWithConfig(config, credentials)
      } catch (error) {
        // Only a credential rejection counts toward the streak. A 503 from an
        // unreachable provider must not lock users out of their own accounts.
        if (error instanceof ApiError && error.status === 401) {
          const after = lockout.recordFailure(lockKey)
          if (after.locked) {
            res.setHeader('Retry-After', String(Math.ceil(after.retryAfterMs / 1000)))
            throw new ApiError('ACCOUNT_LOCKED', 429)
          }
        }
        throw error
      }
      lockout.recordSuccess(lockKey)
      // Anchor the session to a durable account row. With a provider this is the
      // Logto subject; without one it is the environment account. Devices are
      // owned through this id, so the login and the device routes agree on who
      // the caller is even after an address changes.
      if (identity.externalId !== undefined) {
        store.upsertAccount({ externalId: identity.externalId, email: identity.account, isAdmin: identity.isAdmin })
      }
      for (const [key, expires] of sessions) if (expires <= Date.now()) sessions.delete(key)
      if (sessions.size >= 256) throw new ApiError('RATE_LIMITED', 429)
      const value = secret(), expiresAt = Date.now() + 8 * 3600_000
      // Evict the identity alongside the session it belongs to.
      for (const [key, expires] of sessions) {
        if (expires <= Date.now()) { sessions.delete(key); sessionIdentities.delete(key) }
      }
      const digest = hash(value)
      sessions.set(digest, expiresAt)
      sessionIdentities.set(digest, identity)
      res.setHeader('Set-Cookie', cookie(value, 8 * 3600))
      // Response shape is unchanged from the single-account version: the shipped
      // clients parse exactly these fields.
      json(res, 200, {
        account: identity.account,
        profile: { displayName: identity.displayName },
        isAdmin: identity.isAdmin,
        token: value,
        expiresAt,
      }); return
    }
    if (method === 'GET' && path === '/api/v1/auth/me') {
      accountAuth(req)
      const identity = profileFor(hash(token(req)))
      json(res, 200, {
        account: identity.account,
        profile: { displayName: identity.displayName },
        isAdmin: identity.isAdmin,
      }); return
    }
    if (method === 'POST' && path === '/api/v1/auth/logout') {
      const digest = hash(token(req))
      sessions.delete(digest); sessionIdentities.delete(digest)
      res.setHeader('Set-Cookie', cookie('', 0)); json(res, 200, { status: 'ok' }); return
    }
    if (method === 'GET' && path === '/api/v1/account/devices') {
      accountAuth(req); json(res, 200, { items: store.list().map(descriptor), serverUrl: url.origin, transport: 'webrtc' }); return
    }
    if (method === 'POST' && (path === '/api/v1/devices/register' || path === '/api/v1/devices/register-owned-role')) {
      const source = path.endsWith('register-owned-role') ? deviceAuth(req) : undefined
      if (!source) accountAuth(req)
      const { device } = deviceRegistrationRequestSchema.parse(await body(req))
      if (source && (source.descriptor.deviceId === device.deviceId || source.descriptor.role === device.role)) throw new ApiError('INVALID_MESSAGE', 409)
      json(res, 200, store.register(device)); return
    }
    if (method === 'POST' && path === '/api/v1/auth/refresh') {
      const data = deviceRefreshRequestSchema.parse(await body(req))
      json(res, 200, store.refresh(data.deviceId, data.refreshToken)); return
    }
    if (method === 'DELETE' && path === '/api/v1/devices/self') {
      store.revoke(deviceAuth(req).descriptor.deviceId); json(res, 200, { status: 'revoked' }); return
    }
    if (method === 'GET' && path === '/api/v1/me') { json(res, 200, descriptor(deviceAuth(req))); return }
    if (method === 'GET' && path === '/api/v1/turn/credentials') {
      const source = deviceAuth(req)
      const connectionId = requestUrl.searchParams.get('connection_id') ?? ''
      if (!connectionId || connectionId.length > 128) throw new ApiError('INVALID_MESSAGE')
      if (!gateway.authorizeIce(source.descriptor.deviceId, connectionId)) throw new ApiError('CONNECTION_NOT_FOUND', 404)
      json(res, 200, { iceServers: buildIceServers(ice, source.descriptor.deviceId) }); return
    }
    if (method === 'GET' && path === '/api/v1/devices') {
      const source = deviceAuth(req)
      if (source.descriptor.role !== 'client') throw new ApiError('MEMBERSHIP_REQUIRED', 403)
      const items = store.listFor(source.accountId)
        .filter(d => d.descriptor.role === 'host')
        .map(d => {
          const { identityKey: _key, ...item } = descriptor(d)
          return item
        })
      json(res, 200, { items, nextCursor: null }); return
    }
    const renameMatch = /^\/api\/v1\/devices\/([^/]+)\/name$/.exec(path)
    if (method === 'POST' && renameMatch) {
      accountAuth(req)
      const { name } = z.object({ name: z.string().trim().min(1).max(80) }).parse(await body(req))
      store.rename(store.getOwned(renameMatch[1]!, store.accountId).descriptor.deviceId, name)
      json(res, 200, descriptor(store.get(renameMatch[1]!))); return
    }
    const match = /^\/api\/v1\/devices\/([^/]+)(\/presence)?$/.exec(path)
    if (method === 'GET' && match) {
      const source = deviceAuth(req), target = store.getOwned(match[1]!, source.accountId)
      if (source.descriptor.role === target.descriptor.role) throw new ApiError('MEMBERSHIP_REQUIRED', 403)
      const d = descriptor(target)
      json(res, 200, match[2] ? { deviceId: d.deviceId, online: d.online, lastSeenAt: d.lastSeenAt } : d); return
    }
    throw new ApiError('METHOD_NOT_FOUND', 404)
  }
  return { server, store, gateway, logger, close: async () => { gateway.close(); server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())) } }
}
function json(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(value))
}
