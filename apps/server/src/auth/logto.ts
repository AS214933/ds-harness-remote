/**
 * Logto as the identity source for this Server.
 *
 * The shipped clients only know `POST /api/v1/auth/login { email, password }`,
 * so there is no browser, redirect or callback to hand to Logto's OIDC flow.
 * This adapter therefore uses the one Management API endpoint whose semantics
 * are "does this string match the stored hash" — `POST /users/{id}/password/verify`
 * — and treats it as the authentication primitive.
 *
 * Two consequences drive the code below, both verified against a live Logto:
 *
 * 1. `password/verify` is a pure hash comparison. It does not look at
 *    `isSuspended`, MFA factors or password expiry, and it answers 204 for a
 *    suspended user. Account state is this adapter's responsibility, not Logto's.
 * 2. It deliberately ignores MFA. That is what lets a user who enabled 2FA in
 *    Logto still sign in from a client that cannot perform a second factor.
 *
 * Everything Logto-specific lives in this file: upgrading Logto means changing
 * this file and nothing else.
 */
import { timingSafeEqual } from 'node:crypto'

export type AuthOutcome =
  | { ok: true; externalId: string; email: string; isAdmin: boolean }
  | { ok: false; reason: 'invalid' | 'suspended' | 'ambiguous' | 'unavailable' }

/**
 * What the Server needs from an identity provider. Keeping this free of Logto
 * types means the login route never learns which provider is behind it.
 */
export interface AuthProvider {
  authenticate(email: string, password: string): Promise<AuthOutcome>
}

export interface LogtoConfig {
  /** Base URL of the tenant that owns your users, e.g. https://logto.example.com */
  endpoint: string
  clientId: string
  clientSecret: string
  /** Resource indicator. Self-hosted/OSS is always https://default.logto.app/api */
  resource: string
  /** Logto role name that grants `isAdmin` here. */
  adminRole: string
}

interface LogtoUser {
  id: string
  primaryEmail: string | null
  isSuspended?: boolean
}

/** Logto is unreachable, misconfigured or returned an unexpected status. */
class LogtoUnavailable extends Error {}

/**
 * Equalise the cost of every failure path.
 *
 * Measured against Logto 1.46 the three paths differ a lot: an unknown address
 * answers in ~70ms because it skips password hashing, a wrong password costs the
 * argon2 verify, and a correct password costs verify plus the admin-role lookup.
 * Any of those differences is an oracle for "does this address exist".
 *
 * Rather than guess a per-path delay, every failure is padded at a single exit
 * point up to a fixed budget. Successful logins are left alone: they are the
 * only path a legitimate user takes, and their cost does not reveal anything an
 * attacker does not already know (they had the password).
 */
const FAILURE_BUDGET_MS = 700

/** Pad a failure so its total wall time matches the budget. Never sleeps less than jitter. */
async function padFailure(startedAt: number): Promise<void> {
  const elapsed = Date.now() - startedAt
  // Spread the remainder so the padding itself does not look like a fixed step.
  const jitter = Math.floor(Math.random() * 60)
  const wait = Math.max(0, FAILURE_BUDGET_MS - elapsed) + jitter
  await new Promise(resolve => setTimeout(resolve, wait))
}

/** Constant-time string compare that does not leak length through early exit. */
function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left), b = Buffer.from(right)
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

export class LogtoAuthProvider implements AuthProvider {
  private cached: { token: string; expiresAt: number } | null = null
  private inflight: Promise<string> | null = null

  constructor(private readonly config: LogtoConfig) {
    if (!config.endpoint) throw new Error('LOGTO_ENDPOINT is required')
    if (!config.clientId || !config.clientSecret) throw new Error('LOGTO_M2M_CLIENT_ID and LOGTO_M2M_CLIENT_SECRET are required')
    if (!config.resource) throw new Error('LOGTO_API_RESOURCE is required')
  }

  /**
   * M2M access token. Single-flight so a burst of logins produces one token
   * request, and refreshed 60s early so an in-flight call never races expiry.
   */
  private async token(): Promise<string> {
    if (this.cached && this.cached.expiresAt - 60_000 > Date.now()) return this.cached.token
    if (this.inflight) return this.inflight
    this.inflight = (async () => {
      const basic = Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString('base64')
      const response = await fetch(`${this.config.endpoint}/oidc/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${basic}`,
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          resource: this.config.resource,
          scope: 'all',
        }),
        signal: AbortSignal.timeout(5000),
      })
      if (!response.ok) throw new LogtoUnavailable(`token ${response.status}`)
      const body = await response.json() as { access_token?: unknown; expires_in?: unknown }
      if (typeof body.access_token !== 'string' || typeof body.expires_in !== 'number') {
        throw new LogtoUnavailable('token response shape')
      }
      this.cached = { token: body.access_token, expiresAt: Date.now() + body.expires_in * 1000 }
      return body.access_token
    })().finally(() => { this.inflight = null })
    return this.inflight
  }

  /** Management API call. A rejected token is dropped and re-fetched once. */
  private async management(path: string, init: RequestInit = {}, retry = true): Promise<Response> {
    let token: string
    try { token = await this.token() } catch { throw new LogtoUnavailable('token') }
    const response = await fetch(`${this.config.endpoint}${path}`, {
      ...init,
      headers: { ...init.headers, Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(8000),
    })
    if (response.status === 401 && retry) {
      this.cached = null
      return this.management(path, init, false)
    }
    return response
  }

  /** Exact email lookup. `mode` must be `exact`: the default is fuzzy and treats %/_ as wildcards. */
  private async findByEmail(email: string): Promise<LogtoUser | 'none' | 'ambiguous'> {
    const url = new URL(`${this.config.endpoint}/api/users`)
    url.searchParams.set('search.primaryEmail', email)
    url.searchParams.set('mode.primaryEmail', 'exact')
    url.searchParams.set('page_size', '10')
    let response: Response
    try { response = await this.management(`${url.pathname}${url.search}`) } catch { throw new LogtoUnavailable('users') }
    if (!response.ok) throw new LogtoUnavailable(`users ${response.status}`)
    const body = await response.json() as unknown
    if (!Array.isArray(body)) throw new LogtoUnavailable('users shape')
    // Re-filter locally instead of trusting the server filter: a fuzzy mode or a
    // future default change must not silently match a different user.
    const matches = (body as LogtoUser[]).filter(user =>
      typeof user?.primaryEmail === 'string' && safeEqual(user.primaryEmail.toLowerCase(), email))
    if (matches.length === 0) return 'none'
    if (matches.length > 1) return 'ambiguous'
    return matches[0]!
  }

  private async isAdmin(userId: string): Promise<boolean> {
    try {
      const response = await this.management(`/api/users/${userId}/roles`)
      if (!response.ok) return false
      const body = await response.json() as unknown
      if (!Array.isArray(body)) return false
      return body.some(role => typeof role?.name === 'string' && role.name === this.config.adminRole)
    } catch {
      // Never grant admin on an infrastructure error.
      return false
    }
  }

  async authenticate(email: string, password: string): Promise<AuthOutcome> {
    const startedAt = Date.now()
    const normalized = email.trim().toLowerCase()
    // Empty input costs nothing to produce and runs before any I/O, so it cannot
    // be distinguished from a rejected login by timing anyway.
    if (!normalized || !password) return { ok: false, reason: 'invalid' }

    let user: LogtoUser | 'none' | 'ambiguous'
    try { user = await this.findByEmail(normalized) } catch { return { ok: false, reason: 'unavailable' } }
    if (user === 'none') { await padFailure(startedAt); return { ok: false, reason: 'invalid' } }
    if (user === 'ambiguous') { await padFailure(startedAt); return { ok: false, reason: 'ambiguous' } }

    let verified: Response
    try {
      verified = await this.management(`/api/users/${user.id}/password/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      })
    } catch { return { ok: false, reason: 'unavailable' } }

    // 422 = wrong password (also returned for a user with no password set),
    // 404 = the user was deleted between the lookup and this call.
    if (verified.status === 422 || verified.status === 404) { await padFailure(startedAt); return { ok: false, reason: 'invalid' } }
    if (verified.status !== 204) return { ok: false, reason: 'unavailable' }

    // Only after the password is known good do we reveal that the account is
    // suspended. Checking first would let an attacker distinguish "no such
    // account" from "exists but suspended" by the status code alone. Suspension
    // is padded too: it is a failure an attacker can observe.
    if (user.isSuspended === true) { await padFailure(startedAt); return { ok: false, reason: 'suspended' } }

    const isAdmin = await this.isAdmin(user.id)
    return { ok: true, externalId: user.id, email: normalized, isAdmin }
  }
}

export function createLogtoAuth(env: NodeJS.ProcessEnv): LogtoAuthProvider {
  return new LogtoAuthProvider({
    endpoint: env.LOGTO_ENDPOINT ?? '',
    clientId: env.LOGTO_M2M_CLIENT_ID ?? '',
    clientSecret: env.LOGTO_M2M_CLIENT_SECRET ?? '',
    // Self-hosted Logto always uses this literal; Cloud would use
    // https://<tenant-id>.logto.app/api instead.
    resource: env.LOGTO_API_RESOURCE ?? 'https://default.logto.app/api',
    adminRole: env.LOGTO_ADMIN_ROLE ?? 'admin',
  })
}
