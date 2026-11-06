/**
 * Unit tests for the Logto adapter's protocol handling.
 *
 * The live integration test (tests/logto.integration.test.ts) proves the adapter
 * matches real Logto behaviour. This file proves the request SHAPE, which a live
 * test cannot check: that we ask for `mode.primaryEmail=exact`, send the M2M
 * body Logto expects, and map each status to the right outcome. Those are the
 * details that break silently against a future Logto release.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { LogtoAuthProvider } from '../src/auth/logto.js'
import type { LogtoConfig } from '../src/auth/logto.js'

const config: LogtoConfig = {
  endpoint: 'https://logto.test',
  clientId: 'client-id',
  clientSecret: 'client-secret',
  resource: 'https://default.logto.app/api',
  adminRole: 'admin',
}

interface Captured { url: string; init: RequestInit }

/** Minimal Logto stub: one user, configurable verify status. */
function stub(options: {
  users?: unknown[]
  verifyStatus?: number
  roles?: unknown[]
  tokenStatus?: number
  userStatus?: number
} = {}) {
  const calls: Captured[] = []
  const users = options.users ?? [{ id: 'user1', primaryEmail: 'a@b.com', isSuspended: false }]
  const fetchStub = vi.fn(async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = String(input instanceof Request ? input.url : input)
    calls.push({ url, init })
    const respond = (status: number, body?: unknown): Response =>
      new Response(body === undefined ? null : JSON.stringify(body), {
        status, headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      })
    if (url.endsWith('/oidc/token')) {
      return respond(options.tokenStatus ?? 200, { access_token: 'm2m-token', expires_in: 3600 })
    }
    if (url.includes('/password/verify')) return respond(options.verifyStatus ?? 204)
    if (url.includes('/roles')) return respond(200, options.roles ?? [])
    if (url.includes('/api/users/')) return respond(options.userStatus ?? 200, users[0])
    if (url.includes('/api/users')) return respond(200, users)
    return respond(404, { code: 'not_found' })
  })
  vi.stubGlobal('fetch', fetchStub)
  return { calls }
}

afterEach(() => { vi.unstubAllGlobals() })

describe('LogtoAuthProvider request shape', () => {
  it('requests an exact email match, never the fuzzy default', async () => {
    const { calls } = stub()
    await new LogtoAuthProvider(config).authenticate('a@b.com', 'pw')
    const search = calls.find(c => c.url.includes('/api/users?'))
    expect(search).toBeDefined()
    const params = new URL(search!.url).searchParams
    // Default mode is `like`, which treats % and _ as wildcards and can match a
    // different user. This assertion is the guard against losing that line.
    expect(params.get('mode.primaryEmail')).toBe('exact')
    expect(params.get('search.primaryEmail')).toBe('a@b.com')
  })

  it('exchanges M2M credentials as form-encoded client_credentials', async () => {
    const { calls } = stub()
    await new LogtoAuthProvider(config).authenticate('a@b.com', 'pw')
    const token = calls.find(c => c.url.endsWith('/oidc/token'))!
    expect(token.init.method).toBe('POST')
    expect(String((token.init.headers as Record<string, string>).Authorization))
      .toBe(`Basic ${Buffer.from('client-id:client-secret').toString('base64')}`)
    const body = new URLSearchParams(String(token.init.body))
    expect(body.get('grant_type')).toBe('client_credentials')
    expect(body.get('resource')).toBe('https://default.logto.app/api')
    expect(body.get('scope')).toBe('all')
  })

  it('posts only the password to the verify endpoint', async () => {
    const { calls } = stub()
    await new LogtoAuthProvider(config).authenticate('a@b.com', 's3cret')
    const verify = calls.find(c => c.url.includes('/password/verify'))!
    expect(verify.init.method).toBe('POST')
    expect(JSON.parse(String(verify.init.body))).toEqual({ password: 's3cret' })
    expect((verify.init.headers as Record<string, string>).Authorization).toBe('Bearer m2m-token')
  })

  it('caches the M2M token across calls', async () => {
    const { calls } = stub()
    const provider = new LogtoAuthProvider(config)
    await provider.authenticate('a@b.com', 'pw')
    await provider.authenticate('a@b.com', 'pw')
    expect(calls.filter(c => c.url.endsWith('/oidc/token'))).toHaveLength(1)
  })

  it('refetches the token once when the API answers 401', async () => {
    let first = true
    const fetchStub = vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      if (url.endsWith('/oidc/token')) {
        return new Response(JSON.stringify({ access_token: first ? 'stale' : 'fresh', expires_in: 3600 }),
          { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (String((input as Request).headers ?? '') === '') { /* noop */ }
      if (url.includes('/password/verify')) return new Response(null, { status: 204 })
      if (url.includes('/roles')) return new Response('[]', { status: 200 })
      if (url.includes('/api/users')) {
        if (first) { first = false; return new Response('{}', { status: 401 }) }
        return new Response(JSON.stringify([{ id: 'user1', primaryEmail: 'a@b.com' }]),
          { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(null, { status: 404 })
    })
    vi.stubGlobal('fetch', fetchStub)
    const result = await new LogtoAuthProvider(config).authenticate('a@b.com', 'pw')
    expect(result.ok).toBe(true)
  })
})

describe('LogtoAuthProvider outcome mapping', () => {
  it('maps 422 from verify to invalid', async () => {
    stub({ verifyStatus: 422 })
    expect(await new LogtoAuthProvider(config).authenticate('a@b.com', 'pw'))
      .toEqual({ ok: false, reason: 'invalid' })
  })

  it('maps 404 from verify to invalid (user deleted mid-flight)', async () => {
    stub({ verifyStatus: 404 })
    expect(await new LogtoAuthProvider(config).authenticate('a@b.com', 'pw'))
      .toEqual({ ok: false, reason: 'invalid' })
  })

  it('maps an unexpected verify status to unavailable', async () => {
    stub({ verifyStatus: 500 })
    expect(await new LogtoAuthProvider(config).authenticate('a@b.com', 'pw'))
      .toEqual({ ok: false, reason: 'unavailable' })
  })

  it('reports suspended only after the password is verified', async () => {
    stub({ users: [{ id: 'user1', primaryEmail: 'a@b.com', isSuspended: true }] })
    expect(await new LogtoAuthProvider(config).authenticate('a@b.com', 'pw'))
      .toEqual({ ok: false, reason: 'suspended' })
  })

  it('hides suspension when the password is wrong', async () => {
    stub({ users: [{ id: 'user1', primaryEmail: 'a@b.com', isSuspended: true }], verifyStatus: 422 })
    expect(await new LogtoAuthProvider(config).authenticate('a@b.com', 'pw'))
      .toEqual({ ok: false, reason: 'invalid' })
  })

  it('fails closed to unavailable when the token request fails', async () => {
    stub({ tokenStatus: 400 })
    expect(await new LogtoAuthProvider(config).authenticate('a@b.com', 'pw'))
      .toEqual({ ok: false, reason: 'unavailable' })
  })

  it('treats duplicate exact matches as ambiguous rather than picking one', async () => {
    stub({ users: [
      { id: 'user1', primaryEmail: 'a@b.com' },
      { id: 'user2', primaryEmail: 'A@B.com' },
    ] })
    expect(await new LogtoAuthProvider(config).authenticate('a@b.com', 'pw'))
      .toEqual({ ok: false, reason: 'ambiguous' })
  })

  it('rejects a local mis-match even if the server filter returned it', async () => {
    // Defends against a fuzzy server response: the local compare must drop it.
    stub({ users: [{ id: 'user1', primaryEmail: 'someone-else@b.com' }] })
    expect(await new LogtoAuthProvider(config).authenticate('a@b.com', 'pw'))
      .toEqual({ ok: false, reason: 'invalid' })
  })

  it('grants isAdmin only when the configured role is present', async () => {
    stub({ roles: [{ name: 'admin' }] })
    const granted = await new LogtoAuthProvider(config).authenticate('a@b.com', 'pw')
    expect(granted.ok && granted.isAdmin).toBe(true)

    stub({ roles: [{ name: 'viewer' }] })
    const denied = await new LogtoAuthProvider(config).authenticate('a@b.com', 'pw')
    expect(denied.ok && denied.isAdmin).toBe(false)
  })

  it('never grants admin when the role lookup fails', async () => {
    const fetchStub = vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      if (url.endsWith('/oidc/token')) {
        return new Response(JSON.stringify({ access_token: 't', expires_in: 3600 }),
          { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      if (url.includes('/password/verify')) return new Response(null, { status: 204 })
      if (url.includes('/roles')) throw new Error('network down')
      if (url.includes('/api/users')) {
        return new Response(JSON.stringify([{ id: 'user1', primaryEmail: 'a@b.com' }]),
          { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(null, { status: 404 })
    })
    vi.stubGlobal('fetch', fetchStub)
    const result = await new LogtoAuthProvider(config).authenticate('a@b.com', 'pw')
    expect(result.ok && result.isAdmin).toBe(false)
  })
})

describe('LogtoAuthProvider construction', () => {
  it('refuses to start without the required configuration', () => {
    const partial = { ...config, clientSecret: '' }
    expect(() => new LogtoAuthProvider(partial)).toThrow(/LOGTO_M2M_CLIENT_SECRET/)
    expect(() => new LogtoAuthProvider({ ...config, endpoint: '' })).toThrow(/LOGTO_ENDPOINT/)
  })
})
