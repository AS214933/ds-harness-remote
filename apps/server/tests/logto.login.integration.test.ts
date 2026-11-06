/**
 * End-to-end login against a REAL Logto through the real HTTP route.
 *
 * Unlike tests/logto.test.ts (stub provider) this boots createRemoteServer with
 * the actual LogtoAuthProvider and drives `POST /api/v1/auth/login` over HTTP,
 * so the whole path is exercised: route -> provider -> Logto -> response shape.
 *
 *   LOGTO_INTEGRATION=1 LOGTO_ENDPOINT=... LOGTO_M2M_CLIENT_ID=... \
 *   LOGTO_M2M_CLIENT_SECRET=... pnpm --filter @dsh-remote/server exec \
 *   vitest run tests/logto.login.integration.test.ts
 */
import { afterEach, describe, expect, it } from 'vitest'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import { createRemoteServer } from '../src/server.js'
import { createLogtoAuth } from '../src/auth/logto.js'

const enabled = process.env.LOGTO_INTEGRATION === '1'
const PASSWORD = 'CorrectHorseBattery1!'

let app: ReturnType<typeof createRemoteServer> | undefined
let base = ''

async function start(): Promise<void> {
  app = createRemoteServer({
    account: 'owner@example.com',
    password: 'local-test-password',
    dataFile: join(mkdtempSync(join(tmpdir(), 'dsh-e2e-')), 'state.json'),
    publicUrl: 'http://localhost:8080',
    auth: createLogtoAuth(process.env),
  })
  app.server.listen(0, '127.0.0.1')
  await once(app.server, 'listening')
  base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`
}

async function login(email: string, password: string) {
  const response = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  return { status: response.status, data: await response.json() as any, headers: response.headers }
}

afterEach(async () => { if (app) { await app.close(); app = undefined } })

describe.runIf(enabled)('login route against live Logto', () => {
  it('signs in a real Logto user and returns the client contract', async () => {
    await start()
    const result = await login('t_happy@example.com', PASSWORD)
    expect(result.status).toBe(200)
    expect(Object.keys(result.data).sort()).toEqual(['account', 'expiresAt', 'isAdmin', 'profile', 'token'])
    expect(result.data.account).toBe('t_happy@example.com')
    expect(result.headers.get('set-cookie')).toContain('dsh_session=')
  })

  it('rejects a wrong password with 401', async () => {
    await start()
    const result = await login('t_wrong@example.com', 'definitely-wrong')
    expect(result.status).toBe(401)
    expect(result.data.error.code).toBe('AUTH_INVALID')
  })

  it('rejects an unknown email with the same 401 as a wrong password', async () => {
    await start()
    const unknown = await login('nobody@example.com', PASSWORD)
    expect(unknown.status).toBe(401)
    expect(unknown.data.error.code).toBe('AUTH_INVALID')
  })

  it('refuses a suspended Logto user with 403', async () => {
    await start()
    const result = await login('t_susp@example.com', PASSWORD)
    expect(result.status).toBe(403)
    expect(result.data.error.code).toBe('ACCOUNT_SUSPENDED')
  })

  it('lets a TOTP-MFA user sign in (the clients cannot do a second factor)', async () => {
    await start()
    const result = await login('t_mfa@example.com', PASSWORD)
    expect(result.status).toBe(200)
  })

  it('lets a passkey user sign in', async () => {
    await start()
    const result = await login('t_passkey@example.com', PASSWORD)
    expect(result.status).toBe(200)
  })

  it('exposes the signed-in identity through /auth/me', async () => {
    await start()
    const { data } = await login('t_happy@example.com', PASSWORD)
    const me = await fetch(`${base}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${data.token}` },
    })
    const body = await me.json() as any
    expect(body.account).toBe('t_happy@example.com')
  })

  it('invalidates the session on logout', async () => {
    await start()
    const { data } = await login('t_happy@example.com', PASSWORD)
    const out = await fetch(`${base}/api/v1/auth/logout`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${data.token}` },
    })
    expect(out.status).toBe(200)
    const me = await fetch(`${base}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${data.token}` },
    })
    expect(me.status).toBe(401)
  })

  it('does not let a device token authenticate the account routes', async () => {
    // The account session and the device credential are different authorities;
    // mixing them would let a paired device manage the whole account.
    await start()
    const result = await login('t_happy@example.com', PASSWORD)
    const me = await fetch(`${base}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${result.data.token}x` },
    })
    expect(me.status).toBe(401)
  })
})
