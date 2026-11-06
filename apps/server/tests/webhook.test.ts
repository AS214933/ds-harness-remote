/**
 * Webhook receiver tests.
 *
 * The signature is the only thing authenticating these requests — they bypass
 * session and device auth — so both the accept and the reject paths are pinned
 * here, along with the rule that a reactivation must NOT revoke anything.
 */
import { afterEach, describe, expect, it } from 'vitest'
import { createHmac } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import { randomUUID } from 'node:crypto'
import { verifySignature, interpret } from '../src/auth/webhook.js'
import { createRemoteServer } from '../src/server.js'
import { Store } from '../src/store.js'
import { generateKeyPair } from '../../../packages/crypto/src/index.js'

const KEY = 'webhook-signing-key-for-tests'
let app: ReturnType<typeof createRemoteServer> | undefined
let dir = ''

afterEach(async () => {
  if (app) { await app.close(); app = undefined }
  if (dir) { rmSync(dir, { recursive: true, force: true }); dir = '' }
})

function sign(body: string, key = KEY): string {
  return createHmac('sha256', key).update(Buffer.from(body)).digest('hex')
}

async function boot(options: { key?: string | undefined } = { key: KEY }) {
  dir = mkdtempSync(join(tmpdir(), 'dsh-hook-'))
  // Build the config without the key at all when disabled, so the route really
  // is unregistered rather than keyed to undefined.
  const config: Record<string, unknown> = {
    account: 'owner@example.com',
    password: 'local-test-password',
    dataFile: join(dir, 'state.json'),
    publicUrl: 'http://localhost:8080',
  }
  if (options.key !== undefined) config.webhookSigningKey = options.key
  app = createRemoteServer(config as never)
  app.server.listen(0, '127.0.0.1')
  await once(app.server, 'listening')
  const base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`
  const post = (body: string, signature?: string) => fetch(`${base}/api/v1/hooks/logto`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(signature === undefined ? {} : { 'logto-signature-sha-256': signature }),
    },
    body,
  })
  return { app, base, post }
}

describe('webhook signature', () => {
  it('accepts a correct HMAC-SHA256 over the raw body', () => {
    const body = Buffer.from('{"a":1}')
    expect(verifySignature(KEY, body, sign('{"a":1}'))).toBe(true)
  })

  it('rejects a wrong signature, a missing one, and whitespace tampering', () => {
    const body = Buffer.from('{"a":1}')
    expect(verifySignature(KEY, body, sign('{"a":1}', 'other-key'))).toBe(false)
    expect(verifySignature(KEY, body, undefined)).toBe(false)
    // Re-serialising parsed JSON changes the bytes; the signature must notice.
    expect(verifySignature(KEY, Buffer.from('{"a": 1}'), sign('{"a":1}'))).toBe(false)
  })

  it('rejects everything when no key is configured', () => {
    expect(verifySignature('', Buffer.from('{}'), sign('{}', ''))).toBe(false)
  })

  it('is case- and whitespace-insensitive on the header, as sent by proxies', () => {
    const body = Buffer.from('{"a":1}')
    expect(verifySignature(KEY, body, `  ${sign('{"a":1}').toUpperCase()}  `)).toBe(true)
  })
})

describe('webhook interpretation', () => {
  it('revokes on user deletion', () => {
    expect(interpret({ event: 'User.Deleted', data: { userId: 'u1' } }))
      .toEqual({ handled: true, event: 'User.Deleted', userId: 'u1', revoke: true })
  })

  it('revokes only when the suspension event ends suspended', () => {
    expect(interpret({ event: 'User.SuspensionStatus.Updated', data: { userId: 'u1', isSuspended: true } }))
      .toMatchObject({ revoke: true })
    // Reactivation must not log the user out of everything.
    expect(interpret({ event: 'User.SuspensionStatus.Updated', data: { userId: 'u1', isSuspended: false } }))
      .toMatchObject({ revoke: false })
  })

  it('fails closed when a suspension event omits the resulting state', () => {
    // Revoking a reactivated user is a nuisance; leaving a suspended one active
    // is a security failure, so an unknown shape revokes.
    expect(interpret({ event: 'User.SuspensionStatus.Updated', data: { userId: 'u1' } }))
      .toMatchObject({ revoke: true })
  })

  it('ignores unrelated events without erroring', () => {
    expect(interpret({ event: 'User.Created', data: { userId: 'u1' } }))
      .toEqual({ handled: false, reason: 'ignored' })
  })

  it('treats a payload without an event as malformed', () => {
    expect(interpret({ data: { userId: 'u1' } })).toEqual({ handled: false, reason: 'malformed' })
  })

  it('finds the user id at either the top level or nested under user', () => {
    expect(interpret({ event: 'User.Deleted', data: { id: 'u2' } })).toMatchObject({ userId: 'u2' })
    expect(interpret({ event: 'User.Deleted', data: { user: { id: 'u3' } } })).toMatchObject({ userId: 'u3' })
  })
})

describe('webhook route', () => {
  it('is a 404 when no signing key is configured', async () => {
    // The endpoint must not exist for deployments that do not use webhooks:
    // an unauthenticated route that can revoke devices is worth hiding.
    const { post } = await boot({ key: undefined })
    const response = await post('{"event":"User.Deleted"}', 'anything')
    expect(response.status).toBe(404)
  })

  it('rejects an unsigned or wrongly signed request with 401', async () => {
    const { post } = await boot()
    const body = JSON.stringify({ event: 'User.Deleted', data: { userId: 'u1' } })
    expect((await post(body)).status).toBe(401)
    expect((await post(body, sign(body, 'wrong-key'))).status).toBe(401)
  })

  it('accepts a correctly signed event', async () => {
    const { post } = await boot()
    const body = JSON.stringify({ event: 'User.Deleted', data: { userId: 'u1' } })
    expect((await post(body, sign(body))).status).toBe(200)
  })

  it('returns 200 for an ignored event so Logto does not retry', async () => {
    const { post } = await boot()
    const body = JSON.stringify({ event: 'User.Created', data: { userId: 'u1' } })
    expect((await post(body, sign(body))).status).toBe(200)
  })

  it('returns 200 even for a malformed body once the signature verifies', async () => {
    // Retrying cannot fix malformed JSON, and a non-2xx would make Logto retry.
    const { post } = await boot()
    const body = 'not json'
    expect((await post(body, sign(body))).status).toBe(200)
  })
})

describe('revocation on webhook', () => {
  function descriptor(role: 'host' | 'client' = 'client') {
    const keys = generateKeyPair()
    return { deviceId: randomUUID(), identityKey: keys.publicKey, name: 'd', role, platform: 'linux', clientVersion: '0.4.15' }
  }

  it('revokes every device of the account named by the subject', async () => {
    const store = new Store(join(mkdtempSync(join(tmpdir(), 'dsh-rev-')), 'state.json'),
      'owner@example.com', 'local-test-password')
    const first = descriptor('host'), second = descriptor('client')
    const issued = store.register(first)
    store.register(second)

    // Adopt the environment account so the subject owns these devices.
    const account = store.upsertAccount({ externalId: 'logto-subject-1', email: 'owner@example.com', isAdmin: false })
    expect(store.listFor(account.id).length).toBeGreaterThanOrEqual(2)

    const revoked = store.revokeAccountSessions('logto-subject-1')
    expect(revoked).toEqual(expect.arrayContaining([first.deviceId, second.deviceId]))
    // The pre-existing token must stop working. It reports AUTH_INVALID rather
    // than DEVICE_REVOKED because revocation deletes the token records outright,
    // so the lookup fails before the device state is even consulted — a stronger
    // outcome than a flagged device.
    expect(() => store.authenticate(issued.accessToken))
      .toThrowError(expect.objectContaining({ code: 'AUTH_INVALID' }))
    // And the devices themselves are marked revoked, so re-registration needs an
    // operator rather than silently succeeding on the next connect.
    expect(() => store.get(first.deviceId))
      .toThrowError(expect.objectContaining({ code: 'DEVICE_REVOKED' }))
  })

  it('marks the account suspended so a later login does not silently re-enable it', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'dsh-rev-')), 'state.json')
    const store = new Store(path, 'owner@example.com', 'local-test-password')
    store.upsertAccount({ externalId: 'subject-x', email: 'x@example.com', isAdmin: false })
    store.revokeAccountSessions('subject-x')
    const saved = JSON.parse(require('node:fs').readFileSync(path, 'utf8'))
    const account = Object.values(saved.accounts).find((a: any) => a.externalId === 'subject-x') as any
    expect(account.status).toBe('suspended')
  })

  it('does nothing for an unknown subject', () => {
    const store = new Store(join(mkdtempSync(join(tmpdir(), 'dsh-rev-')), 'state.json'),
      'owner@example.com', 'local-test-password')
    expect(store.revokeAccountSessions('never-seen')).toEqual([])
  })

  it('reactivation restores the account but not the revoked devices', () => {
    // Re-enabling is an operator decision: the devices were revoked deliberately,
    // and silently un-revoking them would re-open a possibly compromised token.
    const path = join(mkdtempSync(join(tmpdir(), 'dsh-rev-')), 'state.json')
    const store = new Store(path, 'owner@example.com', 'local-test-password')
    const device = descriptor()
    store.register(device)
    store.upsertAccount({ externalId: 'subject-y', email: 'owner@example.com', isAdmin: false })
    store.revokeAccountSessions('subject-y')

    expect(store.activateAccount('subject-y')).toBe(true)
    expect(() => store.get(device.deviceId))
      .toThrowError(expect.objectContaining({ code: 'DEVICE_REVOKED' }))
  })
})
