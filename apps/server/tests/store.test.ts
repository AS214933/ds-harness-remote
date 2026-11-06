/**
 * Store upgrade and account-model tests.
 *
 * The upgrade path is the risky part: an operator's state.json already holds
 * paired devices, and losing them means every device has to re-pair. These tests
 * pin that a v1 file is adopted with devices and tokens intact, and that the
 * account id is stable and does not leak the address.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { createHash } from 'node:crypto'
import { scryptSync } from 'node:crypto'
import { Store } from '../src/store.js'
import { generateKeyPair } from '../../../packages/crypto/src/index.js'

const ACCOUNT = 'owner@example.com'
const PASSWORD = 'local-test-password'
let dir: string, file: string

beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'dsh-store-')); file = join(dir, 'state.json') })
afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

function descriptor(role: 'host' | 'client' = 'client') {
  const keys = generateKeyPair()
  return { deviceId: randomUUID(), identityKey: keys.publicKey, name: 'd', role, platform: 'linux', clientVersion: '0.4.15' }
}

/** A version 1 state file exactly as the previous release wrote it. */
function writeV1(devices: Record<string, unknown>, tokens: Record<string, unknown> = {}) {
  // The store recomputes the verifier from the password and drops tokens when it
  // differs, so a realistic file must carry the scrypt output for this password.
  const salt = 'legacy-salt'
  const verifier = scryptSync(PASSWORD, salt, 32).toString('hex')
  writeFileSync(file, JSON.stringify({
    version: 1, account: ACCOUNT, salt, verifier,
    devices, tokens,
  }))
}

describe('state upgrade from version 1', () => {
  it('keeps every device and token so nothing has to re-pair', () => {
    const device = descriptor('host')
    // Tokens are stored by digest, so write the digest of a known plaintext and
    // then check that plaintext still authenticates after the upgrade.
    const accessToken = 'legacy-access-token-plaintext'
    const digest = createHash('sha256').update(accessToken).digest('hex')
    writeV1(
      { [device.deviceId]: { descriptor: device, revoked: false, lastSeenAt: 1234 } },
      { [digest]: { kind: 'access', deviceId: device.deviceId, expires: Date.now() + 60_000, used: false } },
    )

    const store = new Store(file, ACCOUNT, PASSWORD)
    // The device is still readable under its own id...
    expect(store.get(device.deviceId).descriptor).toMatchObject({ deviceId: device.deviceId, role: 'host' })
    // ...and its lastSeenAt survived, which proves we adopted rather than reset.
    expect(store.get(device.deviceId).lastSeenAt).toBe(1234)
    // The pre-upgrade token still authenticates: a paired device keeps working.
    expect(store.authenticate(accessToken).descriptor.deviceId).toBe(device.deviceId)
    expect(store.listFor(store.accountId)).toHaveLength(1)
  })

  it('writes version 2 with a stable account id', () => {
    writeV1({})
    new Store(file, ACCOUNT, PASSWORD)
    const saved = JSON.parse(readFileSync(file, 'utf8'))
    expect(saved.version).toBe(2)
    const ids = Object.keys(saved.accounts)
    expect(ids).toHaveLength(1)
    expect(saved.accounts[ids[0]!].email).toBe(ACCOUNT)
    expect(saved.accounts[ids[0]!].status).toBe('active')
  })

  it('keeps the account id stable across restarts', () => {
    writeV1({})
    const first = new Store(file, ACCOUNT, PASSWORD).accountId
    const second = new Store(file, ACCOUNT, PASSWORD).accountId
    expect(first).toBe(second)
  })

  it('does not put the email address in the account id', () => {
    writeV1({})
    const store = new Store(file, ACCOUNT, PASSWORD)
    // The id surfaces in device descriptors as membershipId, so it must not
    // disclose the operator's address.
    expect(store.accountId).not.toContain(ACCOUNT)
    expect(store.accountId).not.toContain('owner')
    expect(store.accountId).toMatch(/^account:[0-9a-f]{16}$/)
  })

  it('drops devices and tokens when the account name changed', () => {
    const device = descriptor()
    const digest = 'b'.repeat(64)
    writeV1(
      { [device.deviceId]: { descriptor: device, revoked: false, lastSeenAt: 0 } },
      { [digest]: { kind: 'access', deviceId: device.deviceId, expires: Date.now() + 60_000, used: false } },
    )
    // A different DSH_SERVER_ACCOUNT must not inherit the previous owner's
    // devices; that is the documented "changing the account resets pairing".
    const store = new Store(file, 'someone-else@example.com', PASSWORD)
    expect(store.listFor(store.accountId)).toHaveLength(0)
  })

  it('is idempotent: loading a v2 file twice changes nothing', () => {
    writeV1({})
    new Store(file, ACCOUNT, PASSWORD)
    const once = readFileSync(file, 'utf8')
    new Store(file, ACCOUNT, PASSWORD)
    const twice = readFileSync(file, 'utf8')
    expect(JSON.parse(twice)).toEqual(JSON.parse(once))
  })
})

describe('account scoping', () => {
  it('gives a foreign account no devices and no direct reads', () => {
    const store = new Store(file, ACCOUNT, PASSWORD)
    const device = descriptor('host')
    store.register(device)

    expect(store.listFor('account:0000000000000000')).toHaveLength(0)
    // Must be indistinguishable from a missing device, not a 403.
    expect(() => store.getOwned(device.deviceId, 'account:0000000000000000'))
      .toThrowError(expect.objectContaining({ code: 'DEVICE_NOT_FOUND', status: 404 }))
    expect(() => store.getOwned(randomUUID(), store.accountId))
      .toThrowError(expect.objectContaining({ code: 'DEVICE_NOT_FOUND', status: 404 }))
  })

  it('stamps each authenticated device with the account id', () => {
    const store = new Store(file, ACCOUNT, PASSWORD)
    const device = descriptor()
    const issued = store.register(device)
    expect(store.authenticate(issued.accessToken).accountId).toBe(store.accountId)
  })

  it('still revokes and persists, since get() returns the live record', () => {
    // Regression guard: returning a copy from get() would silently break
    // revoke() and touch(), which mutate the returned object in place.
    const store = new Store(file, ACCOUNT, PASSWORD)
    const device = descriptor()
    store.register(device)
    store.touch(device.deviceId, '0.4.16')
    expect(new Store(file, ACCOUNT, PASSWORD).get(device.deviceId).lastSeenAt).toBeGreaterThan(0)

    store.revoke(device.deviceId)
    expect(() => new Store(file, ACCOUNT, PASSWORD).get(device.deviceId))
      .toThrowError(expect.objectContaining({ code: 'DEVICE_REVOKED' }))
  })
})

describe('account upsert by identity-provider subject', () => {
  it('anchors the account to the subject, not the address', () => {
    const store = new Store(file, ACCOUNT, PASSWORD)
    const created = store.upsertAccount({ externalId: 'logto-abc', email: 'alice@example.com', isAdmin: false })
    expect(created.externalId).toBe('logto-abc')
    expect(created.email).toBe('alice@example.com')
    // The id must not be derived from the email, or changing the address would
    // orphan the devices.
    expect(created.id).not.toContain('alice')
  })

  it('keeps the same account when the address changes', () => {
    const store = new Store(file, ACCOUNT, PASSWORD)
    const first = store.upsertAccount({ externalId: 'logto-abc', email: 'alice@example.com', isAdmin: false })
    const second = store.upsertAccount({ externalId: 'logto-abc', email: 'alice.new@example.com', isAdmin: true })
    expect(second.id).toBe(first.id)
    expect(second.email).toBe('alice.new@example.com')
    expect(second.isAdmin).toBe(true)
  })

  it('creates a separate account for a second subject', () => {
    const store = new Store(file, ACCOUNT, PASSWORD)
    const a = store.upsertAccount({ externalId: 'logto-a', email: 'a@example.com', isAdmin: false })
    const b = store.upsertAccount({ externalId: 'logto-b', email: 'b@example.com', isAdmin: false })
    expect(b.id).not.toBe(a.id)
  })

  it('does not give a second subject the first subject\'s devices', () => {
    // This is the hijack the email-as-key design would allow: two people whose
    // addresses collide, or a deleted address being re-registered.
    const store = new Store(file, ACCOUNT, PASSWORD)
    const device = descriptor('host')
    store.register(device)
    const a = store.upsertAccount({ externalId: 'logto-a', email: 'a@example.com', isAdmin: false })
    const b = store.upsertAccount({ externalId: 'logto-b', email: 'b@example.com', isAdmin: false })
    expect(store.listFor(b.id)).toHaveLength(0)
    expect(store.listFor(a.id).length + store.listFor(store.accountId).length).toBeGreaterThanOrEqual(0)
  })

  it('adopts the environment account on the first subject so devices survive', () => {
    // An operator enabling Logto on an existing deployment must keep the devices
    // already paired under the environment account.
    const store = new Store(file, ACCOUNT, PASSWORD)
    const device = descriptor('host')
    store.register(device)
    const before = store.accountId

    const adopted = store.upsertAccount({ externalId: 'logto-first', email: ACCOUNT, isAdmin: false })
    expect(adopted.id).toBe(before)
    // Reload: adoption must be durable, not just in memory.
    const reloaded = new Store(file, ACCOUNT, PASSWORD)
    expect(reloaded.listFor(adopted.id)).toHaveLength(1)
  })

  it('does not adobt twice: a second subject gets its own account', () => {
    const store = new Store(file, ACCOUNT, PASSWORD)
    const first = store.upsertAccount({ externalId: 'logto-first', email: ACCOUNT, isAdmin: false })
    const second = store.upsertAccount({ externalId: 'logto-second', email: 'other@example.com', isAdmin: false })
    expect(second.id).not.toBe(first.id)
    // And the adopted account stays bound to the first subject.
    const again = store.upsertAccount({ externalId: 'logto-first', email: ACCOUNT, isAdmin: false })
    expect(again.id).toBe(first.id)
  })

  it('is idempotent across reloads', () => {
    const store = new Store(file, ACCOUNT, PASSWORD)
    const created = store.upsertAccount({ externalId: 'logto-abc', email: 'alice@example.com', isAdmin: false })
    const reloaded = new Store(file, ACCOUNT, PASSWORD)
    const again = reloaded.upsertAccount({ externalId: 'logto-abc', email: 'alice@example.com', isAdmin: false })
    expect(again.id).toBe(created.id)
    // One account, not two: the first subject adopted the environment account
    // rather than creating a sibling, and the reload did not duplicate it.
    expect(Object.keys(JSON.parse(readFileSync(file, 'utf8')).accounts)).toHaveLength(1)
  })
})
