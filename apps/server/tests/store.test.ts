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
