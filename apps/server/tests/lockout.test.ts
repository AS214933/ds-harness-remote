/**
 * Login lockout tests.
 *
 * The lockout exists because fixed-window rate limits forgive an attacker every
 * minute. These tests pin the properties that make it useful rather than
 * harmful: it counts consecutive failures, a good password clears the streak, an
 * outage does not lock anyone out, and the lock expires on its own so the
 * endpoint cannot be used to permanently deny an address.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import { LoginLockout } from '../src/auth/lockout.js'
import { createRemoteServer } from '../src/server.js'
import type { AuthOutcome } from '../src/auth/logto.js'

describe('LoginLockout', () => {
  it('does not lock before the threshold', () => {
    const lockout = new LoginLockout({ threshold: 3 })
    expect(lockout.recordFailure('k').locked).toBe(false)
    expect(lockout.recordFailure('k').locked).toBe(false)
    expect(lockout.check('k').locked).toBe(false)
  })

  it('locks on the threshold and reports how long to wait', () => {
    const lockout = new LoginLockout({ threshold: 3, lockMs: 60_000 })
    lockout.recordFailure('k'); lockout.recordFailure('k')
    const third = lockout.recordFailure('k')
    expect(third.locked).toBe(true)
    if (third.locked) expect(third.retryAfterMs).toBe(60_000)
    const check = lockout.check('k')
    expect(check.locked).toBe(true)
  })

  it('clears the streak after a successful login', () => {
    // A user who mistypes twice and then succeeds must not carry a debt into
    // their next session.
    const lockout = new LoginLockout({ threshold: 3 })
    lockout.recordFailure('k'); lockout.recordFailure('k')
    lockout.recordSuccess('k')
    expect(lockout.check('k')).toEqual({ locked: false, failures: 0, remaining: 3 })
  })

  it('expires the lock on its own instead of locking permanently', () => {
    // A permanent lock would let anyone deny service to any address they type.
    const lockout = new LoginLockout({ threshold: 2, lockMs: 1_000 })
    lockout.recordFailure('k')
    const t0 = 10_000
    lockout.recordFailure('k', t0)
    expect(lockout.check('k', t0 + 500).locked).toBe(true)
    // After the lock window the account is usable again, with a clean streak.
    expect(lockout.check('k', t0 + 1_001)).toEqual({ locked: false, failures: 0, remaining: 2 })
  })

  it('forgets a stale streak that never reached the threshold', () => {
    const lockout = new LoginLockout({ threshold: 5, streakMs: 1_000 })
    lockout.recordFailure('k', 1_000)
    lockout.recordFailure('k', 1_500)
    // Much later: the old failures should not count toward a new lockout.
    expect(lockout.check('k', 60_000)).toEqual({ locked: false, failures: 0, remaining: 5 })
  })

  it('keeps accounts independent', () => {
    const lockout = new LoginLockout({ threshold: 2 })
    lockout.recordFailure('a'); lockout.recordFailure('a')
    expect(lockout.check('a').locked).toBe(true)
    expect(lockout.check('b').locked).toBe(false)
  })

  it('does not grow without bound', () => {
    const lockout = new LoginLockout({ threshold: 2, lockMs: 10, streakMs: 10 })
    for (let i = 0; i < 100; i += 1) lockout.recordFailure(`k${i}`, 1_000)
    expect(lockout.size).toBe(100)
    // Sweeping on the next call at a later time drops them all.
    lockout.check('probe', 10_000)
    expect(lockout.size).toBe(0)
  })
})

describe('lockout in the login route', () => {
  let app: ReturnType<typeof createRemoteServer> | undefined
  let dir = ''
  let mode: 'invalid' | 'unavailable' | 'ok' = 'invalid'

  /** (Re)start the server, optionally with a low lockout threshold. */
  async function reset(lockout?: { threshold?: number; lockMs?: number }): Promise<void> {
    if (app) { await app.close(); app = undefined }
    if (dir) rmSync(dir, { recursive: true, force: true })
    dir = mkdtempSync(join(tmpdir(), 'dsh-lock-'))
    app = createRemoteServer({
      account: 'owner@example.com',
      password: 'local-test-password',
      dataFile: join(dir, 'state.json'),
      publicUrl: 'http://localhost:8080',
      auth: {
        authenticate: async (): Promise<AuthOutcome> => {
          if (mode === 'unavailable') return { ok: false, reason: 'unavailable' }
          if (mode === 'ok') return { ok: true, externalId: 'sub-1', email: 'a@b.com', isAdmin: false }
          return { ok: false, reason: 'invalid' }
        },
      },
      ...(lockout === undefined ? {} : { lockout }),
    })
    app.server.listen(0, '127.0.0.1')
    await once(app.server, 'listening')
  }

  beforeEach(async () => {
    mode = 'invalid'
    await reset()
  })

  afterEach(async () => {
    if (app) { await app.close(); app = undefined }
    if (dir) { rmSync(dir, { recursive: true, force: true }); dir = '' }
  })

  const attempt = () => fetch(
    `http://127.0.0.1:${(app!.server.address() as { port: number }).port}/api/v1/auth/login`,
    { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'a@b.com', password: 'pw' }) })

  it('locks after consecutive failures and reports Retry-After', async () => {
    // The production threshold (25) sits ABOVE the per-address budget (20/min) on
    // purpose, so the documented 20-attempt behaviour stays intact and only an
    // attacker rotating addresses meets the lockout. Lower it here so the route
    // path is exercised without 25 real requests.
    await reset({ threshold: 3, lockMs: 60_000 })
    const statuses: number[] = []
    for (let i = 0; i < 5; i += 1) statuses.push((await attempt()).status)
    expect(statuses.slice(0, 2).every(s => s === 401)).toBe(true)
    expect(statuses.slice(2)).toEqual([429, 429, 429])
    const response = await attempt()
    expect(response.status).toBe(429)
    // The client is told when to come back rather than being left guessing.
    expect(response.headers.get('retry-after')).toBeTruthy()
  }, 20_000)

  it('does not count an outage as a failed attempt', async () => {
    // A Logto outage already produces 503; locking accounts on top of that would
    // turn an infrastructure problem into a user lockout.
    mode = 'unavailable'
    for (let i = 0; i < 10; i += 1) expect((await attempt()).status).toBe(503)
    mode = 'invalid'
    // The streak is still empty, so a wrong password reports 401, not 429.
    expect((await attempt()).status).toBe(401)
  }, 20_000)

  it('a successful login clears the streak', async () => {
    for (let i = 0; i < 7; i += 1) await attempt()
    mode = 'ok'
    expect((await attempt()).status).toBe(200)
    mode = 'invalid'
    // A fresh streak starts; the next wrong password is a plain 401.
    expect((await attempt()).status).toBe(401)
  }, 20_000)
})
