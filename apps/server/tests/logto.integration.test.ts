/**
 * Integration test for the Logto adapter against a REAL Logto instance.
 *
 * This is a live test, not a mock: it only runs when LOGTO_INTEGRATION=1 and the
 * environment points at a running Logto. It exists because the behaviour that
 * matters here (does `password/verify` check suspension? does it ignore MFA?)
 * is a property of Logto, not of our code, so a mock would assert our own
 * assumptions back at us.
 *
 * Start the lab instance, seed users, then:
 *   LOGTO_INTEGRATION=1 \
 *   LOGTO_ENDPOINT=http://localhost:3001 \
 *   LOGTO_M2M_CLIENT_ID=... LOGTO_M2M_CLIENT_SECRET=... \
 *   pnpm --filter @dsh-remote/server exec vitest run tests/logto.integration.test.ts
 *
 * Users are seeded by logto-lab/seed_for_ts_test.py.
 */
import { describe, expect, it } from 'vitest'
import { LogtoAuthProvider, createLogtoAuth } from '../src/auth/logto.js'

const enabled = process.env.LOGTO_INTEGRATION === '1'
const PASSWORD = 'CorrectHorseBattery1!'

function provider(): LogtoAuthProvider {
  return createLogtoAuth(process.env)
}

describe.runIf(enabled)('Logto adapter (live)', () => {
  it('accepts a correct password and returns the Logto user id', async () => {
    const result = await provider().authenticate('t_happy@example.com', PASSWORD)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.email).toBe('t_happy@example.com')
      expect(result.externalId).toMatch(/^[a-z0-9]{12}$/)
      expect(typeof result.isAdmin).toBe('boolean')
    }
  })

  it('rejects a wrong password', async () => {
    expect(await provider().authenticate('t_wrong@example.com', 'definitely-wrong'))
      .toEqual({ ok: false, reason: 'invalid' })
  })

  it('rejects an unknown email exactly like a wrong password', async () => {
    expect(await provider().authenticate('nobody@example.com', PASSWORD))
      .toEqual({ ok: false, reason: 'invalid' })
  })

  it('rejects a suspended user even with the correct password', async () => {
    // Logto's password/verify answers 204 for a suspended user; the /204/ is the
    // whole reason this adapter checks isSuspended itself.
    expect(await provider().authenticate('t_susp@example.com', PASSWORD))
      .toEqual({ ok: false, reason: 'suspended' })
  })

  it('reports a suspended user as invalid when the password is also wrong', async () => {
    // A wrong password must not reveal suspension, or the status code becomes a
    // probe for "this account exists and is suspended".
    expect(await provider().authenticate('t_susp@example.com', 'nope'))
      .toEqual({ ok: false, reason: 'invalid' })
  })

  it('accepts a user who enabled TOTP MFA', async () => {
    // The clients cannot perform a second factor. password/verify ignores MFA,
    // which is what keeps a 2FA user able to sign in here.
    const result = await provider().authenticate('t_mfa@example.com', PASSWORD)
    expect(result.ok).toBe(true)
  })

  it('accepts a user who registered a passkey', async () => {
    const result = await provider().authenticate('t_passkey@example.com', PASSWORD)
    expect(result.ok).toBe(true)
  })

  it('rejects a user with no password set', async () => {
    expect(await provider().authenticate('t_nopw2@example.com', PASSWORD))
      .toEqual({ ok: false, reason: 'invalid' })
  })

  it('rejects empty credentials without calling Logto', async () => {
    expect(await provider().authenticate('', '')).toEqual({ ok: false, reason: 'invalid' })
    expect(await provider().authenticate('t_happy@example.com', '')).toEqual({ ok: false, reason: 'invalid' })
  })

  it('normalises email case and whitespace', async () => {
    const result = await provider().authenticate('  T_HAPPY@EXAMPLE.COM  ', PASSWORD)
    expect(result.ok).toBe(true)
  })

  it('reports unavailable when Logto cannot be reached', async () => {
    const unreachable = new LogtoAuthProvider({
      endpoint: 'http://127.0.0.1:1',
      clientId: 'x',
      clientSecret: 'y',
      resource: 'https://default.logto.app/api',
      adminRole: 'admin',
    })
    expect(await unreachable.authenticate('t_happy@example.com', PASSWORD))
      .toEqual({ ok: false, reason: 'unavailable' })
  })

  it('spends comparable time on unknown-email and wrong-password', async () => {
    // Enumeration defence: if "no such user" returned noticeably faster than
    // "wrong password", an attacker could enumerate registered emails.
    const p = provider()
    const time = async (email: string, password: string): Promise<number> => {
      const started = Date.now()
      await p.authenticate(email, password)
      return Date.now() - started
    }
    const unknown: number[] = [], wrong: number[] = []
    for (let i = 0; i < 3; i += 1) {
      unknown.push(await time('nobody@example.com', PASSWORD))
      wrong.push(await time('t_wrong@example.com', 'nope'))
    }
    const mean = (xs: number[]): number => xs.reduce((a, b) => a + b, 0) / xs.length
    const delta = Math.abs(mean(unknown) - mean(wrong))
    // Loose bound: this guards against an order-of-magnitude gap, not jitter.
    expect(delta).toBeLessThan(120)
  })
})
