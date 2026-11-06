/**
 * Per-account login lockout.
 *
 * The existing rate limits are fixed windows: they cap throughput but forgive
 * completely once the window rolls. That means a slow, patient attacker gets a
 * fresh budget every minute forever. This adds a second, independent signal —
 * consecutive failures against one account — so a sustained guessing campaign
 * eventually meets a lockout that does not reset just because a minute passed.
 *
 * Threshold sizing matters. The per-address limit (20/min) already stops a
 * single source long before any reasonable threshold, so a lockout set BELOW it
 * would only change the meaning of the existing limit — it would fire first and
 * make the documented 20-attempt budget unreachable. The lockout therefore sits
 * ABOVE the per-source budget (`25`), which means it is only reachable by an
 * attacker rotating source addresses. That is exactly the case the fixed-window
 * limiter cannot cover, and it keeps the existing behaviour intact.
 *
 * Scope and design choices:
 *
 * - Keyed by the submitted address, hashed. Never by whether the account exists:
 *   a lockout that only applies to real accounts would confirm which addresses
 *   are registered.
 * - A successful login clears the counter, so a legitimate user who mistyped a
 *   few times is not penalised after they get it right.
 * - The lockout is temporary and self-healing. A permanent lock would turn the
 *   endpoint into a denial-of-service tool against any address an attacker types.
 * - State is in memory. A restart clears lockouts, which is acceptable: the
 *   window is short, and persisting it would add a write per failed login.
 */

export interface LockoutOptions {
  /** Consecutive failures before the account is locked. */
  threshold?: number
  /** How long a lock lasts once triggered. */
  lockMs?: number
  /** How long a failure streak is remembered if it never reaches the threshold. */
  streakMs?: number
}

interface Entry {
  failures: number
  firstFailureAt: number
  lockedUntil: number | null
}

export type LockoutState =
  | { locked: false; failures: number; remaining: number }
  | { locked: true; retryAfterMs: number }

export class LoginLockout {
  private readonly entries = new Map<string, Entry>()
  private readonly threshold: number
  private readonly lockMs: number
  private readonly streakMs: number

  constructor(options: LockoutOptions = {}) {
    this.threshold = options.threshold ?? 25
    this.lockMs = options.lockMs ?? 5 * 60_000
    this.streakMs = options.streakMs ?? 15 * 60_000
  }

  /**
   * Check without recording. Called before verifying so a locked account does
   * not pay the (expensive) password-hash cost on every attempt.
   */
  check(key: string, now = Date.now()): LockoutState {
    this.sweep(now)
    const entry = this.entries.get(key)
    if (!entry) return { locked: false, failures: 0, remaining: this.threshold }
    if (entry.lockedUntil !== null) {
      if (entry.lockedUntil > now) return { locked: true, retryAfterMs: entry.lockedUntil - now }
      // Lock expired: start a clean streak rather than resuming the old count.
      this.entries.delete(key)
      return { locked: false, failures: 0, remaining: this.threshold }
    }
    if (now - entry.firstFailureAt > this.streakMs) {
      this.entries.delete(key)
      return { locked: false, failures: 0, remaining: this.threshold }
    }
    return { locked: false, failures: entry.failures, remaining: Math.max(0, this.threshold - entry.failures) }
  }

  /** Record a failed attempt. Returns the state after recording. */
  recordFailure(key: string, now = Date.now()): LockoutState {
    this.sweep(now)
    const existing = this.entries.get(key)
    const stale = existing !== undefined
      && existing.lockedUntil === null
      && now - existing.firstFailureAt > this.streakMs
    const entry: Entry = existing === undefined || stale
      ? { failures: 0, firstFailureAt: now, lockedUntil: null }
      : existing
    entry.failures += 1
    if (entry.failures >= this.threshold) {
      entry.lockedUntil = now + this.lockMs
      this.entries.set(key, entry)
      return { locked: true, retryAfterMs: this.lockMs }
    }
    this.entries.set(key, entry)
    return { locked: false, failures: entry.failures, remaining: this.threshold - entry.failures }
  }

  /** A good password clears the streak: the user is not being attacked. */
  recordSuccess(key: string): void { this.entries.delete(key) }

  /**
   * Drop expired state. Runs on every call so a flood of distinct addresses
   * cannot grow the map without bound — the same reason the rate limiter sweeps.
   */
  private sweep(now: number): void {
    for (const [key, entry] of this.entries) {
      const expired = entry.lockedUntil !== null
        ? entry.lockedUntil <= now
        : now - entry.firstFailureAt > this.streakMs
      if (expired) this.entries.delete(key)
    }
  }

  /** Exposed for tests and diagnostics. */
  get size(): number { return this.entries.size }
}
