/**
 * Receives Logto webhooks so a deleted or suspended user loses access at once
 * instead of waiting for their token to expire.
 *
 * Without this the Server only learns about a disabled account on next login,
 * which means a device token issued before the change keeps working for its full
 * lifetime (8h for web sessions, 1h for device access tokens, 30d for refresh).
 *
 * Delivery is asynchronous and must not be treated as reliable: Logto retries but
 * a response is not a guarantee, and a webhook cannot block a sign-in. The login
 * path still checks `isSuspended` on every attempt, so this only shortens the
 * window — it never becomes the sole control.
 *
 * Signature: HMAC-SHA256 hex over the RAW body, in `logto-signature-sha-256`.
 * The raw bytes matter; re-serialising parsed JSON changes them.
 */
import { createHmac, timingSafeEqual } from 'node:crypto'

/** Events that revoke access. Everything else is accepted and ignored. */
const REVOKING_EVENTS = new Set([
  'User.Deleted',
  'User.SuspensionStatus.Updated',
])

export interface WebhookPayload {
  hookId?: string
  /** Kept across delivery retries; lets a handler deduplicate. */
  deliveryId?: string
  event?: string
  createdAt?: string
  session?: unknown
  data?: unknown
  /** Some event shapes carry the user entity at the top level instead of `data`. */
  user?: unknown
}

export type WebhookOutcome =
  | { handled: false; reason: 'signature' | 'malformed' | 'ignored' }
  | { handled: true; event: string; userId: string | null; revoke: boolean }

/**
 * Constant-time signature comparison. `expected` is untrusted input, so length
 * differences must not short-circuit a partial match into a timing signal.
 */
export function verifySignature(signingKey: string, rawBody: Buffer, header: string | undefined): boolean {
  if (!signingKey || !header) return false
  const computed = createHmac('sha256', signingKey).update(rawBody).digest('hex')
  const a = Buffer.from(computed, 'utf8')
  const b = Buffer.from(header.trim().toLowerCase(), 'utf8')
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

/**
 * Interpret a verified payload.
 *
 * `User.SuspensionStatus.Updated` fires for both suspend and reactivate, and the
 * payload carries the resulting state. Treating every such event as a revoke
 * would log a reactivated user out of everything for no reason, so the payload's
 * own flag decides. Deletion is unconditional.
 */
export function interpret(payload: WebhookPayload): WebhookOutcome {
  const event = typeof payload.event === 'string' ? payload.event : undefined
  if (!event) return { handled: false, reason: 'malformed' }
  if (!REVOKING_EVENTS.has(event)) return { handled: false, reason: 'ignored' }

  const data = payload.data
  const userId = extractUserId(data) ?? extractUserId(payload.user)
  if (event === 'User.Deleted') return { handled: true, event, userId, revoke: true }

  // Suspension: revoke only when the account ends up suspended.
  const suspended = extractSuspended(data) ?? extractSuspended(payload.user)
  if (suspended === undefined) {
    // Unknown shape: fail closed. Revoking a reactivated user is a nuisance;
    // leaving a suspended user active is a security failure.
    return { handled: true, event, userId, revoke: true }
  }
  return { handled: true, event, userId, revoke: suspended }
}

function extractUserId(data: unknown): string | null {
  // Where the user entity lives, per Logto's own context manager
  // (packages/core/src/libraries/hook/context-manager.ts):
  //
  //   const { user, ...rest } = context
  //   push({ event, ...(user ? { data: pick(user, ...) } : {}), ...rest })
  //
  // The `user` field is lifted OUT of the context and placed in `data`, so the
  // id is at `data.id`. (The docs describe `User.Deleted` as `data: null`, which
  // is stale: the delete route passes `{ user }` explicitly so the payload
  // carries the deleted entity.) `userId` and a nested `data.user.id` are also
  // accepted because different event families and older versions differ.
  if (typeof data !== 'object' || data === null) return null
  const record = data as Record<string, unknown>
  for (const key of ['userId', 'id']) {
    if (typeof record[key] === 'string') return record[key] as string
  }
  // Some events nest the entity.
  if (typeof record.user === 'object' && record.user !== null) {
    const nested = record.user as Record<string, unknown>
    if (typeof nested.id === 'string') return nested.id
  }
  return null
}
function extractSuspended(data: unknown): boolean | undefined {
  if (typeof data !== 'object' || data === null) return undefined
  const record = data as Record<string, unknown>
  if (typeof record.isSuspended === 'boolean') return record.isSuspended
  // Older/newer shapes may nest it under the user entity.
  if (typeof record.user === 'object' && record.user !== null) {
    const nested = record.user as Record<string, unknown>
    if (typeof nested.isSuspended === 'boolean') return nested.isSuspended
  }
  return undefined
}
