import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { accountDeviceDescriptorSchema, type AccountDeviceDescriptor } from '@dsh-remote/protocol'
import { z } from 'zod'

export class ApiError extends Error {
  constructor(readonly code: string, readonly status = 400) { super(code) }
}
export const hash = (value: string): string => createHash('sha256').update(value).digest('hex')
export const secret = (): string => randomBytes(32).toString('base64url')
export const equal = (left: string, right: string): boolean => timingSafeEqual(Buffer.from(hash(left)), Buffer.from(hash(right)))
const tokenSchema = z.object({ kind: z.enum(['access', 'refresh']), deviceId: z.string(), expires: z.number(), used: z.boolean() })
const savedDeviceSchema = z.object({ descriptor: accountDeviceDescriptorSchema, revoked: z.boolean(), lastSeenAt: z.number() })
/**
 * One account. `id` is the stable key every device hangs off; `externalId` is the
 * identity-provider subject (Logto `user.id`) when one is configured, and absent
 * for the environment-variable single account. Email is stored but never used as
 * a key: it is mutable, and after a user is deleted it can be re-registered by
 * someone else, which would silently hand over the previous owner's devices.
 */
const accountSchema = z.object({
  id: z.string(),
  externalId: z.string().optional(),
  email: z.string(),
  isAdmin: z.boolean(),
  status: z.enum(['active', 'suspended']),
})
type Account = z.infer<typeof accountSchema>
export type { Account }
/**
 * version 2 introduced `accounts` and moved device indices under it. version 1
 * (a single `account` string plus a password verifier) still parses so an
 * existing state.json upgrades in place rather than being rejected.
 */
const stateSchemaV2 = z.object({
  version: z.literal(2),
  accounts: z.record(z.string(), accountSchema),
  devices: z.record(z.string(), savedDeviceSchema),
  tokens: z.record(z.string(), tokenSchema),
  /**
   * The environment single account, kept for the password comparison and for
   * choosing which account a new device registers under while the Server runs
   * without an identity provider. Removed once Logto is the only entry point.
   */
  account: z.string(),
  salt: z.string(),
  verifier: z.string(),
})
const stateSchemaV1 = z.object({ version: z.literal(1), account: z.string(), salt: z.string(), verifier: z.string(), devices: z.record(z.string(), savedDeviceSchema), tokens: z.record(z.string(), tokenSchema) })
const stateSchema = z.union([stateSchemaV2, stateSchemaV1])
type SavedDevice = z.infer<typeof savedDeviceSchema>
/**
 * A stored device plus the account it belongs to. `accountId` is the account's
 * stable id, not its email, so devices survive a user changing address.
 */
export type AuthenticatedDevice = SavedDevice & { accountId: string }

/** Single-process store. Only token digests and public identities reach disk. */
export class Store {
  private state: z.infer<typeof stateSchemaV2>
  onInvalidate: (id: string) => void = () => {}
  constructor(private readonly file: string, readonly account: string, password: string) {
    const parsed = existsSync(file) ? stateSchema.parse(JSON.parse(readFileSync(file, 'utf8'))) : undefined
    const salt = parsed?.salt ?? secret()
    const verifier = scryptSync(password, salt, 32).toString('hex')
    this.state = parsed === undefined ? this.fresh(account, salt, verifier) : this.upgrade(parsed, account, salt, verifier)
    Object.assign(this.state, { account, verifier })
    this.save()
  }
  private fresh(account: string, salt: string, verifier: string): z.infer<typeof stateSchemaV2> {
    return {
      version: 2,
      accounts: { [this.accountIdFor(account)]: { id: this.accountIdFor(account), email: account, isAdmin: false, status: 'active' } },
      devices: {}, tokens: {}, account, salt, verifier,
    }
  }
  /**
   * Version 1 stored one account by name. Adopt it as-is: keep every device and
   * token so an operator upgrading does not have to re-pair anything. The only
   * change is that devices now hang off a stable account id.
   */
  private upgrade(parsed: z.infer<typeof stateSchema>, account: string, salt: string, verifier: string): z.infer<typeof stateSchemaV2> {
    if (parsed.version === 2) {
      if (parsed.account !== account || !equal(parsed.verifier, verifier)) parsed.tokens = {}
      if (parsed.account !== account) parsed.devices = {}
      return parsed
    }
    const id = this.accountIdFor(account)
    return {
      version: 2,
      accounts: { [id]: { id, email: account, isAdmin: false, status: 'active' } },
      devices: parsed.account === account ? parsed.devices : {},
      tokens: parsed.account === account && equal(parsed.verifier, verifier) ? parsed.tokens : {},
      account, salt, verifier,
    }
  }
  /**
   * Stable account key derived from the sign-in name. Hashing keeps the address
   * out of ids that surface in responses; it is stable across restarts so devices
   * stay attached.
   */
  private accountIdFor(account: string): string { return `account:${hash(account).slice(0, 16)}` }
  /** The account a request belongs to while the Server is single-account. */
  get accountId(): string { return this.accountIdFor(this.account) }

  /**
   * Find or create the account for an identity-provider subject.
   *
   * Keyed by `externalId` rather than email: the address is mutable and, after a
   * user is deleted, re-registerable by someone else. Reusing it as a key would
   * hand the new person the previous owner's devices.
   *
   * A first login adopts the environment account instead of creating a second
   * one, so an operator switching on Logto keeps their paired devices. That
   * adoption is only safe for the very first subject and while the environment
   * account is the current owner; afterwards new subjects get their own account.
   */
  upsertAccount(identity: { externalId: string; email: string; isAdmin: boolean }): Account {
    const byExternal = Object.values(this.state.accounts).find(a => a.externalId === identity.externalId)
    if (byExternal) {
      byExternal.email = identity.email
      byExternal.isAdmin = identity.isAdmin
      this.save()
      return byExternal
    }

    // Adopt the environment account on first Logto login: it has no externalId
    // yet and still owns the devices registered before Logto was configured.
    const legacyId = this.accountId
    const legacy = this.state.accounts[legacyId]
    const adopt = legacy !== undefined && legacy.externalId === undefined && Object.keys(this.state.accounts).length === 1
    const id = adopt ? legacyId : `account:${hash(identity.externalId).slice(0, 16)}`
    const existing = this.state.accounts[id]
    const account: Account = {
      id,
      externalId: identity.externalId,
      email: identity.email,
      isAdmin: identity.isAdmin,
      status: existing?.status ?? 'active',
    }
    this.state.accounts[id] = account
    // Keep `account` pointing at the adopted owner so device registration and the
    // password fallback keep working.
    if (adopt) this.state.account = identity.email
    this.save()
    return account
  }
  private save(): void {
    mkdirSync(dirname(this.file), { recursive: true, mode: 0o700 })
    const tmp = `${this.file}.tmp`
    writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 })
    renameSync(tmp, this.file)
  }
  get(id: string): SavedDevice {
    const d = Object.hasOwn(this.state.devices, id) ? this.state.devices[id] : undefined
    if (!d) throw new ApiError('DEVICE_NOT_FOUND', 404)
    if (d.revoked) throw new ApiError('DEVICE_REVOKED', 403)
    return d
  }
  list(): SavedDevice[] { return Object.values(this.state.devices).filter(d => !d.revoked) }
  /**
   * Devices the given account is allowed to see. While the Server is
   * single-account every stored device belongs to `this.accountId` and any other
   * id sees none; reading through here keeps every call site already
   * account-scoped for the day a second account exists.
   */
  listFor(accountId: string): SavedDevice[] { return accountId === this.accountId ? this.list() : [] }
  /**
   * Read a device the given account is allowed to see. A device owned by another
   * account must look exactly like a missing one: reporting 403 instead would
   * turn callers into existence probes for foreign deviceIds.
   */
  getOwned(id: string, accountId: string): SavedDevice {
    const d = this.get(id)
    if (accountId !== this.accountId) throw new ApiError('DEVICE_NOT_FOUND', 404)
    return d
  }
  register(descriptor: AccountDeviceDescriptor): ReturnType<Store['issue']> {
    const old = this.state.devices[descriptor.deviceId]
    if (old?.revoked) throw new ApiError('DEVICE_REVOKED', 403)
    if (old && (old.descriptor.identityKey !== descriptor.identityKey || old.descriptor.role !== descriptor.role)) throw new ApiError('PEER_IDENTITY_MISMATCH', 409)
    if (!old && Object.keys(this.state.devices).length >= 256) throw new ApiError('RATE_LIMITED', 429)
    this.state.devices[descriptor.deviceId] = { descriptor, revoked: false, lastSeenAt: old?.lastSeenAt ?? 0 }
    this.invalidate(descriptor.deviceId)
    return this.issue(descriptor.deviceId)
  }
  private issue(deviceId: string, refreshTokenExpiresAt = Date.now() + 30 * 86400_000) {
    for (const [key, value] of Object.entries(this.state.tokens)) if (value.expires <= Date.now()) delete this.state.tokens[key]
    if (Object.keys(this.state.tokens).length >= 16384) throw new ApiError('RATE_LIMITED', 429)
    const accessToken = secret(), refreshToken = secret()
    const accessTokenExpiresAt = Date.now() + 60 * 60_000
    this.state.tokens[hash(accessToken)] = { kind: 'access', deviceId, expires: accessTokenExpiresAt, used: false }
    this.state.tokens[hash(refreshToken)] = { kind: 'refresh', deviceId, expires: refreshTokenExpiresAt, used: false }
    this.save()
    return { accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt }
  }
  authenticate(token: string): AuthenticatedDevice {
    const record = this.state.tokens[hash(token)]
    if (!record || record.kind !== 'access') throw new ApiError('AUTH_INVALID', 401)
    if (record.expires <= Date.now()) throw new ApiError('TOKEN_EXPIRED', 401)
    return { ...this.get(record.deviceId), accountId: this.accountId }
  }
  refresh(deviceId: string, token: string) {
    this.get(deviceId)
    const record = this.state.tokens[hash(token)]
    if (!record || record.kind !== 'refresh' || record.deviceId !== deviceId) throw new ApiError('AUTH_INVALID', 401)
    if (record.expires <= Date.now()) throw new ApiError('TOKEN_EXPIRED', 401)
    if (record.used) { this.invalidate(deviceId); throw new ApiError('AUTH_INVALID', 401) }
    record.used = true
    return this.issue(deviceId, record.expires)
  }
  invalidate(deviceId: string): void {
    for (const [key, value] of Object.entries(this.state.tokens)) if (value.deviceId === deviceId) delete this.state.tokens[key]
    this.onInvalidate(deviceId)
    this.save()
  }
  revoke(id: string): void { this.get(id).revoked = true; this.invalidate(id) }
  rename(id: string, name: string): void {
    this.get(id).descriptor.name = name
    this.save()
  }
  touch(id: string, clientVersion?: string, harnessVersion?: string): void {
    const d = this.get(id)
    d.lastSeenAt = Date.now()
    if (clientVersion) d.descriptor.clientVersion = clientVersion.slice(0, 64)
    if (d.descriptor.role === 'host' && harnessVersion) d.descriptor.harnessVersion = harnessVersion.slice(0, 64)
    this.save()
  }
}
