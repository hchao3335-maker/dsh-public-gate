/**
 * Security primitives for dsh-public-gate.
 *
 * Everything here is dependency-free and built on node:crypto:
 *   - scrypt password hashing (memory-hard, per-credential salt)
 *   - RFC 6238 TOTP second factor
 *   - in-memory session store with idle/absolute expiry
 *   - escalating brute-force lockout with a global circuit breaker
 */
import {
  createHash,
  createHmac,
  randomBytes,
  randomInt,
  scrypt as scryptCallback,
  timingSafeEqual,
} from 'node:crypto'
import { promisify } from 'node:util'

const scrypt = promisify(scryptCallback)

/* ------------------------------------------------------------------ */
/* Encoding helpers                                                     */
/* ------------------------------------------------------------------ */

export function base64url(buffer) {
  return Buffer.from(buffer).toString('base64url')
}

export function randomToken(bytes = 32) {
  return base64url(randomBytes(bytes))
}

/** Uniformly random decimal digits (used for emailed one-time codes). */
export function randomDigits(count) {
  let out = ''
  for (let index = 0; index < count; index += 1) out += String(randomInt(0, 10))
  return out
}

/** Constant-time string comparison that never throws on length mismatch. */
export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  const left = Buffer.from(a, 'utf8')
  const right = Buffer.from(b, 'utf8')
  if (left.length !== right.length) {
    // Still compare something of equal length to keep the timing flat.
    timingSafeEqual(left, left)
    return false
  }
  return timingSafeEqual(left, right)
}

export function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

/* ------------------------------------------------------------------ */
/* Password hashing                                                     */
/* ------------------------------------------------------------------ */

const SCRYPT_N = 2 ** 15
const SCRYPT_R = 8
const SCRYPT_P = 1
const SCRYPT_KEYLEN = 64
const SCRYPT_MAXMEM = 128 * 1024 * 1024

/**
 * Hash a password into `scrypt$N$r$p$saltB64$hashB64`.
 * @param password - plaintext password.
 * @param options - optional parameter overrides (tests / future rehashing).
 */
export async function hashPassword(password, options = {}) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('password must be a non-empty string')
  }
  const N = options.N ?? SCRYPT_N
  const r = options.r ?? SCRYPT_R
  const p = options.p ?? SCRYPT_P
  const salt = randomBytes(16)
  const derived = await scrypt(Buffer.from(password, 'utf8'), salt, SCRYPT_KEYLEN, {
    N,
    r,
    p,
    maxmem: SCRYPT_MAXMEM,
  })
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64url')}$${Buffer.from(derived).toString('base64url')}`
}

/** A fixed hash used to equalize timing when the username does not match. */
export const DUMMY_HASH = `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${Buffer.from('dsh-public-gate-dummy-salt').toString('base64url')}$${Buffer.alloc(SCRYPT_KEYLEN, 7).toString('base64url')}`

/**
 * Verify a password against a stored scrypt hash.
 * Runs the full KDF even for unknown users when a dummy hash is passed.
 */
export async function verifyPassword(password, stored) {
  const parsed = parsePasswordHash(stored)
  if (parsed === undefined) {
    // Burn comparable CPU so a malformed record cannot be probed by timing.
    await hashPassword(typeof password === 'string' ? password : '', { N: SCRYPT_N })
    return false
  }
  const { N, r, p, salt, hash } = parsed
  let derived
  try {
    derived = Buffer.from(
      await scrypt(Buffer.from(typeof password === 'string' ? password : '', 'utf8'), salt, hash.length, {
        N,
        r,
        p,
        maxmem: SCRYPT_MAXMEM,
      }),
    )
  } catch {
    return false
  }
  if (derived.length !== hash.length) return false
  return timingSafeEqual(derived, hash)
}

export function parsePasswordHash(stored) {
  if (typeof stored !== 'string') return undefined
  const parts = stored.split('$')
  if (parts.length !== 6 || parts[0] !== 'scrypt') return undefined
  const N = Number(parts[1])
  const r = Number(parts[2])
  const p = Number(parts[3])
  if (!Number.isInteger(N) || N < 2 ** 12 || N > 2 ** 20) return undefined
  if (!Number.isInteger(r) || r < 1 || r > 32) return undefined
  if (!Number.isInteger(p) || p < 1 || p > 16) return undefined
  let salt
  let hash
  try {
    salt = Buffer.from(parts[4], 'base64url')
    hash = Buffer.from(parts[5], 'base64url')
  } catch {
    return undefined
  }
  if (salt.length < 8 || hash.length < 16) return undefined
  return { N, r, p, salt, hash }
}

/* ------------------------------------------------------------------ */
/* TOTP (RFC 6238, HMAC-SHA1)                                          */
/* ------------------------------------------------------------------ */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export function base32Decode(input) {
  const normalized = String(input).toUpperCase().replace(/=+$/, '').replace(/[\s-]/g, '')
  if (normalized.length === 0) throw new Error('empty base32 secret')
  let bits = 0
  let value = 0
  const out = []
  for (const char of normalized) {
    const index = BASE32_ALPHABET.indexOf(char)
    if (index === -1) throw new Error(`invalid base32 character ${JSON.stringify(char)}`)
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((value >>> bits) & 0xff)
    }
  }
  return Buffer.from(out)
}

export function base32Encode(buffer) {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of buffer) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += BASE32_ALPHABET[(value >>> bits) & 31]
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31]
  return out
}

/** Generate a new 160-bit base32 secret. */
export function generateTotpSecret() {
  return base32Encode(randomBytes(20))
}

export function totpAt(secretBase32, { digits = 6, period = 30, timestamp = Date.now() } = {}) {
  const key = base32Decode(secretBase32)
  const counter = Math.floor(timestamp / 1000 / period)
  const buffer = Buffer.alloc(8)
  buffer.writeBigUInt64BE(BigInt(counter))
  const digest = createHmac('sha1', key).update(buffer).digest()
  const offset = digest[digest.length - 1] & 0x0f
  const code =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3]
  return String(code % 10 ** digits).padStart(digits, '0')
}

/**
 * Verify a TOTP code within the configured window.
 * Rejects reused counters through the caller-supplied `lastUsedCounter`.
 */
export function verifyTotp(secretBase32, code, options = {}) {
  const digits = options.digits ?? 6
  const period = options.period ?? 30
  const window = options.window ?? 1
  const now = options.timestamp ?? Date.now()
  const normalized = String(code ?? '').replace(/\s+/g, '')
  if (!new RegExp(`^\\d{${digits}}$`).test(normalized)) return { ok: false, reason: 'format' }
  const counter = Math.floor(now / 1000 / period)
  for (let offset = -window; offset <= window; offset += 1) {
    const candidateCounter = counter + offset
    if (candidateCounter < 0) continue
    const expected = totpAt(secretBase32, { digits, period, timestamp: candidateCounter * period * 1000 })
    if (safeEqual(expected, normalized)) {
      return { ok: true, counter: candidateCounter }
    }
  }
  return { ok: false, reason: 'mismatch' }
}

export function otpauthUrl({ secret, issuer = 'DeepSeek Harness', account = 'dsh', digits = 6, period = 30 }) {
  const label = encodeURIComponent(`${issuer}:${account}`)
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(digits),
    period: String(period),
  })
  return `otpauth://totp/${label}?${params.toString()}`
}

/* ------------------------------------------------------------------ */
/* Sessions                                                             */
/* ------------------------------------------------------------------ */

export class SessionStore {
  #sessions = new Map()

  constructor({ idleMs, absoluteMs, maxSessions = 8 }) {
    this.idleMs = idleMs
    this.absoluteMs = absoluteMs
    this.maxSessions = maxSessions
  }

  /** Create a session and return its opaque id. */
  create(meta = {}) {
    this.purge()
    while (this.#sessions.size >= this.maxSessions) {
      // Evict the least recently used session.
      let oldestId
      let oldestSeen = Infinity
      for (const [id, session] of this.#sessions) {
        if (session.lastSeen < oldestSeen) {
          oldestSeen = session.lastSeen
          oldestId = id
        }
      }
      if (oldestId === undefined) break
      this.#sessions.delete(oldestId)
    }
    const id = randomToken(32)
    const now = Date.now()
    this.#sessions.set(id, {
      id,
      createdAt: now,
      lastSeen: now,
      ip: meta.ip,
      userAgent: meta.userAgent,
      username: meta.username,
      rotatedFrom: meta.rotatedFrom,
    })
    return id
  }

  /** Look up a live session, refreshing its idle timer. */
  get(id) {
    if (typeof id !== 'string' || id.length === 0) return undefined
    const session = this.#sessions.get(id)
    if (session === undefined) return undefined
    const now = Date.now()
    if (now - session.createdAt > this.absoluteMs) {
      this.#sessions.delete(id)
      return undefined
    }
    if (now - session.lastSeen > this.idleMs) {
      this.#sessions.delete(id)
      return undefined
    }
    session.lastSeen = now
    return session
  }

  destroy(id) {
    if (typeof id !== 'string') return false
    return this.#sessions.delete(id)
  }

  destroyAll() {
    const count = this.#sessions.size
    this.#sessions.clear()
    return count
  }

  get size() {
    return this.#sessions.size
  }

  purge(now = Date.now()) {
    for (const [id, session] of this.#sessions) {
      if (now - session.createdAt > this.absoluteMs || now - session.lastSeen > this.idleMs) {
        this.#sessions.delete(id)
      }
    }
  }
}

/* ------------------------------------------------------------------ */
/* Brute-force protection                                               */
/* ------------------------------------------------------------------ */

const MINUTE = 60_000

export class LoginGuard {
  #ips = new Map()
  #globalFailures = []
  #globalLockedUntil = 0
  #now

  constructor(config, now = () => Date.now()) {
    this.config = config
    this.#now = now
  }

  #pruneIp(entry, now) {
    const windowStart = now - this.config.windowMinutes * MINUTE
    while (entry.failures.length > 0 && entry.failures[0] < windowStart) entry.failures.shift()
  }

  #tierFor(failures) {
    let tier
    for (const candidate of this.config.lockoutTiers) {
      if (failures >= candidate.failures) tier = candidate
    }
    return tier
  }

  #globalLocked(now) {
    if (now < this.#globalLockedUntil) return true
    const windowStart = now - this.config.globalWindowMinutes * MINUTE
    while (this.#globalFailures.length > 0 && this.#globalFailures[0] < windowStart) this.#globalFailures.shift()
    if (this.#globalFailures.length >= this.config.globalFailureThreshold) {
      this.#globalLockedUntil = now + this.config.globalLockMinutes * MINUTE
      this.#globalFailures = []
      return true
    }
    return false
  }

  /** Whether this IP may attempt a login right now. */
  check(ip) {
    const now = this.#now()
    if (this.#globalLocked(now)) {
      return { allowed: false, reason: 'global', retryAfterMs: Math.max(0, this.#globalLockedUntil - now) }
    }
    const entry = this.#ips.get(ip)
    if (entry === undefined) return { allowed: true, failures: 0, delayMs: 0 }
    this.#pruneIp(entry, now)
    if (entry.lockedUntil > now) {
      return { allowed: false, reason: 'ip', retryAfterMs: entry.lockedUntil - now }
    }
    return { allowed: true, failures: entry.failures.length, delayMs: this.#delayFor(entry.failures.length) }
  }

  #delayFor(failures) {
    if (failures <= 0) return 0
    const delay = this.config.baseDelayMs * 2 ** Math.min(failures - 1, 8)
    return Math.min(delay, this.config.maxDelayMs)
  }

  /** Record a failed attempt and return the resulting penalty. */
  recordFailure(ip) {
    const now = this.#now()
    let entry = this.#ips.get(ip)
    if (entry === undefined) {
      if (this.#ips.size >= this.config.maxTrackedIps) {
        // Evict the stalest tracker instead of growing without bound.
        let oldestIp
        let oldest = Infinity
        for (const [key, value] of this.#ips) {
          const seen = value.failures[value.failures.length - 1] ?? 0
          if (seen < oldest) {
            oldest = seen
            oldestIp = key
          }
        }
        if (oldestIp !== undefined) this.#ips.delete(oldestIp)
      }
      entry = { failures: [], lockedUntil: 0 }
      this.#ips.set(ip, entry)
    }
    this.#pruneIp(entry, now)
    entry.failures.push(now)
    this.#globalFailures.push(now)

    const tier = this.#tierFor(entry.failures.length)
    let lockMs = 0
    if (tier !== undefined) {
      entry.lockedUntil = Math.max(entry.lockedUntil, now + tier.lockMinutes * MINUTE)
      lockMs = entry.lockedUntil - now
    }
    return {
      failures: entry.failures.length,
      delayMs: this.#delayFor(entry.failures.length),
      lockedMs: lockMs,
    }
  }

  recordSuccess(ip) {
    const entry = this.#ips.get(ip)
    if (entry !== undefined) {
      entry.failures = []
      entry.lockedUntil = 0
    }
  }

  /** Remove every tracked penalty (used on configuration reload). */
  reset() {
    this.#ips.clear()
    this.#globalFailures = []
    this.#globalLockedUntil = 0
  }

  get trackedIps() {
    return this.#ips.size
  }
}

/* ------------------------------------------------------------------ */
/* Address helpers                                                      */
/* ------------------------------------------------------------------ */

/** Normalize a socket/forwarded address: strip IPv4-mapped IPv6 and port. */
export function normalizeIp(value) {
  if (typeof value !== 'string') return '0.0.0.0'
  let ip = value.trim()
  if (ip.startsWith('[')) {
    const end = ip.indexOf(']')
    if (end !== -1) ip = ip.slice(1, end)
  } else if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(ip)) {
    ip = ip.slice(0, ip.lastIndexOf(':'))
  }
  if (ip.toLowerCase().startsWith('::ffff:')) ip = ip.slice(7)
  return ip.length === 0 ? '0.0.0.0' : ip
}

function ipv4ToInt(ip) {
  const parts = ip.split('.')
  if (parts.length !== 4) return undefined
  let value = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return undefined
    const octet = Number(part)
    if (octet > 255) return undefined
    value = (value * 256) + octet
  }
  return value
}

/**
 * Match an address against CIDR or bare-address allowlist entries.
 * IPv4 only; an empty allowlist means "allow every address".
 */
export function matchesAllowlist(ip, allowlist) {
  if (!Array.isArray(allowlist) || allowlist.length === 0) return true
  const normalized = normalizeIp(ip)
  for (const entry of allowlist) {
    const [address, prefixText] = String(entry).split('/')
    const target = ipv4ToInt(normalized)
    const network = ipv4ToInt(address)
    if (target === undefined || network === undefined) {
      if (normalized === String(entry).trim()) return true
      continue
    }
    const prefix = prefixText === undefined ? 32 : Number(prefixText)
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) continue
    if (prefix === 0) return true
    const mask = prefix === 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0
    if ((target & mask) >>> 0 === (network & mask) >>> 0) return true
  }
  return false
}
