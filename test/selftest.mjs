/**
 * Local self-test for dsh-public-gate's pure modules. Run with plain node.
 *   node test/selftest.mjs
 */
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  LoginGuard,
  SessionStore,
  base32Decode,
  generateTotpSecret,
  hashPassword,
  matchesAllowlist,
  normalizeIp,
  safeEqual,
  totpAt,
  verifyPassword,
  verifyTotp,
} from '../lib/security.js'

let passed = 0
function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed += 1
      console.log(`ok - ${name}`)
    })
    .catch((error) => {
      console.error(`FAIL - ${name}`)
      throw error
    })
}

/* ---------------- password ---------------- */
await test('scrypt hash verifies the right password', async () => {
  const hash = await hashPassword('correct horse battery staple')
  assert.match(hash, /^scrypt\$32768\$8\$1\$/)
  assert.equal(await verifyPassword('correct horse battery staple', hash), true)
})

await test('scrypt rejects a wrong password', async () => {
  const hash = await hashPassword('correct horse battery staple', { N: 2 ** 12 })
  assert.equal(await verifyPassword('wrong', hash), false)
})

await test('malformed hash fails closed', async () => {
  assert.equal(await verifyPassword('x', 'not-a-hash'), false)
  assert.equal(await verifyPassword('x', 'scrypt$0$8$1$aaaa$bbbb'), false)
})

await test('safeEqual is length-safe', () => {
  assert.equal(safeEqual('abc', 'abc'), true)
  assert.equal(safeEqual('abc', 'abcd'), false)
  assert.equal(safeEqual('', ''), true)
})

/* ---------------- TOTP ---------------- */
await test('base32 round trip', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
  const bytes = base32Decode(secret)
  assert.equal(bytes.length, 20)
})

await test('RFC 6238 test vector (SHA1, T=59s, 8 digits)', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' // "12345678901234567890"
  assert.equal(totpAt(secret, { digits: 8, timestamp: 59_000 }), '94287082')
  assert.equal(totpAt(secret, { digits: 8, timestamp: 1111111109_000 }), '07081804')
  assert.equal(totpAt(secret, { digits: 8, timestamp: 2000000000_000 }), '69279037')
})

await test('verifyTotp accepts the current window and rejects others', () => {
  const secret = generateTotpSecret()
  const now = 1_800_000_000_000
  const code = totpAt(secret, { digits: 6, timestamp: now })
  assert.equal(verifyTotp(secret, code, { digits: 6, window: 1, timestamp: now }).ok, true)
  // 10 minutes later is outside a +/-1 window.
  assert.equal(verifyTotp(secret, code, { digits: 6, window: 1, timestamp: now + 600_000 }).ok, false)
  assert.equal(verifyTotp(secret, 'abcdef', { timestamp: now }).ok, false)
})

/* ---------------- sessions ---------------- */
await test('session store enforces idle and absolute expiry', () => {
  const store = new SessionStore({ idleMs: 1000, absoluteMs: 3000, maxSessions: 2 })
  const id = store.create({ ip: '1.2.3.4' })
  assert.ok(store.get(id))
  // Simulate idle expiry by rewriting the timestamps.
  const session = store.get(id)
  session.lastSeen = Date.now() - 2000
  assert.equal(store.get(id), undefined)

  const id2 = store.create({})
  const session2 = store.get(id2)
  session2.createdAt = Date.now() - 4000
  assert.equal(store.get(id2), undefined)
})

await test('session store evicts beyond maxSessions', () => {
  const store = new SessionStore({ idleMs: 60_000, absoluteMs: 60_000, maxSessions: 2 })
  const a = store.create({})
  const b = store.create({})
  const c = store.create({})
  assert.equal(store.size, 2)
  assert.equal(store.get(a), undefined)
  assert.ok(store.get(b))
  assert.ok(store.get(c))
})

/* ---------------- brute force ---------------- */
await test('lockout escalates and then resets on success', () => {
  let now = 1_700_000_000_000
  const guard = new LoginGuard(
    {
      windowMinutes: 30,
      lockoutTiers: [
        { failures: 3, lockMinutes: 1 },
        { failures: 5, lockMinutes: 15 },
      ],
      maxTrackedIps: 16,
      globalWindowMinutes: 10,
      globalFailureThreshold: 100,
      globalLockMinutes: 5,
      baseDelayMs: 100,
      maxDelayMs: 1000,
    },
    () => now,
  )
  guard.recordFailure('9.9.9.9')
  guard.recordFailure('9.9.9.9')
  assert.equal(guard.check('9.9.9.9').allowed, true)
  guard.recordFailure('9.9.9.9')
  const locked = guard.check('9.9.9.9')
  assert.equal(locked.allowed, false)
  assert.ok(locked.retryAfterMs > 0)

  now += 61_000
  assert.equal(guard.check('9.9.9.9').allowed, true)
  guard.recordSuccess('9.9.9.9')
  assert.equal(guard.check('9.9.9.9').failures, 0)
})

await test('progressive delay is capped', () => {
  const guard = new LoginGuard({
    windowMinutes: 30,
    lockoutTiers: [{ failures: 100, lockMinutes: 1 }],
    maxTrackedIps: 8,
    globalWindowMinutes: 10,
    globalFailureThreshold: 1000,
    globalLockMinutes: 5,
    baseDelayMs: 200,
    maxDelayMs: 1500,
  })
  let delay = 0
  for (let i = 0; i < 6; i += 1) delay = guard.recordFailure('8.8.8.8').delayMs
  assert.equal(delay, 1500)
})

await test('global circuit breaker trips', () => {
  let now = 1_700_000_000_000
  const guard = new LoginGuard(
    {
      windowMinutes: 30,
      lockoutTiers: [{ failures: 1000, lockMinutes: 1 }],
      maxTrackedIps: 2048,
      globalWindowMinutes: 10,
      globalFailureThreshold: 5,
      globalLockMinutes: 5,
      baseDelayMs: 1,
      maxDelayMs: 1,
    },
    () => now,
  )
  for (let i = 0; i < 5; i += 1) guard.recordFailure(`10.0.0.${i}`)
  assert.equal(guard.check('10.0.0.99').allowed, false)
  now += 6 * 60_000
  assert.equal(guard.check('10.0.0.99').allowed, true)
})

/* ---------------- addresses ---------------- */
await test('normalizeIp strips mapped prefixes and ports', () => {
  assert.equal(normalizeIp('::ffff:1.2.3.4'), '1.2.3.4')
  assert.equal(normalizeIp('1.2.3.4:5678'), '1.2.3.4')
  assert.equal(normalizeIp('[::1]:443'), '::1')
  assert.equal(normalizeIp(undefined), '0.0.0.0')
})

await test('CIDR allowlist', () => {
  assert.equal(matchesAllowlist('1.2.3.4', []), true)
  assert.equal(matchesAllowlist('1.2.3.4', ['1.2.3.0/24']), true)
  assert.equal(matchesAllowlist('1.2.4.4', ['1.2.3.0/24']), false)
  assert.equal(matchesAllowlist('5.5.5.5', ['5.5.5.5']), true)
  assert.equal(matchesAllowlist('5.5.5.6', ['5.5.5.5']), false)
})

/* ---------------- config ---------------- */
await test('config fails closed without credentials', async () => {
  const home = mkdtempSync(join(tmpdir(), 'gate-'))
  process.env.DSH_HOME = home
  const { loadConfig } = await import('../lib/config.js?fresh=1')
  assert.throws(() => loadConfig(undefined), /no second factor configured/)
  rmSync(home, { recursive: true, force: true })
})

await test('config requires TOTP unless explicitly allowed', async () => {
  const home = mkdtempSync(join(tmpdir(), 'gate-'))
  process.env.DSH_HOME = home
  mkdirSync(join(home, 'public-gate'), { recursive: true })
  const hash = await hashPassword('abcd')
  writeFileSync(
    join(home, 'public-gate', 'config.json'),
    JSON.stringify({ security: { username: 'admin', passwordHash: hash } }),
  )
  const { loadConfig } = await import('../lib/config.js?fresh=2')
  assert.throws(() => loadConfig(undefined), /no second factor configured/)
  const ok = loadConfig({ security: { allowPasswordOnly: true } })
  assert.equal(ok.security.allowPasswordOnly, true)
  rmSync(home, { recursive: true, force: true })
})

console.log(`\n${passed} checks passed`)
