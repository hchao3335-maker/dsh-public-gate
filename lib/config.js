/**
 * Configuration loading and validation for dsh-public-gate.
 *
 * Sources, low to high precedence:
 *   1. built-in defaults
 *   2. $DSH_HOME/public-gate/config.json   (secrets live here, mode 0600)
 *   3. the plugin row's `config:` in cordis.patch.yml
 *
 * Credentials are mandatory: when none are configured the plugin refuses to
 * activate (fail closed) rather than exposing an unauthenticated proxy.
 */
import { existsSync, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

export const GATE_DIR_NAME = 'public-gate'

/** Resolve the DSH home directory the same way the harness does. */
export function dshHome(env = process.env) {
  const configured = env.DSH_HOME
  if (typeof configured === 'string' && configured.length > 0) return configured
  return join(homedir(), '.dsh')
}

export function gatePaths(env = process.env) {
  const home = dshHome(env)
  const dir = join(home, GATE_DIR_NAME)
  return {
    home,
    dir,
    configFile: join(dir, 'config.json'),
    tlsDir: join(dir, 'tls'),
    certFile: join(dir, 'tls', 'cert.pem'),
    keyFile: join(dir, 'tls', 'key.pem'),
    auditFile: join(dir, 'audit.log'),
  }
}

const DEFAULT_UPSTREAM_HOST = '127.0.0.1'

export function defaults(env = process.env) {
  const paths = gatePaths(env)
  return {
    // Public listener. 0.0.0.0 keeps working across address changes; the
    // upstream dsh listener stays on loopback either way.
    host: '0.0.0.0',
    port: 8443,
    // Path prefix for the gate's own pages (obscurity only, not a boundary).
    loginPath: '/__gate/login',
    logoutPath: '/__gate/logout',
    totpPath: '/__gate/totp',
    sendCodePath: '/__gate/send-code',
    emailCodePath: '/__gate/email',
    tls: {
      certFile: paths.certFile,
      keyFile: paths.keyFile,
      // Generate a self-signed certificate on first start when the configured
      // files are missing. SANs default to the machine's non-loopback IPv4s.
      autoGenerate: true,
      subjectAltNames: [],
      minVersion: 'TLSv1.2',
    },
    upstream: {
      // Overridable for exotic layouts; by default we reuse the webServer's
      // own origin (which is loopback by construction).
      host: DEFAULT_UPSTREAM_HOST,
      port: 0,
      // The upstream Host/Origin the proxy sends. Loopback hosts pass dsh's
      // browser-trust fence without configuring trustedHosts.
      authority: '',
    },
    security: {
      username: '',
      // Format: scrypt$N$r$p$saltB64$hashB64 (see security.js).
      passwordHash: '',
      // RFC 6238 secret (base32). When absent the gate refuses to run unless
      // allowPasswordOnly is explicitly true.
      totp: {
        secret: '',
        issuer: 'DeepSeek Harness',
        account: '',
        digits: 6,
        period: 30,
        window: 1,
      },
      allowPasswordOnly: false,
      // Optional source-address allowlist, CIDR or bare addresses.
      ipAllowlist: [],
      // Set when an upstream TLS-terminating proxy fronts the gate.
      trustProxy: false,
      // Emulate loopback inside the dsh client (settings persistence, file open).
      emulateLoopback: true,
    },
    session: {
      cookieName: 'dsh_gate_session',
      idleMinutes: 120,
      absoluteHours: 12,
      maxSessions: 8,
    },
    // Email one-time code, used instead of (or before) the TOTP step.
    email: {
      enabled: false,
      // 'code-only'      : the login page only asks for the emailed code
      // 'password+code'  : password first, then the emailed code
      mode: 'code-only',
      smtp: {
        host: '',
        port: 465,
        secure: true,
        requireAuth: true,
        user: '',
        pass: '',
        timeoutMs: 20_000,
        // Accept a self-signed mail server certificate (self-hosted SMTP only).
        tlsInsecure: false,
      },
      from: '',
      fromName: 'DeepSeek Harness',
      to: [],
      subject: 'DeepSeek Harness 登录验证码',
      code: {
        digits: 6,
        ttlMinutes: 10,
        maxAttempts: 5,
      },
      send: {
        minIntervalSeconds: 30,
        maxPerHourPerIp: 10,
        maxPerHourGlobal: 120,
        maxChallenges: 512,
      },
      challengeCookieName: 'dsh_gate_challenge',
    },
    limits: {
      // Bounds the login form body; the real API traffic is not buffered here.
      maxLoginBodyBytes: 8 * 1024,
      headersTimeoutMs: 30_000,
      requestTimeoutMs: 300_000,
      keepAliveTimeoutMs: 65_000,
      maxConnections: 512,
      maxUpgrades: 64,
      loginUserFieldMaxBytes: 128,
    },
    bruteForce: {
      // Sliding window for counting failures.
      windowMinutes: 30,
      // Escalating lockouts, first match wins (attempts -> lockout minutes).
      lockoutTiers: [
        { failures: 5, lockMinutes: 1 },
        { failures: 10, lockMinutes: 15 },
        { failures: 15, lockMinutes: 1440 },
      ],
      // Per-IP cap on simultaneous tracked entries (memory safety).
      maxTrackedIps: 4096,
      // Cluster-wide circuit breaker against distributed guessing.
      globalWindowMinutes: 10,
      globalFailureThreshold: 300,
      globalLockMinutes: 5,
      // Progressive response delay: 200ms * 2^(n-1), capped.
      baseDelayMs: 200,
      maxDelayMs: 4000,
    },
    audit: {
      file: paths.auditFile,
      maxBytes: 5 * 1024 * 1024,
      // Syslog-formatted line on stderr for journald / fail2ban.
      syslog: true,
    },
  }
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function deepMerge(base, override) {
  if (!isPlainObject(override)) return base
  const out = Array.isArray(base) ? [...base] : { ...base }
  for (const [key, value] of Object.entries(override)) {
    if (value === undefined) continue
    if (isPlainObject(value) && isPlainObject(out[key])) out[key] = deepMerge(out[key], value)
    else out[key] = value
  }
  return out
}

function readJson(file, { optional = false } = {}) {
  if (!existsSync(file)) {
    if (optional) return undefined
    throw new Error(`public-gate: configuration file not found: ${file}`)
  }
  let text
  try {
    text = readFileSync(file, 'utf8')
  } catch (error) {
    throw new Error(`public-gate: cannot read ${file}: ${error instanceof Error ? error.message : String(error)}`)
  }
  try {
    return JSON.parse(text)
  } catch (error) {
    throw new Error(`public-gate: ${file} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`)
  }
}

function warnIfLoosePermissions(file) {
  try {
    const mode = statSync(file).mode & 0o777
    if ((mode & 0o077) !== 0) {
      return `public-gate: ${file} is readable by group/other (mode ${mode.toString(8)}); chmod 600 it`
    }
  } catch {
    /* ignore */
  }
  return undefined
}

function assert(condition, message) {
  if (!condition) throw new Error(`public-gate: ${message}`)
}

function parsePort(value, field) {
  const port = Number(value)
  assert(Number.isInteger(port) && port > 0 && port <= 65_535, `${field} must be an integer in 1..65535, got ${JSON.stringify(value)}`)
  return port
}

function normalizeLoginPath(value) {
  assert(typeof value === 'string' && value.startsWith('/'), 'loginPath must start with "/"')
  assert(!value.startsWith('//'), 'loginPath must not start with "//"')
  assert(!value.startsWith('/api'), 'loginPath must not shadow dsh\'s /api routes')
  return value.replace(/\/+$/, '')
}

/**
 * Resolve the effective configuration.
 * @param rowConfig - the plugin row's `config` object (may be undefined).
 * @param env - environment (for DSH_HOME, overridable in tests).
 * @returns validated configuration plus the config-file path that was read.
 */
export function loadConfig(rowConfig, env = process.env) {
  const paths = gatePaths(env)
  const fileConfig = readJson(paths.configFile, { optional: true }) ?? {}
  const warnings = []
  const permissionWarning = warnIfLoosePermissions(paths.configFile)
  if (permissionWarning !== undefined) warnings.push(permissionWarning)

  const merged = deepMerge(deepMerge(defaults(env), fileConfig), rowConfig)

  merged.port = parsePort(merged.port, 'port')
  assert(typeof merged.host === 'string' && merged.host.length > 0, 'host must be a non-empty string')
  merged.loginPath = normalizeLoginPath(merged.loginPath)
  merged.logoutPath = normalizeLoginPath(merged.logoutPath)
  merged.totpPath = normalizeLoginPath(merged.totpPath)
  merged.sendCodePath = normalizeLoginPath(merged.sendCodePath)
  merged.emailCodePath = normalizeLoginPath(merged.emailCodePath)
  const gatePathsInUse = [merged.loginPath, merged.logoutPath, merged.totpPath, merged.sendCodePath, merged.emailCodePath]
  assert(new Set(gatePathsInUse).size === gatePathsInUse.length, 'login/logout/totp/sendCode/emailCode paths must all differ')

  assert(isPlainObject(merged.tls), 'tls must be an object')
  assert(typeof merged.tls.minVersion === 'string', 'tls.minVersion must be a string')
  assert(Array.isArray(merged.tls.subjectAltNames), 'tls.subjectAltNames must be an array')

  assert(isPlainObject(merged.security), 'security must be an object')
  assert(typeof merged.security.username === 'string', 'security.username must be a string')
  assert(typeof merged.security.passwordHash === 'string', 'security.passwordHash must be a string')
  assert(Array.isArray(merged.security.ipAllowlist), 'security.ipAllowlist must be an array')

  const totp = merged.security.totp
  assert(isPlainObject(totp), 'security.totp must be an object')
  assert(Number.isInteger(totp.digits) && totp.digits >= 6 && totp.digits <= 10, 'security.totp.digits must be 6..10')
  assert(Number.isInteger(totp.period) && totp.period >= 10 && totp.period <= 120, 'security.totp.period must be 10..120')
  assert(Number.isInteger(totp.window) && totp.window >= 0 && totp.window <= 3, 'security.totp.window must be 0..3')

  assert(isPlainObject(merged.session), 'session must be an object')
  assert(merged.session.idleMinutes > 0, 'session.idleMinutes must be positive')
  assert(merged.session.absoluteHours > 0, 'session.absoluteHours must be positive')
  assert(merged.session.maxSessions >= 1, 'session.maxSessions must be at least 1')
  // A session may never outlive its absolute limit even if idle is longer.
  assert(merged.session.absoluteHours * 60 >= 1, 'session.absoluteHours is too small to be usable')

  /* ---------------- email one-time code ---------------- */
  assert(isPlainObject(merged.email), 'email must be an object')
  const email = merged.email
  assert(email.mode === 'code-only' || email.mode === 'password+code', "email.mode must be 'code-only' or 'password+code'")
  assert(isPlainObject(email.smtp), 'email.smtp must be an object')
  assert(isPlainObject(email.code), 'email.code must be an object')
  assert(isPlainObject(email.send), 'email.send must be an object')
  assert(Number.isInteger(email.code.digits) && email.code.digits >= 4 && email.code.digits <= 10, 'email.code.digits must be 4..10')
  assert(email.code.ttlMinutes > 0 && email.code.ttlMinutes <= 60, 'email.code.ttlMinutes must be 1..60')
  assert(Number.isInteger(email.code.maxAttempts) && email.code.maxAttempts >= 1, 'email.code.maxAttempts must be a positive integer')
  assert(email.send.minIntervalSeconds >= 0, 'email.send.minIntervalSeconds must not be negative')
  assert(email.send.maxPerHourPerIp >= 1, 'email.send.maxPerHourPerIp must be at least 1')
  assert(email.send.maxPerHourGlobal >= 1, 'email.send.maxPerHourGlobal must be at least 1')
  if (email.enabled === true) {
    assert(typeof email.smtp.host === 'string' && email.smtp.host.length > 0, 'email.smtp.host is required when email.enabled is true')
    assert(Number.isInteger(email.smtp.port) && email.smtp.port > 0 && email.smtp.port <= 65_535, 'email.smtp.port must be 1..65535')
    assert(Array.isArray(email.to) && email.to.length > 0, 'email.to must list at least one recipient')
    for (const recipient of email.to) {
      assert(typeof recipient === 'string' && recipient.includes('@'), `email.to entry ${JSON.stringify(recipient)} is not an address`)
    }
    const effectiveFrom = email.from !== '' ? email.from : email.smtp.user
    assert(typeof effectiveFrom === 'string' && effectiveFrom.includes('@'), 'email.from (or email.smtp.user) must be an address')
    email.from = effectiveFrom
    if (email.smtp.requireAuth !== false) {
      assert(typeof email.smtp.user === 'string' && email.smtp.user.length > 0, 'email.smtp.user is required when email.smtp.requireAuth is true')
      assert(typeof email.smtp.pass === 'string' && email.smtp.pass.length > 0, 'email.smtp.pass is required when email.smtp.requireAuth is true')
    }
  }

  assert(isPlainObject(merged.bruteForce), 'bruteForce must be an object')
  assert(Array.isArray(merged.bruteForce.lockoutTiers) && merged.bruteForce.lockoutTiers.length > 0, 'bruteForce.lockoutTiers must not be empty')
  for (const tier of merged.bruteForce.lockoutTiers) {
    assert(Number.isInteger(tier.failures) && tier.failures > 0, 'bruteForce.lockoutTiers[].failures must be a positive integer')
    assert(tier.lockMinutes > 0, 'bruteForce.lockoutTiers[].lockMinutes must be positive')
  }
  merged.bruteForce.lockoutTiers = [...merged.bruteForce.lockoutTiers].sort((a, b) => a.failures - b.failures)

  // Second factor precedence: email code > TOTP > password only.
  merged.secondFactor = merged.email.enabled === true ? 'email' : merged.security.totp.secret.length > 0 ? 'totp' : 'none'

  if (merged.secondFactor === 'none' && merged.security.allowPasswordOnly !== true) {
    throw new Error(
      'public-gate: no second factor configured. Enable email codes (email.enabled: true plus SMTP settings), ' +
        'add a TOTP secret with "node bin/gate-tool.mjs set-totp", or set security.allowPasswordOnly: true to accept password-only logins',
    )
  }

  // A password is only mandatory when password-only mode or the first of a
  // two-step flow needs it; pure emailed-code logins have no password at all.
  const passwordRequired = merged.secondFactor !== 'email' || merged.email.mode === 'password+code'
  if (passwordRequired && merged.security.passwordHash.length === 0) {
    throw new Error(
      'public-gate: no passwordHash configured; run "node bin/gate-tool.mjs init" to create ' +
        `${paths.configFile} (or set security.passwordHash in the plugin row)`,
    )
  }
  if (merged.security.passwordHash.length > 0) {
    assert(
      merged.security.passwordHash.startsWith('scrypt$'),
      'security.passwordHash must use the scrypt$ format produced by bin/gate-tool.mjs',
    )
  }
  if (merged.security.username.length === 0) {
    merged.security.username = 'admin'
  }

  merged.configFile = paths.configFile
  merged.paths = paths
  merged.warnings = warnings
  return merged
}
