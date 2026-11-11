/**
 * The public gate: an HTTPS listener that authenticates a human, then proxies
 * the request to the loopback dsh web listener.
 *
 * Why a proxy instead of binding dsh itself:
 *   dsh deliberately refuses wildcard binds because the UI can execute code on
 *   the host. Keeping dsh on 127.0.0.1 means the only way in is this gate — if
 *   the gate is down or misconfigured, nothing is exposed.
 *
 * The gate authenticates to dsh exactly once (launch token → browser cookie) and
 * injects that cookie upstream. Clients never see it: responses have Set-Cookie
 * stripped and request cookies are replaced.
 */
import { chmodSync, closeSync, openSync, readFileSync, readSync, statSync, writeFileSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import * as https from 'node:https'
import { createServer as createHttpsServer } from 'node:https'
import { connect as netConnect } from 'node:net'
import { URL } from 'node:url'

import { AuditLog } from './audit.js'
import { buildMessage, sendCodeEmail } from './mailer.js'
import { sendMail } from './smtp.js'
import { emailCodePage, loginPage, messagePage, totpPage } from './pages.js'
import {
  LoginGuard,
  SessionStore,
  DUMMY_HASH,
  hashPassword,
  matchesAllowlist,
  normalizeIp,
  randomDigits,
  randomToken,
  safeEqual,
  sha256Hex,
  verifyPassword,
  verifyTotp,
} from './security.js'
import { lanAddresses, localAddresses, resolveTls } from './tls.js'

const MINUTE = 60_000
const HOUR = 60 * MINUTE

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

/** Headers the gate owns and never forwards from the client. */
const STRIPPED_REQUEST_HEADERS = new Set([
  'host',
  'cookie',
  'origin',
  'referer',
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-forwarded-host',
  'x-forwarded-port',
  'x-real-ip',
  'forwarded',
  'expect',
])

function parseCookies(header) {
  const out = Object.create(null)
  if (typeof header !== 'string' || header.length === 0) return out
  for (const part of header.split(';')) {
    const index = part.indexOf('=')
    if (index === -1) continue
    const name = part.slice(0, index).trim()
    if (name.length === 0) continue
    let value = part.slice(index + 1).trim()
    try {
      value = decodeURIComponent(value)
    } catch {
      /* keep the raw value */
    }
    out[name] = value
  }
  return out
}

function cookie(name, value, { maxAge, secure, httpOnly = true, sameSite = 'Strict' } = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=/']
  if (maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(maxAge / 1000))}`)
  if (httpOnly) parts.push('HttpOnly')
  if (secure) parts.push('Secure')
  if (sameSite !== undefined) parts.push(`SameSite=${sameSite}`)
  return parts.join('; ')
}

function clearCookie(name, { secure } = {}) {
  return cookie(name, '', { maxAge: 0, secure })
}

function wantsHtml(req) {
  const accept = req.headers.accept
  return typeof accept === 'string' && accept.includes('text/html')
}

/** Only same-origin absolute paths are accepted as post-login destinations. */
function safeNext(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) return undefined
  if (!value.startsWith('/') || value.startsWith('//')) return undefined
  if (value.includes('\\') || value.includes('\n') || value.includes('\r')) return undefined
  return value
}

function readBody(req, limitBytes) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let total = 0
    req.on('data', (chunk) => {
      total += chunk.length
      if (total > limitBytes) {
        reject(Object.assign(new Error('body too large'), { code: 'BODY_TOO_LARGE' }))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

function delay(ms) {
  if (ms <= 0) return Promise.resolve()
  return new Promise((resolve) => setTimeout(resolve, ms))
}
/** `ab***@qq.com` — never echo the full delivery address on a public page. */
function maskEmail(to) {
  const address = Array.isArray(to) ? String(to[0] ?? '') : String(to ?? '')
  const at = address.indexOf('@')
  if (at <= 0) return address
  const head = address.slice(0, Math.min(2, at))
  const stars = '*'.repeat(Math.max(1, Math.min(8, at - head.length)))
  return `${head}${stars}${address.slice(at)}`
}

export class GateServer {
  #ctx
  #cfg
  #audit
  #sessions
  #guard
  #pending = new Map()
  #challenges = new Map()
  #lastSendByIp = new Map()
  #sendsByIp = new Map()
  #globalSends = []
  #server
  #tls
  #upstream = null
  #upstreamCookie = null
  #tunnels = new Set()
  #started = false

  constructor(ctx, cfg) {
    this.#ctx = ctx
    this.#cfg = cfg
    this.#audit = new AuditLog(cfg.audit)
    this.#sessions = new SessionStore({
      idleMs: cfg.session.idleMinutes * MINUTE,
      absoluteMs: cfg.session.absoluteHours * HOUR,
      maxSessions: cfg.session.maxSessions,
    })
    this.#guard = new LoginGuard(cfg.bruteForce)
  }

  get listenPort() {
    const address = this.#server?.address()
    return typeof address === 'object' && address !== null ? address.port : this.#cfg.port
  }

  /* ---------------------------------------------------------------- */
  /* Lifecycle                                                        */
  /* ---------------------------------------------------------------- */

  async start() {
    if (this.#started) return
    const cfg = this.#cfg

    this.#tls = await resolveTls(cfg.tls, cfg.host)

    const server = createHttpsServer(
      {
        key: this.#tls.key,
        cert: this.#tls.cert,
        minVersion: cfg.tls.minVersion,
        honorCipherOrder: true,
      },
      (req, res) => {
        this.#handleRequest(req, res).catch((error) => {
          this.#audit.write('gate.error', {
            message: error instanceof Error ? error.message : String(error),
            path: req.url,
          })
          if (!res.headersSent) {
            res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
            res.end('internal error\n')
          } else {
            res.destroy()
          }
        })
      },
    )

    server.headersTimeout = cfg.limits.headersTimeoutMs
    server.requestTimeout = cfg.limits.requestTimeoutMs
    server.keepAliveTimeout = cfg.limits.keepAliveTimeoutMs
    server.maxConnections = cfg.limits.maxConnections
    server.maxRequestsPerSocket = 0

    server.on('upgrade', (req, socket, head) => {
      this.#handleUpgrade(req, socket, head).catch(() => socket.destroy())
    })
    server.on('tlsClientError', () => {})
    server.on('clientError', (error, socket) => {
      if (socket.writable && error.code !== 'ECONNRESET') {
        socket.end('HTTP/1.1 400 Bad Request\r\nconnection: close\r\n\r\n')
      } else {
        socket.destroy()
      }
    })

    await new Promise((resolve, reject) => {
      const onError = (error) => reject(error)
      server.once('error', onError)
      server.listen(cfg.port, cfg.host, () => {
        server.off('error', onError)
        resolve()
      })
    })

    this.#server = server
    this.#started = true

    this.#audit.write('gate.started', {
      bind: `${cfg.host}:${this.listenPort}`,
      tls: this.#tls.source,
      factor: cfg.secondFactor,
      allowlist: cfg.security.ipAllowlist.length,
    })
    const access = this.#accessUrls()
    for (const entry of access.urls) {
      process.stderr.write(`public-gate: reachable at ${entry.url}${entry.lan ? ' (LAN)' : ''}\n`)
    }
    if (this.#tls.regenerated === true) {
      process.stderr.write(
        `public-gate: reissued the self-signed certificate for ${(this.#tls.subjectAltNames ?? []).join(', ')}\n`,
      )
    }
    if (this.#tls.generated) {
      process.stderr.write(
        `public-gate: generated a self-signed certificate (${(this.#tls.subjectAltNames ?? []).join(', ')}); ` +
          `browsers warn until you install a trusted certificate (see ${cfg.paths.tlsDir}/HOW-TO-REPLACE.txt)\n`,
      )
    }
    for (const warning of cfg.warnings ?? []) process.stderr.write(`${warning}\n`)

    try {
      await this.#ensureUpstreamCookie()
    } catch (error) {
      process.stderr.write(
        `public-gate: could not authenticate to the local dsh listener yet: ${error instanceof Error ? error.message : String(error)}\n`,
      )
    }
  }

  async stop() {
    if (!this.#started) return
    this.#started = false
    for (const tunnel of this.#tunnels) {
      try {
        tunnel.destroy()
      } catch {
        /* ignore */
      }
    }
    this.#tunnels.clear()
    const server = this.#server
    this.#server = undefined
    if (server !== undefined) {
      const closed = new Promise((resolve) => server.close(() => resolve()))
      // Idle keep-alive sockets would otherwise hold close() open indefinitely.
      server.closeAllConnections?.()
      await closed
    }
    this.#sessions.destroyAll()
    this.#audit.write('gate.stopped', {})
  }

  /* ---------------------------------------------------------------- */
  /* Upstream session                                                 */
  /* ---------------------------------------------------------------- */

  #resolveUpstream() {
    if (this.#upstream !== null) return this.#upstream
    const cfg = this.#cfg
    let origin
    try {
      origin = new URL(this.#ctx.webServer.getOrigin())
    } catch {
      origin = new URL(`http://${cfg.upstream.host}:${cfg.upstream.port || 3080}/`)
    }
    const port = origin.port === '' ? (origin.protocol === 'https:' ? 443 : 80) : Number(origin.port)
    const host = origin.hostname.replace(/^\[|\]$/g, '')
    const authority =
      cfg.upstream.authority !== '' ? cfg.upstream.authority : `127.0.0.1:${port}`.replace(/:80$/, '')
    this.#upstream = {
      host,
      port,
      secure: origin.protocol === 'https:',
      authority,
      origin: `${origin.protocol}//${origin.host}`,
    }
    return this.#upstream
  }

  /**
   * Exchange the process launch token for a browser cookie on the loopback
   * listener, then reuse that cookie for every proxied request.
   */
  async #ensureUpstreamCookie(force = false) {
    if (this.#upstreamCookie !== null && !force) return this.#upstreamCookie
    const upstream = this.#resolveUpstream()
    const connection = this.#ctx.connection
    if (connection === undefined || typeof connection.authenticatedUrl !== 'function') {
      throw new Error('connection service does not expose authenticatedUrl(); dsh version mismatch?')
    }
    const originUrl = new URL(`${upstream.origin}/`)
    const authenticated = new URL(connection.authenticatedUrl(originUrl.href))
    if (!authenticated.searchParams.has('token')) throw new Error('dsh did not expose a launch token')

    const result = await this.#rawUpstreamRequest({
      method: 'GET',
      path: `/?${authenticated.searchParams.toString()}`,
      headers: { host: upstream.authority, accept: 'text/html' },
    })

    const raw = result.headers['set-cookie']
    const cookies = Array.isArray(raw) ? raw : raw === undefined ? [] : [raw]
    for (const entry of cookies) {
      const pair = String(entry).split(';', 1)[0]
      if (pair.indexOf('=') > 0) {
        this.#upstreamCookie = pair
        this.#audit.write('upstream.authenticated', { authority: upstream.authority })
        return this.#upstreamCookie
      }
    }
    throw new Error(`loopback listener did not return a session cookie (status ${result.status})`)
  }

  #rawUpstreamRequest({ method, path, headers }) {
    const upstream = this.#resolveUpstream()
    return new Promise((resolve, reject) => {
      const client = upstream.secure ? https.request : httpRequest
      const req = client(
        {
          host: upstream.host,
          port: upstream.port,
          method,
          path,
          headers,
          timeout: 20_000,
          rejectUnauthorized: upstream.secure ? false : undefined,
        },
        (res) => {
          res.resume()
          res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers }))
          res.on('error', reject)
        },
      )
      req.on('timeout', () => req.destroy(new Error('upstream timeout')))
      req.on('error', reject)
      req.end()
    })
  }

  /* ---------------------------------------------------------------- */
  /* Request routing                                                  */
  /* ---------------------------------------------------------------- */

  async #handleRequest(req, res) {
    const cfg = this.#cfg
    const clientIp = this.#clientIp(req)

    if (!matchesAllowlist(clientIp, cfg.security.ipAllowlist)) {
      this.#audit.write('access.denied', { reason: 'allowlist', ip: clientIp, path: req.url })
      this.#sendMessage(res, {
        status: 403,
        title: '禁止访问',
        heading: '来源地址不在允许列表内',
        message: 'This client address is not allowed to reach the harness.',
      })
      return
    }

    const url = new URL(req.url ?? '/', 'https://gate.invalid')
    const pathname = url.pathname.replace(/\/+$/, '') || '/'

    if (pathname.startsWith('/__gate/admin/')) return this.#handleAdmin(req, res, pathname, clientIp)
    if (pathname === cfg.loginPath) return this.#handleLogin(req, res, url, clientIp)
    if (pathname === cfg.sendCodePath) return this.#handleSendCode(req, res, url, clientIp)
    if (pathname === cfg.emailCodePath) return this.#handleEmailCode(req, res, url, clientIp)
    if (pathname === cfg.totpPath) return this.#handleTotp(req, res, clientIp)
    if (pathname === cfg.logoutPath) return this.#handleLogout(req, res, clientIp)

    const session = this.#session(req)
    if (session === undefined) {
      this.#rejectUnauthenticated(req, res, url)
      return
    }
    await this.#proxy(req, res, clientIp, session, false)
  }

  #clientIp(req) {
    if (this.#cfg.security.trustProxy === true) {
      const forwarded = req.headers['x-forwarded-for']
      const text = Array.isArray(forwarded) ? forwarded[0] : forwarded
      if (typeof text === 'string' && text.length > 0) return normalizeIp(text.split(',')[0])
    }
    return normalizeIp(req.socket.remoteAddress)
  }

  #session(req) {
    const cookies = parseCookies(req.headers.cookie)
    const id = cookies[this.#cfg.session.cookieName]
    if (id === undefined) return undefined
    return this.#sessions.get(id)
  }

  #rejectUnauthenticated(req, res, url) {
    const path = url.pathname
    if (path.startsWith('/api/') || !wantsHtml(req)) {
      res.writeHead(401, {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        ...this.#securityHeaders(),
      })
      res.end('{"error":"unauthorized"}\n')
      return
    }
    const next = safeNext(`${url.pathname}${url.search}`)
    const location =
      next === undefined || next === '/'
        ? this.#cfg.loginPath
        : `${this.#cfg.loginPath}?next=${encodeURIComponent(next)}`
    res.writeHead(302, { location, 'cache-control': 'no-store', ...this.#securityHeaders() })
    res.end()
  }

  /* ---------------------------------------------------------------- */
  /* Login                                                            */
  /* ---------------------------------------------------------------- */

  #securityHeaders() {
    return {
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
      'strict-transport-security': 'max-age=31536000',
    }
  }

  #htmlHeaders(extra = {}) {
    return {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy':
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      ...this.#securityHeaders(),
      ...extra,
    }
  }

  #sendMessage(res, { status, title, heading, message, action }) {
    res.writeHead(status, this.#htmlHeaders())
    res.end(messagePage({ title, heading, message, status: String(status), action }))
  }

  #loginPage(res, { csrf, error, info, username, next, status = 200 }) {
    const cfg = this.#cfg
    const codeOnly = cfg.email.enabled === true && cfg.email.mode === 'code-only'
    res.writeHead(status, this.#htmlHeaders({ 'set-cookie': cookie('dsh_gate_csrf', csrf, { maxAge: 10 * MINUTE, secure: true }) }))
    res.end(
      loginPage({
        loginPath: cfg.loginPath,
        sendPath: cfg.sendCodePath,
        emailPath: cfg.emailCodePath,
        maskedEmail: maskEmail(cfg.email.to),
        csrf,
        error,
        info,
        username,
        next,
        mode: codeOnly ? 'code-only' : 'password+code',
      }),
    )
  }

  #emailPage(res, { csrf, error, info, next, status = 200 }) {
    const cfg = this.#cfg
    res.writeHead(status, this.#htmlHeaders({ 'set-cookie': cookie('dsh_gate_csrf', csrf, { maxAge: 10 * MINUTE, secure: true }) }))
    res.end(
      emailCodePage({
        emailPath: cfg.emailCodePath,
        sendPath: cfg.sendCodePath,
        csrf,
        maskedEmail: maskEmail(cfg.email.to),
        error,
        info,
        next,
      }),
    )
  }

  /* ---------------- email challenge helpers ---------------- */

  #challenge(req) {
    const id = parseCookies(req.headers.cookie)[this.#cfg.email.challengeCookieName]
    if (id === undefined) return undefined
    const challenge = this.#challenges.get(id)
    if (challenge === undefined) return undefined
    if (challenge.expiresAt <= Date.now()) {
      this.#challenges.delete(id)
      return undefined
    }
    return challenge
  }

  #purgeEmailState(now = Date.now()) {
    for (const [id, challenge] of this.#challenges) {
      if (challenge.expiresAt <= now) this.#challenges.delete(id)
    }
    const hourAgo = now - HOUR
    for (const [ip, stamps] of this.#sendsByIp) {
      const fresh = stamps.filter((value) => value > hourAgo)
      if (fresh.length === 0) this.#sendsByIp.delete(ip)
      else this.#sendsByIp.set(ip, fresh)
    }
    this.#globalSends = this.#globalSends.filter((value) => value > hourAgo)
  }

  /** Whether this source may trigger another email; never throws. */
  #sendBudget(clientIp, now = Date.now()) {
    const cfg = this.#cfg
    this.#purgeEmailState(now)
    const last = this.#lastSendByIp.get(clientIp) ?? 0
    const minGap = cfg.email.send.minIntervalSeconds * 1000
    if (now - last < minGap) return { ok: false, retryAfterMs: minGap - (now - last), reason: 'interval' }
    if ((this.#sendsByIp.get(clientIp) ?? []).length >= cfg.email.send.maxPerHourPerIp) {
      return { ok: false, retryAfterMs: HOUR, reason: 'ip-quota' }
    }
    if (this.#globalSends.length >= cfg.email.send.maxPerHourGlobal) {
      return { ok: false, retryAfterMs: HOUR, reason: 'global-quota' }
    }
    return { ok: true }
  }

  #recordSend(clientIp, now = Date.now()) {
    this.#lastSendByIp.set(clientIp, now)
    const perIp = this.#sendsByIp.get(clientIp) ?? []
    perIp.push(now)
    this.#sendsByIp.set(clientIp, perIp)
    this.#globalSends.push(now)
  }

  /**
   * Create a challenge, deliver the code, and redirect the browser to the code
   * page. Throws when SMTP fails so the caller can render an error.
   */
  async #issueEmailCode(res, req, clientIp, next, redirectTo) {
    const cfg = this.#cfg
    const now = Date.now()
    const code = randomDigits(cfg.email.code.digits)
    const id = randomToken(24)
    const challenge = {
      id,
      ip: clientIp,
      hash: sha256Hex(`${id}:${code}`),
      createdAt: now,
      expiresAt: now + cfg.email.code.ttlMinutes * MINUTE,
      attempts: 0,
      next,
    }

    if (this.#challenges.size >= cfg.email.send.maxChallenges) {
      let oldestId
      let oldest = Infinity
      for (const [key, value] of this.#challenges) {
        if (value.createdAt < oldest) {
          oldest = value.createdAt
          oldestId = key
        }
      }
      if (oldestId !== undefined) this.#challenges.delete(oldestId)
    }
    this.#challenges.set(id, challenge)
    // Count the send before awaiting SMTP so concurrent requests cannot race
    // past the quota.
    this.#recordSend(clientIp, now)

    await sendCodeEmail({
      email: cfg.email,
      smtp: cfg.email.smtp,
      code,
      ttlMinutes: cfg.email.code.ttlMinutes,
      ip: clientIp,
      userAgent: req.headers['user-agent'],
      host: req.headers.host,
      logger: (event, fields) => this.#audit.write(event, fields),
    })
    this.#audit.write('email.code-sent', {
      ip: clientIp,
      to: maskEmail(cfg.email.to),
      expires_in_minutes: cfg.email.code.ttlMinutes,
    })

    res.writeHead(303, {
      location: `${redirectTo}?sent=1`,
      'cache-control': 'no-store',
      'set-cookie': [
        cookie(cfg.email.challengeCookieName, id, { maxAge: cfg.email.code.ttlMinutes * MINUTE, secure: true }),
        cookie('dsh_gate_csrf', randomToken(24), { maxAge: 10 * MINUTE, secure: true }),
      ],
    })
    res.end()
  }

  /* ---------------- login steps ---------------- */

  async #handleLogin(req, res, url, clientIp) {
    const cfg = this.#cfg
    const emailEnabled = cfg.email.enabled === true
    const codeOnly = emailEnabled && cfg.email.mode === 'code-only'

    if (req.method === 'GET' || req.method === 'HEAD') {
      if (this.#session(req) !== undefined) {
        const next = safeNext(url.searchParams.get('next'))
        res.writeHead(302, { location: next ?? '/', 'cache-control': 'no-store' })
        res.end()
        return
      }
      const challenge = codeOnly ? this.#challenge(req) : undefined
      let info
      if (url.searchParams.has('sent')) info = '验证码已发送，请查收邮箱（也看一下垃圾箱）。'
      else if (url.searchParams.has('expired')) info = '会话已过期，请重新登录。'
      else if (codeOnly && challenge === undefined) info = '先点下面的「发送验证码」，再填入收到的 6 位数字。'
      this.#loginPage(res, {
        csrf: randomToken(24),
        info,
        next: safeNext(url.searchParams.get('next')) ?? challenge?.next,
      })
      return
    }

    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'GET, POST', ...this.#securityHeaders() })
      res.end()
      return
    }

    // In code-only mode there is no password form; the login path accepts no POST.
    if (codeOnly) {
      res.writeHead(405, { allow: 'GET', ...this.#securityHeaders() })
      res.end()
      return
    }

    const ipCheck = this.#guard.check(clientIp)
    if (!ipCheck.allowed) {
      const minutes = Math.ceil(ipCheck.retryAfterMs / MINUTE)
      this.#audit.write('login.blocked', { ip: clientIp, reason: ipCheck.reason, retry_minutes: minutes })
      res.writeHead(429, this.#htmlHeaders({ 'retry-after': String(Math.ceil(ipCheck.retryAfterMs / 1000)) }))
      res.end(
        messagePage({
          title: '登录受限制',
          heading: '尝试次数过多',
          message: `Too many failed attempts. Try again in about ${minutes} minute(s). This event has been logged.`,
          status: '429',
        }),
      )
      return
    }

    let body
    try {
      body = await readBody(req, cfg.limits.maxLoginBodyBytes)
    } catch {
      res.writeHead(413, { ...this.#securityHeaders(), connection: 'close' })
      res.end('payload too large\n')
      return
    }

    const form = new URLSearchParams(body)
    const username = (form.get('username') ?? '').slice(0, cfg.limits.loginUserFieldMaxBytes)
    const password = form.get('password') ?? ''
    const csrfBody = form.get('csrf') ?? ''
    const csrfCookie = parseCookies(req.headers.cookie).dsh_gate_csrf

    const csrfOk = csrfCookie !== undefined && csrfBody.length > 0 && safeEqual(csrfBody, csrfCookie)
    const userOk = safeEqual(username, cfg.security.username)
    // Always run the KDF so timing cannot distinguish "wrong user" from
    // "wrong password".
    const passwordOk = await verifyPassword(password, userOk ? cfg.security.passwordHash : DUMMY_HASH)

    if (!csrfOk || !userOk || !passwordOk) {
      const penalty = this.#guard.recordFailure(clientIp)
      await delay(penalty.delayMs)
      this.#audit.write('login.failed', {
        ip: clientIp,
        user: username.slice(0, 64),
        reason: csrfOk ? (userOk ? 'bad-password' : 'bad-user') : 'bad-csrf',
        failures: penalty.failures,
        locked_ms: penalty.lockedMs,
      })
      this.#loginPage(res, {
        status: 401,
        csrf: randomToken(24),
        error: penalty.lockedMs > 0 ? '尝试次数过多，账户已临时锁定。' : '用户名或密码错误。',
        username,
        next: safeNext(form.get('next')),
      })
      return
    }

    const next = safeNext(form.get('next') ?? url.searchParams.get('next'))

    if (emailEnabled) {
      const budget = this.#sendBudget(clientIp)
      if (!budget.ok) {
        const seconds = Math.ceil(budget.retryAfterMs / 1000)
        this.#audit.write('email.send.blocked', { ip: clientIp, reason: budget.reason, retry_seconds: seconds })
        res.writeHead(429, this.#htmlHeaders({ 'retry-after': String(seconds) }))
        res.end(
          messagePage({
            title: '发送受限',
            heading: '验证码请求过于频繁',
            message: `请 ${seconds} 秒后再试。`,
            status: '429',
          }),
        )
        return
      }
      this.#audit.write('login.password-ok', { ip: clientIp, factor: 'email' })
      try {
        await this.#issueEmailCode(res, req, clientIp, next, cfg.emailCodePath)
      } catch (error) {
        this.#audit.write('email.send.failed', {
          ip: clientIp,
          message: error instanceof Error ? error.message : String(error),
        })
        this.#sendMessage(res, {
          status: 502,
          title: '发送失败',
          heading: '验证码邮件发送失败',
          message: 'SMTP 发送失败，请稍后重试或联系管理员查看服务器日志。',
        })
      }
      return
    }

    if (cfg.security.totp.secret.length > 0) {
      const token = randomToken(24)
      this.#pending.set(token, { ip: clientIp, expiresAt: Date.now() + 5 * MINUTE, attempts: 0, next })
      this.#audit.write('login.password-ok', { ip: clientIp, factor: 'totp' })
      res.writeHead(302, {
        location: cfg.totpPath,
        'cache-control': 'no-store',
        'set-cookie': [
          cookie('dsh_gate_pending', token, { maxAge: 5 * MINUTE, secure: true }),
          cookie('dsh_gate_csrf', randomToken(24), { maxAge: 10 * MINUTE, secure: true }),
        ],
      })
      res.end()
      return
    }

    this.#startSession(res, req, clientIp, next, 'password-only')
  }

  async #handleSendCode(req, res, url, clientIp) {
    const cfg = this.#cfg
    if (cfg.email.enabled !== true) {
      res.writeHead(302, { location: cfg.loginPath, 'cache-control': 'no-store' })
      res.end()
      return
    }
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'POST', ...this.#securityHeaders() })
      res.end()
      return
    }

    let body
    try {
      body = await readBody(req, cfg.limits.maxLoginBodyBytes)
    } catch {
      res.writeHead(413, { ...this.#securityHeaders(), connection: 'close' })
      res.end('payload too large\n')
      return
    }
    const form = new URLSearchParams(body)
    const csrfCookie = parseCookies(req.headers.cookie).dsh_gate_csrf
    if (csrfCookie === undefined || !safeEqual(form.get('csrf') ?? '', csrfCookie)) {
      this.#audit.write('email.send.denied', { ip: clientIp, reason: 'bad-csrf' })
      res.writeHead(403, { ...this.#securityHeaders(), 'cache-control': 'no-store' })
      res.end('csrf\n')
      return
    }

    const existing = this.#challenge(req)
    // Password-gated mode: resending requires an in-flight challenge so the
    // endpoint cannot be used to mail-bomb the configured mailbox.
    if (cfg.email.mode === 'password+code' && existing === undefined) {
      res.writeHead(302, { location: cfg.loginPath, 'cache-control': 'no-store' })
      res.end()
      return
    }

    const budget = this.#sendBudget(clientIp)
    if (!budget.ok) {
      const seconds = Math.ceil(budget.retryAfterMs / 1000)
      this.#audit.write('email.send.blocked', { ip: clientIp, reason: budget.reason, retry_seconds: seconds })
      res.setHeader('retry-after', String(seconds))
      this.#loginPage(res, {
        status: 429,
        csrf: randomToken(24),
        next: existing?.next,
        error: `发送太频繁，请 ${seconds} 秒后再试。如果你已经收到过验证码，可以直接在下面输入。`,
      })
      return
    }

    const next = safeNext(form.get('next')) ?? existing?.next
    try {
      await this.#issueEmailCode(res, req, clientIp, next, cfg.email.mode === 'code-only' ? cfg.loginPath : cfg.emailCodePath)
    } catch (error) {
      this.#audit.write('email.send.failed', {
        ip: clientIp,
        message: error instanceof Error ? error.message : String(error),
      })
      this.#sendMessage(res, {
        status: 502,
        title: '发送失败',
        heading: '验证码邮件发送失败',
        message: 'SMTP 发送失败，请稍后重试或联系管理员查看服务器日志。',
      })
    }
  }

  async #handleEmailCode(req, res, url, clientIp) {
    const cfg = this.#cfg
    if (cfg.email.enabled !== true) {
      res.writeHead(302, { location: cfg.loginPath, 'cache-control': 'no-store' })
      res.end()
      return
    }

    const challenge = this.#challenge(req)

    if (req.method === 'GET' || req.method === 'HEAD') {
      if (challenge === undefined) {
        res.writeHead(302, { location: `${cfg.loginPath}?expired=1`, 'cache-control': 'no-store' })
        res.end()
        return
      }
      this.#emailPage(res, {
        csrf: randomToken(24),
        next: challenge.next,
        info: url.searchParams.has('sent') ? '新的验证码已发送。' : undefined,
      })
      return
    }

    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'GET, POST', ...this.#securityHeaders() })
      res.end()
      return
    }

    if (challenge === undefined) {
      res.writeHead(302, { location: `${cfg.loginPath}?expired=1`, 'cache-control': 'no-store' })
      res.end()
      return
    }

    let body
    try {
      body = await readBody(req, cfg.limits.maxLoginBodyBytes)
    } catch {
      res.writeHead(413, { ...this.#securityHeaders(), connection: 'close' })
      res.end('payload too large\n')
      return
    }
    const form = new URLSearchParams(body)
    const csrfCookie = parseCookies(req.headers.cookie).dsh_gate_csrf
    if (csrfCookie === undefined || !safeEqual(form.get('csrf') ?? '', csrfCookie)) {
      this.#audit.write('email.code.failed', { ip: clientIp, reason: 'bad-csrf' })
      res.writeHead(302, { location: `${cfg.loginPath}?expired=1`, 'cache-control': 'no-store' })
      res.end()
      return
    }

    challenge.attempts += 1
    if (challenge.attempts > cfg.email.code.maxAttempts) {
      this.#challenges.delete(challenge.id)
      const penalty = this.#guard.recordFailure(clientIp)
      this.#audit.write('email.code.failed', {
        ip: clientIp,
        reason: 'too-many-attempts',
        locked_ms: penalty.lockedMs,
      })
      await delay(penalty.delayMs)
      res.writeHead(429, this.#htmlHeaders({ 'set-cookie': clearCookie(cfg.email.challengeCookieName, { secure: true }) }))
      res.end(
        messagePage({
          title: '验证失败',
          heading: '验证码错误次数过多',
          message: '请返回登录页重新获取验证码。',
          status: '429',
          action: '本事件已记录。',
        }),
      )
      return
    }

    const submitted = (form.get('code') ?? '').trim()
    const expected = sha256Hex(`${challenge.id}:${submitted}`)
    if (!safeEqual(expected, challenge.hash)) {
      const penalty = this.#guard.recordFailure(clientIp)
      await delay(penalty.delayMs)
      this.#audit.write('email.code.failed', { ip: clientIp, reason: 'mismatch', attempts: challenge.attempts })
      this.#emailPage(res, {
        status: 401,
        csrf: randomToken(24),
        next: challenge.next,
        error: '验证码不正确或已过期。',
      })
      return
    }

    this.#challenges.delete(challenge.id)
    this.#guard.recordSuccess(clientIp)
    this.#startSession(
      res,
      req,
      clientIp,
      challenge.next,
      cfg.email.mode === 'password+code' ? 'password+email-code' : 'email-code',
    )
  }

  #startSession(res, req, clientIp, next, method) {
    const cfg = this.#cfg
    const id = this.#sessions.create({
      ip: clientIp,
      userAgent: String(req.headers['user-agent'] ?? '').slice(0, 200),
      username: cfg.security.username,
    })
    this.#guard.recordSuccess(clientIp)
    this.#audit.write('login.succeeded', { ip: clientIp, method, sessions: this.#sessions.size })
    res.writeHead(303, {
      location: next ?? '/',
      'cache-control': 'no-store',
      'set-cookie': [
        cookie(cfg.session.cookieName, id, { maxAge: cfg.session.absoluteHours * HOUR, secure: true }),
        clearCookie('dsh_gate_pending', { secure: true }),
        clearCookie(cfg.email.challengeCookieName, { secure: true }),
        clearCookie('dsh_gate_csrf', { secure: true }),
      ],
    })
    res.end()
  }

  async #handleTotp(req, res, clientIp) {
    const cfg = this.#cfg
    const cookies = parseCookies(req.headers.cookie)
    const token = cookies.dsh_gate_pending
    const pending = token === undefined ? undefined : this.#pending.get(token)

    if (req.method === 'GET' || req.method === 'HEAD') {
      if (pending === undefined || pending.expiresAt < Date.now()) {
        res.writeHead(302, { location: `${cfg.loginPath}?expired=1`, 'cache-control': 'no-store' })
        res.end()
        return
      }
      const csrf = randomToken(24)
      res.writeHead(200, this.#htmlHeaders({ 'set-cookie': cookie('dsh_gate_csrf', csrf, { maxAge: 10 * MINUTE, secure: true }) }))
      res.end(totpPage({ totpPath: cfg.totpPath, csrf }))
      return
    }

    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'GET, POST', ...this.#securityHeaders() })
      res.end()
      return
    }

    if (pending === undefined || pending.expiresAt < Date.now() || pending.ip !== clientIp) {
      this.#audit.write('totp.failed', { ip: clientIp, reason: 'no-pending' })
      res.writeHead(302, { location: `${cfg.loginPath}?expired=1`, 'cache-control': 'no-store' })
      res.end()
      return
    }

    let body
    try {
      body = await readBody(req, cfg.limits.maxLoginBodyBytes)
    } catch {
      res.writeHead(413, { ...this.#securityHeaders(), connection: 'close' })
      res.end('payload too large\n')
      return
    }
    const form = new URLSearchParams(body)
    const csrfCookie = cookies.dsh_gate_csrf
    if (csrfCookie === undefined || !safeEqual(form.get('csrf') ?? '', csrfCookie)) {
      this.#audit.write('totp.failed', { ip: clientIp, reason: 'bad-csrf' })
      res.writeHead(302, { location: `${cfg.loginPath}?expired=1`, 'cache-control': 'no-store' })
      res.end()
      return
    }

    pending.attempts += 1
    if (pending.attempts > 5) {
      this.#pending.delete(token)
      const penalty = this.#guard.recordFailure(clientIp)
      this.#audit.write('totp.failed', { ip: clientIp, reason: 'too-many-attempts', locked_ms: penalty.lockedMs })
      res.writeHead(429, this.#htmlHeaders())
      res.end(
        messagePage({
          title: '验证失败',
          heading: '验证码尝试次数过多',
          message: 'Restart the login flow and try again.',
          status: '429',
        }),
      )
      return
    }

    const verdict = verifyTotp(cfg.security.totp.secret, form.get('totp') ?? '', {
      digits: cfg.security.totp.digits,
      period: cfg.security.totp.period,
      window: cfg.security.totp.window,
    })

    if (!verdict.ok) {
      const penalty = this.#guard.recordFailure(clientIp)
      await delay(penalty.delayMs)
      this.#audit.write('totp.failed', { ip: clientIp, reason: verdict.reason, failures: penalty.failures })
      const csrf = randomToken(24)
      res.writeHead(401, this.#htmlHeaders({ 'set-cookie': cookie('dsh_gate_csrf', csrf, { maxAge: 10 * MINUTE, secure: true }) }))
      res.end(totpPage({ totpPath: cfg.totpPath, csrf, error: '验证码不正确。' }))
      return
    }

    this.#pending.delete(token)
    this.#startSession(res, req, clientIp, pending.next, 'password+totp')
  }

  async #handleLogout(req, res, clientIp) {
    const cfg = this.#cfg
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'POST', ...this.#securityHeaders() })
      res.end()
      return
    }
    const cookies = parseCookies(req.headers.cookie)
    const sessionId = cookies[cfg.session.cookieName]
    const session = sessionId === undefined ? undefined : this.#sessions.get(sessionId)

    const csrfBody = await readBody(req, 4096).catch(() => '')
    const csrf = new URLSearchParams(csrfBody).get('csrf') ?? ''
    const csrfCookie = cookies.dsh_gate_csrf
    if (csrfCookie !== undefined && csrf.length > 0 && !safeEqual(csrf, csrfCookie)) {
      res.writeHead(403, this.#securityHeaders())
      res.end('csrf\n')
      return
    }

    if (session !== undefined) {
      this.#sessions.destroy(session.id)
      this.#audit.write('logout', { ip: clientIp })
    }
    res.writeHead(303, {
      location: cfg.loginPath,
      'cache-control': 'no-store',
      'set-cookie': [clearCookie(cfg.session.cookieName, { secure: true }), clearCookie('dsh_gate_csrf', { secure: true })],
    })
    res.end()
  }

  /* ---------------------------------------------------------------- */
  /* Settings API — used by the in-UI settings section                 */
  /* ---------------------------------------------------------------- */

  #json(res, status, payload) {
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...this.#securityHeaders(),
    })
    res.end(`${JSON.stringify(payload)}\n`)
  }

  /** Last `limit` audit records, newest first. */
  #recentAudit(limit = 12) {
    try {
      const file = this.#cfg.audit.file
      const size = statSync(file).size
      const start = Math.max(0, size - 32 * 1024)
      const fd = openSync(file, 'r')
      const buffer = Buffer.alloc(size - start)
      try {
        readSync(fd, buffer, 0, buffer.length, start)
      } finally {
        closeSync(fd)
      }
      return buffer
        .toString('utf8')
        .split('\n')
        .filter((line) => line.trim().length > 0)
        .slice(-limit)
        .map((line) => {
          try {
            return JSON.parse(line)
          } catch {
            return undefined
          }
        })
        .filter((entry) => entry !== undefined)
        .reverse()
    } catch {
      return []
    }
  }

  /** Every address a client can reach this gate on. */
  #accessUrls() {
    const cfg = this.#cfg
    const port = this.listenPort
    const wildcard = cfg.host === '0.0.0.0' || cfg.host === '::'
    const addresses = wildcard ? localAddresses() : [cfg.host]
    const lan = new Set(lanAddresses())
    const urls = addresses.map((address) => ({ url: `https://${address}:${port}`, lan: lan.has(address) }))
    return { port, bind: cfg.host, urls }
  }

  #adminStatus() {
    const cfg = this.#cfg
    return {
      access: this.#accessUrls(),
      listen: {
        host: cfg.host,
        port: this.listenPort,
        tls: this.#tls?.source ?? 'unknown',
        generated: this.#tls?.generated === true,
      },
      configFile: cfg.configFile,
      secondFactor: cfg.secondFactor,
      username: cfg.security.username,
      allowlist: cfg.security.ipAllowlist,
      security: {
        hasPassword: cfg.security.passwordHash.length > 0,
        totpEnabled: cfg.security.totp.secret.length > 0,
        allowPasswordOnly: cfg.security.allowPasswordOnly === true,
      },
      email: {
        enabled: cfg.email.enabled === true,
        mode: cfg.email.mode,
        to: cfg.email.to,
        from: cfg.email.from,
        smtpHost: cfg.email.smtp.host,
        smtpPort: cfg.email.smtp.port,
        smtpSecure: cfg.email.smtp.secure === true,
        codeTtlMinutes: cfg.email.code.ttlMinutes,
        minIntervalSeconds: cfg.email.send.minIntervalSeconds,
      },
      session: {
        idleMinutes: cfg.session.idleMinutes,
        absoluteHours: cfg.session.absoluteHours,
        maxSessions: cfg.session.maxSessions,
      },
      recent: this.#recentAudit(12),
    }
  }

  /** Validate, apply live, and persist a settings patch. */
  async #applyAdminSettings(patch, clientIp) {
    const cfg = this.#cfg
    const changes = {}

    if (patch.emailTo !== undefined) {
      const list = String(patch.emailTo)
        .split(',')
        .map((value) => value.trim())
        .filter((value) => value.length > 0)
      if (list.length === 0) throw new Error('至少需要一个收件邮箱')
      for (const address of list) {
        if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(address)) throw new Error(`邮箱格式不正确：${address}`)
      }
      cfg.email.to = list
      changes.to = list
    }

    if (patch.sessionDays !== undefined) {
      const days = Number(patch.sessionDays)
      if (!Number.isFinite(days) || days < 0.05 || days > 365) throw new Error('登录有效期需在 0.05 ~ 365 天之间')
      cfg.session.absoluteHours = Math.max(1, Math.round(days * 24))
      cfg.session.idleMinutes = Math.max(1, Math.round(days * 24 * 60))
      this.#sessions.absoluteMs = cfg.session.absoluteHours * HOUR
      this.#sessions.idleMs = cfg.session.idleMinutes * MINUTE
      changes.sessionDays = days
    }

    if (patch.newPassword !== undefined && String(patch.newPassword).length > 0) {
      const password = String(patch.newPassword)
      if (password.length < 12) throw new Error('密码至少 12 位（这是唯一的口令防线，请用长密码）')
      if (password.length > 512) throw new Error('密码过长')
      cfg.security.passwordHash = await hashPassword(password)
      changes.passwordChanged = true
    }

    if (patch.authMode !== undefined) {
      const mode = String(patch.authMode)
      if (mode !== 'code-only' && mode !== 'password+code') throw new Error('登录方式只能是 code-only 或 password+code')
      if (mode === 'password+code' && cfg.security.passwordHash.length === 0) {
        throw new Error('先设置密码，再切换为「密码 + 邮箱验证码」')
      }
      if (cfg.email.enabled !== true) throw new Error('邮箱验证码未启用，无法切换登录方式')
      cfg.email.mode = mode
      changes.authMode = mode
    }

    if (patch.codeTtlMinutes !== undefined) {
      const ttl = Number(patch.codeTtlMinutes)
      if (!Number.isFinite(ttl) || ttl < 1 || ttl > 60) throw new Error('验证码有效期需在 1 ~ 60 分钟之间')
      cfg.email.code.ttlMinutes = Math.round(ttl)
      changes.codeTtlMinutes = cfg.email.code.ttlMinutes
    }

    if (patch.resendSeconds !== undefined) {
      const seconds = Number(patch.resendSeconds)
      if (!Number.isFinite(seconds) || seconds < 0 || seconds > 600) throw new Error('重发间隔需在 0 ~ 600 秒之间')
      cfg.email.send.minIntervalSeconds = Math.round(seconds)
      changes.resendSeconds = cfg.email.send.minIntervalSeconds
    }

    if (Object.keys(changes).length === 0) return { changes, persisted: true }

    // Persist next to the live config; a missing/merged-only config still gets
    // the live values applied, and the response says so.
    let persisted = true
    try {
      const file = cfg.configFile
      const current = JSON.parse(readFileSync(file, 'utf8'))
      current.session = {
        ...(current.session ?? {}),
        idleMinutes: cfg.session.idleMinutes,
        absoluteHours: cfg.session.absoluteHours,
      }
      current.email = {
        ...(current.email ?? {}),
        mode: cfg.email.mode,
        to: cfg.email.to,
        code: { ...(current.email?.code ?? {}), ttlMinutes: cfg.email.code.ttlMinutes },
        send: { ...(current.email?.send ?? {}), minIntervalSeconds: cfg.email.send.minIntervalSeconds },
      }
      if (changes.passwordChanged === true) {
        current.security = { ...(current.security ?? {}), passwordHash: cfg.security.passwordHash }
      }
      writeFileSync(file, `${JSON.stringify(current, null, 2)}\n`, { mode: 0o600 })
      try {
        chmodSync(file, 0o600)
      } catch {
        /* best effort */
      }
    } catch (error) {
      persisted = false
      this.#audit.write('admin.persist-failed', {
        ip: clientIp,
        message: error instanceof Error ? error.message : String(error),
      })
    }
    this.#audit.write('admin.settings-updated', { ip: clientIp, changes, persisted })
    return { changes, persisted }
  }

  async #handleAdmin(req, res, pathname, clientIp) {
    if (this.#session(req) === undefined) {
      this.#json(res, 401, { error: '会话已失效，请刷新页面重新登录' })
      return
    }
    const origin = req.headers.origin
    if (typeof origin === 'string' && origin.length > 0 && origin !== `https://${req.headers.host}`) {
      this.#json(res, 403, { error: 'origin mismatch' })
      return
    }

    if (pathname === '/__gate/admin/status') {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        this.#json(res, 405, { error: 'method not allowed' })
        return
      }
      this.#json(res, 200, this.#adminStatus())
      return
    }

    if (req.method !== 'POST' || req.headers['x-dsh-gate'] !== 'settings') {
      this.#json(res, 403, { error: 'request rejected' })
      return
    }

    let body
    try {
      body = await readBody(req, 64 * 1024)
    } catch {
      this.#json(res, 413, { error: 'body too large' })
      return
    }
    let patch = {}
    if (body.trim().length > 0) {
      try {
        patch = JSON.parse(body)
      } catch {
        this.#json(res, 400, { error: 'invalid JSON' })
        return
      }
    }

    if (pathname === '/__gate/admin/settings') {
      try {
        const applied = await this.#applyAdminSettings(patch, clientIp)
        this.#json(res, 200, { ok: true, changes: applied.changes, persisted: applied.persisted, status: this.#adminStatus() })
      } catch (error) {
        this.#json(res, 400, { error: error instanceof Error ? error.message : String(error) })
      }
      return
    }

    if (pathname === '/__gate/admin/test-email') {
      const cfg = this.#cfg
      if (cfg.email.enabled !== true) {
        this.#json(res, 400, { error: '邮箱验证码未启用' })
        return
      }
      try {
        const result = await sendMail({
          host: cfg.email.smtp.host,
          port: cfg.email.smtp.port,
          secure: cfg.email.smtp.secure,
          requireAuth: cfg.email.smtp.requireAuth,
          user: cfg.email.smtp.user,
          pass: cfg.email.smtp.pass,
          from: cfg.email.from,
          to: cfg.email.to,
          subject: cfg.email.subject,
          text: buildMessage({
            from: cfg.email.from,
            fromName: cfg.email.fromName,
            to: cfg.email.to,
            subject: cfg.email.subject,
            text: `这是一封来自 dsh-public-gate 设置页的测试邮件。\n\n时间：${new Date().toISOString()}`,
          }),
          timeoutMs: cfg.email.smtp.timeoutMs,
          tlsInsecure: cfg.email.smtp.tlsInsecure === true,
        })
        this.#audit.write('admin.test-email', { ip: clientIp, to: cfg.email.to.join(',') })
        this.#json(res, 200, { ok: true, accepted: result.accepted, response: result.response })
      } catch (error) {
        this.#audit.write('admin.test-email-failed', { ip: clientIp, message: error instanceof Error ? error.message : String(error) })
        this.#json(res, 502, { error: error instanceof Error ? error.message : String(error) })
      }
      return
    }

    this.#json(res, 404, { error: 'not found' })
  }

  /* ---------------------------------------------------------------- */
  /* Proxying                                                         */
  /* ---------------------------------------------------------------- */

  #upstreamRequestHeaders(req, clientIp) {
    const upstream = this.#resolveUpstream()
    const headers = {}
    for (const [name, value] of Object.entries(req.headers)) {
      if (value === undefined) continue
      if (STRIPPED_REQUEST_HEADERS.has(name)) continue
      if (HOP_BY_HOP.has(name)) continue
      headers[name] = value
    }
    headers.host = upstream.authority
    headers['x-forwarded-for'] = clientIp
    headers['x-forwarded-proto'] = 'https'
    if (typeof req.headers.host === 'string') headers['x-forwarded-host'] = req.headers.host
    if (this.#upstreamCookie !== null) headers.cookie = this.#upstreamCookie

    // dsh's browser-trust fence requires Origin to name the same authority as
    // Host, parsed under the Origin's scheme. The browser's Origin points at
    // this gate, so rewrite it to the loopback authority we connect with.
    const originScheme = upstream.secure ? 'https' : 'http'
    if (typeof req.headers.origin === 'string') headers.origin = `${originScheme}://${upstream.authority}`
    if (typeof req.headers.referer === 'string') {
      try {
        const parsed = new URL(req.headers.referer)
        headers.referer = `${originScheme}://${upstream.authority}${parsed.pathname}${parsed.search}`
      } catch {
        delete headers.referer
      }
    }
    return headers
  }

  async #proxy(req, res, clientIp, session, retried) {
    const upstream = this.#resolveUpstream()
    if (this.#upstreamCookie === null) {
      try {
        await this.#ensureUpstreamCookie()
      } catch (error) {
        this.#audit.write('proxy.upstream-auth-failed', {
          message: error instanceof Error ? error.message : String(error),
        })
        this.#sendMessage(res, {
          status: 502,
          title: '上游不可用',
          heading: '网关无法登录本地 dsh',
          message: 'The local dsh listener did not accept the launch token. Check the dsh log.',
        })
        return
      }
    }

    const headers = this.#upstreamRequestHeaders(req, clientIp)
    const client = upstream.secure ? https.request : httpRequest

    const upstreamReq = client(
      {
        host: upstream.host,
        port: upstream.port,
        method: req.method,
        path: req.url,
        headers,
        timeout: 0,
        rejectUnauthorized: upstream.secure ? false : undefined,
      },
      (upstreamRes) => this.#relayResponse(req, res, upstreamRes, clientIp, session, retried),
    )

    upstreamReq.on('error', (error) => {
      this.#audit.write('proxy.upstream-error', {
        message: error instanceof Error ? error.message : String(error),
        path: req.url,
      })
      if (!res.headersSent) {
        this.#sendMessage(res, {
          status: 502,
          title: '上游不可用',
          heading: '无法连接本地 dsh 服务',
          message: 'The gateway could not reach the local dsh listener.',
        })
      } else {
        res.destroy()
      }
    })

    res.on('close', () => {
      if (!res.writableEnded) upstreamReq.destroy()
    })

    req.pipe(upstreamReq)
  }

  #relayResponse(req, res, upstreamRes, clientIp, session, retried) {
    const status = upstreamRes.statusCode ?? 502

    // Our injected upstream session can expire while dsh keeps running. Re-mint
    // once and replay the request instead of surfacing a bare 401 to the user.
    if (status === 401 && retried !== true && !res.headersSent) {
      upstreamRes.resume()
      this.#ensureUpstreamCookie(true)
        .then(() => this.#proxy(req, res, clientIp, session, true))
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
            res.end('upstream authentication failed\n')
          }
        })
      return
    }

    const headers = {}
    for (const [name, value] of Object.entries(upstreamRes.headers)) {
      if (value === undefined) continue
      if (HOP_BY_HOP.has(name)) continue
      // Never leak the upstream dsh credential to the browser.
      if (name === 'set-cookie') continue
      headers[name] = value
    }
    headers['strict-transport-security'] = 'max-age=31536000'
    headers['x-content-type-options'] = 'nosniff'
    headers['x-frame-options'] = headers['x-frame-options'] ?? 'DENY'

    res.writeHead(status, headers)
    if (req.method === 'HEAD') {
      res.end()
      upstreamRes.resume()
      return
    }
    upstreamRes.pipe(res)
    upstreamRes.on('error', () => res.destroy())
  }

  /* ---------------------------------------------------------------- */
  /* WebSocket upgrades                                               */
  /* ---------------------------------------------------------------- */

  async #handleUpgrade(req, socket, head) {
    const cfg = this.#cfg
    const clientIp = this.#clientIp(req)
    const url = new URL(req.url ?? '/', 'https://gate.invalid')

    if (!matchesAllowlist(clientIp, cfg.security.ipAllowlist)) {
      socket.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n')
      return
    }
    if (!url.pathname.startsWith('/api/')) {
      socket.end('HTTP/1.1 404 Not Found\r\nconnection: close\r\n\r\n')
      return
    }
    if (this.#session(req) === undefined) {
      this.#audit.write('ws.denied', { ip: clientIp, path: url.pathname })
      socket.end('HTTP/1.1 401 Unauthorized\r\nconnection: close\r\n\r\n')
      return
    }
    if (this.#tunnels.size >= cfg.limits.maxUpgrades) {
      socket.end('HTTP/1.1 503 Service Unavailable\r\nconnection: close\r\n\r\n')
      return
    }
    if (this.#upstreamCookie === null) {
      try {
        await this.#ensureUpstreamCookie()
      } catch {
        socket.end('HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n')
        return
      }
    }

    const upstream = this.#resolveUpstream()
    const headers = this.#upstreamRequestHeaders(req, clientIp)
    headers.connection = 'Upgrade'
    headers.upgrade = req.headers.upgrade ?? 'websocket'

    let raw = `${req.method} ${req.url} HTTP/1.1\r\n`
    for (const [name, value] of Object.entries(headers)) {
      if (value === undefined) continue
      if (Array.isArray(value)) for (const item of value) raw += `${name}: ${item}\r\n`
      else raw += `${name}: ${value}\r\n`
    }
    raw += '\r\n'

    const upstreamSocket = netConnect({ host: upstream.host, port: upstream.port }, () => {
      upstreamSocket.write(raw)
      if (head !== undefined && head.length > 0) upstreamSocket.write(head)
      upstreamSocket.pipe(socket)
      socket.pipe(upstreamSocket)
    })

    this.#tunnels.add(upstreamSocket)
    let closed = false
    const cleanup = () => {
      if (closed) return
      closed = true
      this.#tunnels.delete(upstreamSocket)
      upstreamSocket.destroy()
      socket.destroy()
    }
    upstreamSocket.on('error', cleanup)
    upstreamSocket.on('close', cleanup)
    socket.on('error', cleanup)
    socket.on('close', cleanup)
    upstreamSocket.setTimeout(0)
  }
}
