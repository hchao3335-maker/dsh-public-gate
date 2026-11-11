/**
 * End-to-end test of the emailed one-time-code login (code-only mode).
 *
 * A fake TLS SMTP server and a fake dsh upstream are used, so no real mailbox
 * or dsh instance is needed.
 *
 *   node test/email-integration.mjs
 *
 * On Windows set OPENSSL_CONF to a valid openssl.cnf before running (the test
 * generates a throwaway certificate for the fake SMTP server).
 */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createServer as createHttpServer } from 'node:http'
import { createServer as createTlsServer } from 'node:tls'
import * as https from 'node:https'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { GateServer } from '../lib/gate.js'
import { loadConfig } from '../lib/config.js'

const UPSTREAM_PORT = 18090
const GATE_PORT = 18453
const SMTP_PORT = 18454
const RECIPIENT = 'owner@example.com'

let passed = 0
function check(name, ok, detail = '') {
  assert.ok(ok, `${name}${detail ? ` [${detail}]` : ''}`)
  passed += 1
  console.log(`ok - ${name}`)
}

/* --------------------------- fake TLS SMTP --------------------------- */
function startFakeSmtp(tlsOptions) {
  const messages = []
  const connections = new Set()
  const server = createTlsServer(tlsOptions, (socket) => {
    connections.add(socket)
    socket.on('close', () => connections.delete(socket))
    socket.on('error', () => {})
    let buffer = ''
    let inData = false
    let data = ''
    let authenticated = false
    socket.write('220 fake.test ESMTP ready\r\n')

    const handleLine = (line) => {
      const upper = line.toUpperCase()
      if (upper.startsWith('EHLO') || upper.startsWith('HELO')) {
        socket.write('250-fake.test\r\n250-AUTH PLAIN LOGIN\r\n250-SIZE 10485760\r\n250 8BITMIME\r\n')
        return
      }
      if (upper.startsWith('AUTH PLAIN')) {
        authenticated = true
        socket.write('235 2.7.0 Authentication successful\r\n')
        return
      }
      if (upper.startsWith('AUTH LOGIN')) {
        socket.write('334 VXNlcm5hbWU6\r\n')
        return
      }
      if (upper.startsWith('MAIL FROM')) return void socket.write('250 2.1.0 Ok\r\n')
      if (upper.startsWith('RCPT TO')) return void socket.write('250 2.1.5 Ok\r\n')
      if (upper === 'DATA') {
        inData = true
        data = ''
        socket.write('354 End data with <CR><LF>.<CR><LF>\r\n')
        return
      }
      if (upper === 'QUIT') {
        socket.write('221 Bye\r\n')
        socket.end()
        return
      }
      if (upper === 'RSET') return void socket.write('250 Ok\r\n')
      socket.write('250 Ok\r\n')
    }

    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8')
      for (;;) {
        if (inData) {
          const end = buffer.indexOf('\r\n.\r\n')
          if (end === -1) return
          data += buffer.slice(0, end)
          buffer = buffer.slice(end + 5)
          inData = false
          messages.push({ data, authenticated })
          socket.write('250 2.0.0 Ok: queued\r\n')
          continue
        }
        const index = buffer.indexOf('\r\n')
        if (index === -1) return
        const line = buffer.slice(0, index)
        buffer = buffer.slice(index + 2)
        handleLine(line)
      }
    })
  })
  return new Promise((resolve) =>
    server.listen(SMTP_PORT, '127.0.0.1', () =>
      resolve({
        server,
        messages,
        close: () => {
          for (const socket of connections) socket.destroy()
          server.close()
        },
      }),
    ),
  )
}

/* ------------------------------ fake dsh ----------------------------- */
function startFakeUpstream() {
  const server = createHttpServer((req, res) => {
    const url = new URL(req.url, 'http://placeholder')
    if (req.headers.host !== `127.0.0.1:${UPSTREAM_PORT}`) {
      res.writeHead(403)
      res.end('untrusted host')
      return
    }
    const cookies = req.headers.cookie ?? ''
    if (url.pathname === '/' && url.searchParams.has('token')) {
      res.writeHead(303, { location: './', 'set-cookie': 'dsh_session=s3cret; Path=/; HttpOnly' })
      res.end()
      return
    }
    if (!cookies.includes('dsh_session=s3cret')) {
      res.writeHead(401)
      res.end('dsh web authentication required')
      return
    }
    if (url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      res.end('<html>INDEX</html>')
      return
    }
    res.writeHead(404)
    res.end('not found')
  })
  return new Promise((resolve) => server.listen(UPSTREAM_PORT, '127.0.0.1', () => resolve(server)))
}

/* ---------------------------- https client --------------------------- */
function request({ method = 'GET', path = '/', headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { host: '127.0.0.1', port: GATE_PORT, method, path, headers, rejectUnauthorized: false },
      (res) => {
        const chunks = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () =>
          resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }),
        )
      },
    )
    req.on('error', reject)
    if (body !== undefined) req.write(body)
    req.end()
  })
}

function setCookies(response) {
  const raw = response.headers['set-cookie']
  if (raw === undefined) return []
  return Array.isArray(raw) ? raw : [raw]
}

function mergeCookies(jar, response) {
  for (const entry of setCookies(response)) {
    const pair = entry.split(';', 1)[0]
    const name = pair.slice(0, pair.indexOf('='))
    const value = pair.slice(pair.indexOf('=') + 1)
    if (value === '') delete jar[name]
    else jar[name] = value
  }
  return jar
}

const cookieHeader = (jar) => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ')
const csrfFrom = (html) => html.match(/name="csrf" value="([^"]+)"/)?.[1]

function codeFromMessage(data) {
  const separator = data.indexOf('\r\n\r\n')
  assert.ok(separator > 0, 'message has header/body separator')
  const body = Buffer.from(data.slice(separator + 4).replace(/\r\n/g, ''), 'base64').toString('utf8')
  const match = body.match(/^ {4}(\d{6})$/m)
  assert.ok(match, `code line present in message body:\n${body}`)
  return match[1]
}

/* -------------------------------- main ------------------------------- */
const tempHome = mkdtempSync(join(tmpdir(), 'dsh-gate-email-'))
process.env.DSH_HOME = tempHome

let upstream
let smtp
let gate

try {
  // Throwaway certificate for the fake SMTP server.
  const keyPath = join(tempHome, 'smtp-key.pem')
  const certPath = join(tempHome, 'smtp-cert.pem')
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
    '-keyout', keyPath, '-out', certPath,
  ], { stdio: 'pipe' })
  smtp = await startFakeSmtp({ key: readFileSync(keyPath), cert: readFileSync(certPath) })
  upstream = await startFakeUpstream()

  mkdirSync(join(tempHome, 'public-gate'), { recursive: true })
  writeFileSync(join(tempHome, 'public-gate', 'config.json'), '{}\n')

  const cfg = loadConfig({
    host: '127.0.0.1',
    port: GATE_PORT,
    tls: {
      certFile: join(tempHome, 'gate', 'cert.pem'),
      keyFile: join(tempHome, 'gate', 'key.pem'),
      autoGenerate: true,
      subjectAltNames: ['IP:127.0.0.1'],
    },
    security: { username: 'admin' },
    email: {
      enabled: true,
      mode: 'code-only',
      smtp: {
        host: '127.0.0.1',
        port: SMTP_PORT,
        secure: true,
        requireAuth: true,
        user: 'sender@example.com',
        pass: 'smtp-secret',
        timeoutMs: 10_000,
        tlsInsecure: true,
      },
      from: 'sender@example.com',
      fromName: 'DSH Gate',
      to: [RECIPIENT],
      code: { digits: 6, ttlMinutes: 10, maxAttempts: 5 },
      send: { minIntervalSeconds: 60, maxPerHourPerIp: 10, maxPerHourGlobal: 100, maxChallenges: 64 },
    },
    audit: { file: join(tempHome, 'audit.log'), maxBytes: 1024 * 1024, syslog: false },
  })
  assert.equal(cfg.secondFactor, 'email', 'email is the active second factor')

  const ctx = {
    webServer: { getOrigin: () => `http://127.0.0.1:${UPSTREAM_PORT}/` },
    connection: { authenticatedUrl: (url) => `${url}${url.includes('?') ? '&' : '?'}token=test-launch-token` },
  }
  gate = new GateServer(ctx, cfg)
  await gate.start()

  const jar = {}

  // 1. anonymous navigation -> login
  const anonymous = await request({ path: '/', headers: { accept: 'text/html' } })
  check('anonymous request redirects to the login page', anonymous.status === 302 && anonymous.headers.location === '/__gate/login')

  // 2. code-only login page offers the send button and no password field
  const loginPage = await request({ path: '/__gate/login', headers: { accept: 'text/html' } })
  mergeCookies(jar, loginPage)
  const csrf = csrfFrom(loginPage.body)
  check('login page renders a send-code button', loginPage.status === 200 && loginPage.body.includes('发送验证码'))
  check('login page has no password field in code-only mode', !loginPage.body.includes('name="password"'))
  check('login page carries a CSRF token', typeof csrf === 'string' && jar.dsh_gate_csrf !== undefined)
  check('login page also shows the code field', loginPage.body.includes('name="code"'))

  // 3. send-code requires the CSRF token
  const badSend = await request({
    method: 'POST',
    path: '/__gate/send-code',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar) },
    body: 'csrf=wrong',
  })
  check('send-code rejects a bad CSRF token', badSend.status === 403)
  check('no email was sent for the rejected request', smtp.messages.length === 0)

  // 4. requesting a code delivers exactly one message
  const send = await request({
    method: 'POST',
    path: '/__gate/send-code',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar) },
    body: `csrf=${encodeURIComponent(csrf)}`,
  })
  mergeCookies(jar, send)
  check('send-code redirects back to the combined login page', send.status === 303 && send.headers.location === '/__gate/login?sent=1')
  check('a challenge cookie is issued', typeof jar.dsh_gate_challenge === 'string')
  check('exactly one email was delivered', smtp.messages.length === 1, `count=${smtp.messages.length}`)
  check('the SMTP session authenticated', smtp.messages[0].authenticated === true)
  check('message is addressed to the configured recipient', smtp.messages[0].data.includes(RECIPIENT))

  const code = codeFromMessage(smtp.messages[0].data)

  // 5. code page renders
  const emailPage = await request({ path: '/__gate/email', headers: { accept: 'text/html', cookie: cookieHeader(jar) } })
  mergeCookies(jar, emailPage)
  check('code page renders', emailPage.status === 200 && emailPage.body.includes('验证码'))
  const emailCsrf = csrfFrom(emailPage.body)
  check('recipient is masked on the page', emailPage.body.includes('ow') && !emailPage.body.includes(RECIPIENT))

  // 6. wrong code is rejected
  const wrong = await request({
    method: 'POST',
    path: '/__gate/email',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar) },
    body: `code=000000&csrf=${encodeURIComponent(emailCsrf)}`,
  })
  mergeCookies(jar, wrong)
  const wrongCsrf = csrfFrom(wrong.body)
  check('wrong code is rejected', wrong.status === 401)
  check('no session exists after a wrong code', jar.dsh_gate_session === undefined)

  // 7. correct code logs in
  const good = await request({
    method: 'POST',
    path: '/__gate/email',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar) },
    body: `code=${encodeURIComponent(code)}&csrf=${encodeURIComponent(wrongCsrf)}`,
  })
  mergeCookies(jar, good)
  check('correct code issues a session', good.status === 303 && typeof jar.dsh_gate_session === 'string')
  check('challenge cookie is cleared after login', jar.dsh_gate_challenge === undefined)

  // 8. the session proxies the harness
  const index = await request({ path: '/', headers: { accept: 'text/html', cookie: cookieHeader(jar) } })
  check('authenticated page is proxied from dsh', index.status === 200 && index.body.includes('INDEX'))

  // 9. codes are single-use
  const replay = await request({
    method: 'POST',
    path: '/__gate/email',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `dsh_gate_challenge=stale` },
    body: `code=${encodeURIComponent(code)}&csrf=${encodeURIComponent(wrongCsrf)}`,
  })
  check('a consumed challenge cannot be replayed', replay.status === 302)

  // 10. resend rate limit kicks in
  const jar2 = {}
  const page2 = await request({ path: '/__gate/login', headers: { accept: 'text/html' } })
  mergeCookies(jar2, page2)
  const csrf2 = csrfFrom(page2.body)
  await request({
    method: 'POST',
    path: '/__gate/send-code',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar2) },
    body: `csrf=${encodeURIComponent(csrf2)}`,
  })
  const tooSoon = await request({
    method: 'POST',
    path: '/__gate/send-code',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar2) },
    body: `csrf=${encodeURIComponent(csrf2)}`,
  })
  check('immediate resend is rate limited', tooSoon.status === 429, `status=${tooSoon.status}`)
  // 11. settings API used by the in-UI settings section
  const anonymousStatus = await request({ path: '/__gate/admin/status', headers: { accept: 'application/json' } })
  check('admin status requires a session', anonymousStatus.status === 401, String(anonymousStatus.status))

  const statusResponse = await request({
    path: '/__gate/admin/status',
    headers: { accept: 'application/json', cookie: cookieHeader(jar) },
  })
  const statusPayload = JSON.parse(statusResponse.body)
  check('admin status reports the email configuration', statusResponse.status === 200 && statusPayload.email.to[0] === RECIPIENT)
  check('admin status reports recent audit events', Array.isArray(statusPayload.recent) && statusPayload.recent.length > 0)

  const forged = await request({
    method: 'POST',
    path: '/__gate/admin/settings',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(jar) },
    body: JSON.stringify({ emailTo: 'attacker@example.com' }),
  })
  check('admin settings rejects requests without the gate header', forged.status === 403, String(forged.status))

  const changed = await request({
    method: 'POST',
    path: '/__gate/admin/settings',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(jar),
      origin: `https://127.0.0.1:${GATE_PORT}`,
      'x-dsh-gate': 'settings',
    },
    body: JSON.stringify({ sessionDays: 3, codeTtlMinutes: 7, resendSeconds: 15 }),
  })
  const changedPayload = JSON.parse(changed.body)
  check('admin settings applies the patch', changed.status === 200 && changedPayload.status.session.absoluteHours === 72)
  check('admin settings updates the code ttl', changedPayload.status.email.codeTtlMinutes === 7)
  check('admin settings updates the resend interval', changedPayload.status.email.minIntervalSeconds === 15)

  const persisted = JSON.parse(readFileSync(join(tempHome, 'public-gate', 'config.json'), 'utf8'))
  check('admin settings persists to config.json', persisted.session.absoluteHours === 72 && persisted.email.send.minIntervalSeconds === 15)

  const badEmail = await request({
    method: 'POST',
    path: '/__gate/admin/settings',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(jar),
      'x-dsh-gate': 'settings',
    },
    body: JSON.stringify({ emailTo: 'not-an-email' }),
  })
  check('admin settings rejects an invalid address', badEmail.status === 400, String(badEmail.status))

  const crossOrigin = await request({
    method: 'POST',
    path: '/__gate/admin/settings',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(jar),
      origin: 'https://evil.example',
      'x-dsh-gate': 'settings',
    },
    body: JSON.stringify({ resendSeconds: 1 }),
  })
  check('admin settings rejects a cross-origin origin header', crossOrigin.status === 403, String(crossOrigin.status))

  // 12. login mode switching and password change
  const post = (payload) =>
    request({
      method: 'POST',
      path: '/__gate/admin/settings',
      headers: {
        'content-type': 'application/json',
        cookie: cookieHeader(jar),
        origin: `https://127.0.0.1:${GATE_PORT}`,
        'x-dsh-gate': 'settings',
      },
      body: JSON.stringify(payload),
    })

  check('fresh install reports no password', statusPayload.security.hasPassword === false)

  const switchWithoutPassword = await post({ authMode: 'password+code' })
  check('cannot switch to password mode without a password', switchWithoutPassword.status === 400, String(switchWithoutPassword.status))

  const shortPassword = await post({ newPassword: 'short' })
  check('rejects a password shorter than 12 characters', shortPassword.status === 400, String(shortPassword.status))

  const setPassword = await post({ newPassword: 'correct-horse-battery' })
  const setPasswordPayload = JSON.parse(setPassword.body)
  check('accepts a strong password', setPassword.status === 200 && setPasswordPayload.changes.passwordChanged === true)
  check('status now reports a password', setPasswordPayload.status.security.hasPassword === true)

  const switchMode = await post({ authMode: 'password+code' })
  const switchPayload = JSON.parse(switchMode.body)
  check('switching to password+code succeeds', switchMode.status === 200 && switchPayload.status.email.mode === 'password+code')

  const passwordLoginPage = await request({ path: '/__gate/login', headers: { accept: 'text/html' } })
  check('login page now asks for a password', passwordLoginPage.body.includes('name="password"'))

  const backToCodeOnly = await post({ authMode: 'code-only' })
  check('switching back to code-only succeeds', backToCodeOnly.status === 200)

  const persistedMode = JSON.parse(readFileSync(join(tempHome, 'public-gate', 'config.json'), 'utf8'))
  check('login mode is persisted', persistedMode.email.mode === 'code-only')
  check('password hash is persisted', typeof persistedMode.security.passwordHash === 'string')
} finally {
  await gate?.stop()
  smtp?.close()
  upstream?.closeAllConnections?.()
  upstream?.close()
  rmSync(tempHome, { recursive: true, force: true })
}

console.log(`\n${passed} email-login checks passed`)
process.exit(passed > 0 ? 0 : 1)
