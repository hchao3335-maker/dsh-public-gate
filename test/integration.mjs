/**
 * Local end-to-end test for the gate against a fake dsh upstream.
 * Exercises: redirect to login, CSRF, scrypt login, TOTP step, session cookie,
 * proxying, Origin/Host rewriting, Set-Cookie stripping, and WS tunneling.
 *
 *   node test/integration.mjs
 */
import assert from 'node:assert/strict'
import { createServer as createHttpServer } from 'node:http'
import * as https from 'node:https'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { connect as tlsConnect } from 'node:tls'

import { GateServer } from '../lib/gate.js'
import { loadConfig } from '../lib/config.js'
import { hashPassword, totpAt, generateTotpSecret } from '../lib/security.js'

const UPSTREAM_PORT = 18080
const GATE_PORT = 18443
const PASSWORD = 'correct horse battery staple'
const SECRET = generateTotpSecret()

/* ------------------------------- fake dsh ------------------------------- */
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
      res.writeHead(303, {
        location: './',
        'set-cookie': 'dsh_session=s3cret; Path=/; HttpOnly',
      })
      res.end()
      return
    }
    if (!cookies.includes('dsh_session=s3cret')) {
      res.writeHead(401)
      res.end('dsh web authentication required')
      return
    }
    if (url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'set-cookie': 'leak=1; Path=/' })
      res.end('<html>INDEX</html>')
      return
    }
    if (url.pathname === '/api/ping') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, origin: req.headers.origin ?? null, host: req.headers.host }))
      return
    }
    res.writeHead(404)
    res.end('not found')
  })
  const upgraded = new Set()
  server.upgradedSockets = upgraded
  server.on('upgrade', (req, socket) => {
    upgraded.add(socket)
    socket.on('close', () => upgraded.delete(socket))
    if (!(req.headers.cookie ?? '').includes('dsh_session=s3cret')) {
      socket.end('HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n')
      return
    }
    socket.write('HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n')
    socket.on('data', (chunk) => socket.write(chunk))
  })
  return new Promise((resolve) => server.listen(UPSTREAM_PORT, '127.0.0.1', () => resolve(server)))
}

/* ------------------------------ https client ---------------------------- */
function request({ method = 'GET', path = '/', headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port: GATE_PORT,
        method,
        path,
        headers,
        rejectUnauthorized: false,
      },
      (res) => {
        const chunks = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
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

function mergeCookies(jar, response, { drop = [] } = {}) {
  for (const entry of setCookies(response)) {
    const pair = entry.split(';', 1)[0]
    const name = pair.slice(0, pair.indexOf('='))
    if (drop.includes(name)) continue
    const value = pair.slice(pair.indexOf('=') + 1)
    if (value === '') {
      delete jar[name]
      continue
    }
    jar[name] = value
  }
  return jar
}

function cookieHeader(jar) {
  return Object.entries(jar)
    .map(([name, value]) => `${name}=${value}`)
    .join('; ')
}

function extractCsrf(html) {
  const match = html.match(/name="csrf" value="([^"]+)"/)
  assert.ok(match, 'csrf token present in the page')
  return match[1]
}

/* --------------------------------- main --------------------------------- */
const tempHome = mkdtempSync(join(tmpdir(), 'dsh-gate-it-'))
process.env.DSH_HOME = tempHome

let upstream
let gate
let passed = 0
function check(name, condition) {
  assert.ok(condition, name)
  passed += 1
  console.log(`ok - ${name}`)
}

try {
  upstream = await startFakeUpstream()

  const passwordHash = await hashPassword(PASSWORD, { N: 2 ** 12 })
  const cfg = loadConfig({
    host: '127.0.0.1',
    port: GATE_PORT,
    tls: {
      certFile: join(tempHome, 'public-gate', 'tls', 'cert.pem'),
      keyFile: join(tempHome, 'public-gate', 'tls', 'key.pem'),
      autoGenerate: true,
      subjectAltNames: ['IP:127.0.0.1'],
    },
    security: {
      username: 'admin',
      passwordHash,
      totp: { secret: SECRET, issuer: 'Test', account: 'admin' },
    },
    audit: { file: join(tempHome, 'public-gate', 'audit.log'), maxBytes: 1024 * 1024, syslog: false },
  })

  const ctx = {
    webServer: { getOrigin: () => `http://127.0.0.1:${UPSTREAM_PORT}/` },
    connection: { authenticatedUrl: (url) => `${url}${url.includes('?') ? '&' : '?'}token=test-launch-token` },
  }

  gate = new GateServer(ctx, cfg)
  await gate.start()
  check('gate started on the configured port', gate.listenPort === GATE_PORT)

  const jar = {}

  // 1. anonymous navigation is redirected to the login page
  const anonymous = await request({ path: '/', headers: { accept: 'text/html' } })
  check('anonymous page request redirects to login', anonymous.status === 302 && anonymous.headers.location === '/__gate/login')

  // 2. the harness API is refused, not redirected
  const anonymousApi = await request({ path: '/api/ping', headers: { accept: 'application/json' } })
  check('anonymous api request returns 401', anonymousApi.status === 401 && anonymousApi.body.includes('unauthorized'))

  // 3. login page carries a CSRF token bound to a cookie
  const loginPage = await request({ path: '/__gate/login', headers: { accept: 'text/html' } })
  mergeCookies(jar, loginPage)
  const csrf = extractCsrf(loginPage.body)
  check('login page is served with a CSRF token', loginPage.status === 200 && jar.dsh_gate_csrf !== undefined)

  // 4. wrong password is rejected and audited
  const wrong = await request({
    method: 'POST',
    path: '/__gate/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar) },
    body: `username=admin&password=nope&csrf=${encodeURIComponent(csrf)}`,
  })
  mergeCookies(jar, wrong)
  check('wrong password is rejected', wrong.status === 401 && wrong.body.includes('用户名或密码错误'))
  const csrf2 = extractCsrf(wrong.body)

  // 5. missing CSRF is rejected even with the right password
  const noCsrf = await request({
    method: 'POST',
    path: '/__gate/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar) },
    body: 'username=admin&password=correct%20horse%20battery%20staple',
  })
  check('missing CSRF is rejected', noCsrf.status === 401)

  // 6. correct password moves to the TOTP step (no session yet)
  const passwordOk = await request({
    method: 'POST',
    path: '/__gate/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar) },
    body: `username=admin&password=${encodeURIComponent(PASSWORD)}&csrf=${encodeURIComponent(csrf2)}`,
  })
  mergeCookies(jar, passwordOk)
  check('password success redirects to the TOTP step', passwordOk.status === 302 && passwordOk.headers.location === '/__gate/totp')
  check('no session cookie before TOTP', jar.dsh_gate_session === undefined)

  const totpPage = await request({ path: '/__gate/totp', headers: { accept: 'text/html', cookie: cookieHeader(jar) } })
  mergeCookies(jar, totpPage)
  const totpCsrf = extractCsrf(totpPage.body)

  // 7. wrong TOTP keeps the pending state but no session
  const badTotp = await request({
    method: 'POST',
    path: '/__gate/totp',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar) },
    body: `totp=000000&csrf=${encodeURIComponent(totpCsrf)}`,
  })
  mergeCookies(jar, badTotp)
  check('wrong TOTP is rejected', badTotp.status === 401)
  const totpCsrf2 = extractCsrf(badTotp.body)

  // 8. correct TOTP issues the session cookie
  const goodTotp = await request({
    method: 'POST',
    path: '/__gate/totp',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar) },
    body: `totp=${totpAt(SECRET)}&csrf=${encodeURIComponent(totpCsrf2)}`,
  })
  mergeCookies(jar, goodTotp)
  check('correct TOTP issues a session', goodTotp.status === 303 && typeof jar.dsh_gate_session === 'string')

  const sessionCookie = setCookies(goodTotp)[0]
  check('session cookie is HttpOnly + Secure + SameSite=Strict', /HttpOnly/.test(sessionCookie) && /Secure/.test(sessionCookie) && /SameSite=Strict/.test(sessionCookie))

  // 9. authenticated proxying works and rewrites Origin/Host
  const index = await request({ path: '/', headers: { accept: 'text/html', cookie: cookieHeader(jar) } })
  check('authenticated page is proxied', index.status === 200 && index.body.includes('INDEX'))
  check('upstream Set-Cookie is stripped from the response', !setCookies(index).some((c) => c.startsWith('leak=')))
  check('upstream auth cookie never reaches the client', !JSON.stringify(index.headers).includes('s3cret'))

  const ping = await request({
    path: '/api/ping',
    headers: { accept: 'application/json', origin: `https://127.0.0.1:${GATE_PORT}`, cookie: cookieHeader(jar) },
  })
  const payload = JSON.parse(ping.body)
  check(
    'Origin is rewritten to the loopback authority',
    payload.origin === `http://127.0.0.1:${UPSTREAM_PORT}`,
    `got ${payload.origin}`,
  )
  check('Host is rewritten to the loopback authority', payload.host === `127.0.0.1:${UPSTREAM_PORT}`)

  // 10. WebSocket upgrades are gated and tunneled
  const deniedUpgrade = await new Promise((resolve) => {
    const socket = tlsConnect({ host: '127.0.0.1', port: GATE_PORT, rejectUnauthorized: false }, () => {
      socket.write(`GET /api/remote.mux HTTP/1.1\r\nhost: 127.0.0.1:${GATE_PORT}\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n`)
    })
    let buffer = ''
    socket.on('data', (chunk) => {
      buffer += chunk.toString()
      if (buffer.includes('\r\n\r\n')) {
        socket.destroy()
        resolve(buffer.split('\r\n')[0])
      }
    })
    socket.on('error', () => resolve('error'))
  })
  check('WS upgrade without a session is refused', deniedUpgrade.includes('401'))

  const allowedUpgrade = await new Promise((resolve) => {
    const socket = tlsConnect({ host: '127.0.0.1', port: GATE_PORT, rejectUnauthorized: false }, () => {
      socket.write(
        `GET /api/remote.mux HTTP/1.1\r\nhost: 127.0.0.1:${GATE_PORT}\r\nupgrade: websocket\r\nconnection: Upgrade\r\n` +
          `origin: https://127.0.0.1:${GATE_PORT}\r\ncookie: ${cookieHeader(jar)}\r\n\r\n`,
      )
    })
    let buffer = ''
    let stage = 'handshake'
    socket.on('data', (chunk) => {
      buffer += chunk.toString()
      if (stage === 'handshake' && buffer.includes('\r\n\r\n')) {
        const status = buffer.split('\r\n')[0]
        if (!status.includes('101')) {
          socket.destroy()
          resolve(status)
          return
        }
        stage = 'echo'
        socket.write('ping')
        return
      }
      if (stage === 'echo' && buffer.endsWith('ping')) {
        socket.destroy()
        resolve('echo-ok')
      }
    })
    socket.on('error', () => resolve('error'))
    setTimeout(() => {
      socket.destroy()
      resolve('timeout')
    }, 4000)
  })
  check('WS upgrade with a session is tunneled', allowedUpgrade === 'echo-ok', String(allowedUpgrade))

  // 11. logout destroys the session server-side
  const logout = await request({
    method: 'POST',
    path: '/__gate/logout',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar) },
    body: '',
  })
  mergeCookies(jar, logout)
  check('logout clears the session cookie', logout.status === 303 && jar.dsh_gate_session === undefined)

  const afterLogout = await request({
    path: '/',
    headers: { accept: 'text/html', cookie: `dsh_gate_session=${sessionCookie.split(';', 1)[0].split('=')[1]}` },
  })
  check('revoked session no longer authenticates', afterLogout.status === 302)

  // 12. brute-force lockout after repeated failures
  const jar2 = {}
  const page2 = await request({ path: '/__gate/login', headers: { accept: 'text/html' } })
  mergeCookies(jar2, page2)
  let lastStatus = 0
  for (let i = 0; i < 6; i += 1) {
    const csrfN = extractCsrf((await request({ path: '/__gate/login', headers: { accept: 'text/html' } })).body)
    const attempt = await request({
      method: 'POST',
      path: '/__gate/login',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar2) },
      body: `username=admin&password=bad${i}&csrf=${encodeURIComponent(csrfN)}`,
    })
    mergeCookies(jar2, attempt)
    lastStatus = attempt.status
  }
  check('repeated failures eventually lock the source out', lastStatus === 429, `final status ${lastStatus}`)
} finally {
  await gate?.stop()
  upstream?.closeAllConnections?.()
  upstream?.close()
  rmSync(tempHome, { recursive: true, force: true })
}

console.log(`\n${passed} integration checks passed`)
process.exit(passed > 0 ? 0 : 1)

