/**
 * Hostile-input suite: every check here is an attack or a malformed request that
 * the gate must refuse. It exercises the same GateServer the plugin runs.
 *
 *   node test/security-selftest.mjs
 */
import assert from 'node:assert/strict'
import { createServer as createHttpServer } from 'node:http'
import * as https from 'node:https'
import { connect as tlsConnect } from 'node:tls'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { GateServer } from '../lib/gate.js'
import { loadConfig } from '../lib/config.js'
import { hashPassword } from '../lib/security.js'

const UPSTREAM_PORT = 18095
const GATE_PORT = 18455
const PASSWORD = 'security-suite-password'

let passed = 0
function check(name, ok, detail = '') {
  assert.ok(ok, `${name}${detail ? ` [${detail}]` : ''}`)
  passed += 1
  console.log(`ok - ${name}`)
}

const tempHome = mkdtempSync(join(tmpdir(), 'dsh-gate-sec-'))
process.env.DSH_HOME = tempHome

function startFakeUpstream() {
  const server = createHttpServer((req, res) => {
    const cookies = req.headers.cookie ?? ''
    if (req.url.startsWith('/?token=')) {
      res.writeHead(303, { location: './', 'set-cookie': 'dsh_session=s3cret; Path=/; HttpOnly' })
      res.end()
      return
    }
    if (!cookies.includes('dsh_session=s3cret')) {
      res.writeHead(401)
      res.end('upstream unauthorized')
      return
    }
    if (req.url.startsWith('/api')) {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ path: req.url, host: req.headers.host, forwardedFor: req.headers['x-forwarded-for'] ?? null }))
      return
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    res.end('<html>INDEX</html>')
  })
  const upgraded = new Set()
  server.upgradedSockets = upgraded
  server.on('upgrade', (req, socket) => {
    upgraded.add(socket)
    socket.on('close', () => upgraded.delete(socket))
    socket.write('HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n')
    socket.on('data', (chunk) => socket.write(chunk))
  })
  return new Promise((resolve) => server.listen(UPSTREAM_PORT, '127.0.0.1', () => resolve(server)))
}

function request({ method = 'GET', path = '/', headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { host: '127.0.0.1', port: GATE_PORT, method, path, headers, rejectUnauthorized: false },
      (res) => {
        const chunks = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }))
      },
    )
    req.on('error', reject)
    if (body !== undefined) req.write(body)
    req.end()
  })
}

/** Send a raw request line, used for absolute-form targets. */
function rawRequest(line, headers = '') {
  return new Promise((resolve) => {
    const socket = tlsConnect({ host: '127.0.0.1', port: GATE_PORT, rejectUnauthorized: false }, () => {
      socket.write(`${line}\r\nhost: 127.0.0.1:${GATE_PORT}\r\nconnection: close\r\n${headers}\r\n`)
    })
    let buffer = ''
    socket.on('data', (chunk) => {
      buffer += chunk.toString()
    })
    const done = () => {
      socket.destroy()
      resolve(buffer)
    }
    socket.on('close', done)
    socket.on('error', done)
    setTimeout(done, 3000)
  })
}

const setCookies = (response) => {
  const raw = response.headers['set-cookie']
  if (raw === undefined) return []
  return Array.isArray(raw) ? raw : [raw]
}
const mergeCookies = (jar, response) => {
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

let upstream
let gate

try {
  upstream = await startFakeUpstream()

  const passwordHash = await hashPassword(PASSWORD, { N: 2 ** 12 })
  const cfg = loadConfig({
    host: '127.0.0.1',
    port: GATE_PORT,
    tls: {
      certFile: join(tempHome, 'gate', 'cert.pem'),
      keyFile: join(tempHome, 'gate', 'key.pem'),
      autoGenerate: true,
      subjectAltNames: ['IP:127.0.0.1'],
    },
    security: { username: 'admin', passwordHash, allowPasswordOnly: true },
    audit: { file: join(tempHome, 'audit.log'), maxBytes: 1_000_000, syslog: false },
  })

  const ctx = {
    webServer: { getOrigin: () => `http://127.0.0.1:${UPSTREAM_PORT}/` },
    connection: { authenticatedUrl: (url) => `${url}${url.includes('?') ? '&' : '?'}token=test-launch-token` },
  }
  gate = new GateServer(ctx, cfg)
  await gate.start()

  /* ---------------- unauthenticated access ---------------- */
  const anonymousPage = await request({ path: '/', headers: { accept: 'text/html' } })
  check('anonymous page request redirects to login', anonymousPage.status === 302)

  const anonymousApi = await request({ path: '/api/session/list', headers: { accept: 'application/json' } })
  check('anonymous api request is 401, not a redirect', anonymousApi.status === 401)

  const adminNoSession = await request({ path: '/__gate/admin/status', headers: { accept: 'application/json' } })
  check('admin status without a session is 401', adminNoSession.status === 401)

  const traversal = await request({ path: '/__gate/admin/../admin/status', headers: { accept: 'application/json' } })
  check('normalized traversal still lands on the guarded admin route', traversal.status === 401)

  const encoded = await request({ path: '/__gate%2Fadmin%2Fstatus', headers: { accept: 'application/json' } })
  check('percent-encoded gate path is proxied, never treated as admin', encoded.status === 401 || encoded.body.includes('unauthorized'))

  /* ---------------- malformed requests ---------------- */
  const absolute = await rawRequest('GET http://evil.example/ HTTP/1.1')
  check('absolute-form request target is rejected with 400', absolute.startsWith('HTTP/1.1 400'))

  const asterisk = await rawRequest('OPTIONS * HTTP/1.1')
  check('asterisk-form request target is rejected', asterisk.startsWith('HTTP/1.1 400'))

  const wrongMethod = await request({ method: 'DELETE', path: '/__gate/login', headers: { accept: 'text/html' } })
  check('unsupported method on the login page is 405', wrongMethod.status === 405)

  const hugeBody = await request({
    method: 'POST',
    path: '/__gate/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: `username=${'a'.repeat(20_000)}`,
  }).catch((error) => ({ status: 413, reset: true, error: String(error) }))
  check('oversized login body is refused', hugeBody.status === 413, String(hugeBody.status))

  /* ---------------- login hardening ---------------- */
  const jar = {}
  const loginPage = await request({ path: '/__gate/login?next=//evil.example/', headers: { accept: 'text/html' } })
  mergeCookies(jar, loginPage)
  let csrf = csrfFrom(loginPage.body)

  const noCsrf = await request({
    method: 'POST',
    path: '/__gate/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar) },
    body: `username=admin&password=${encodeURIComponent(PASSWORD)}`,
  })
  check('login without the CSRF field is refused', noCsrf.status === 401)

  const badPassword = await request({
    method: 'POST',
    path: '/__gate/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar) },
    body: `username=admin&password=wrong&csrf=${encodeURIComponent(csrf)}`,
  })
  mergeCookies(jar, badPassword)
  csrf = csrfFrom(badPassword.body) ?? csrf
  check('wrong password is refused', badPassword.status === 401)

  const good = await request({
    method: 'POST',
    path: '/__gate/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar) },
    body: `username=admin&password=${encodeURIComponent(PASSWORD)}&csrf=${encodeURIComponent(csrf)}&next=//evil.example/`,
  })
  mergeCookies(jar, good)
  check('valid password logs in', good.status === 303 && typeof jar.dsh_gate_session === 'string')
  check('open redirect through `next` is ignored', good.headers.location === '/' || good.headers.location === '/__gate/login', good.headers.location)

  const sessionCookie = setCookies(good).find((entry) => entry.startsWith('dsh_gate_session='))
  check('session cookie is HttpOnly + Secure + SameSite=Strict',
    /HttpOnly/.test(sessionCookie) && /Secure/.test(sessionCookie) && /SameSite=Strict/.test(sessionCookie))

  /* ---------------- authenticated surface ---------------- */
  const adminAuthed = await request({
    path: '/__gate/admin/status',
    headers: { accept: 'application/json', cookie: cookieHeader(jar) },
  })
  check('admin status works for an authenticated session', adminAuthed.status === 200 && JSON.parse(adminAuthed.body).secondFactor === 'none')

  const adminNoHeader = await request({
    method: 'POST',
    path: '/__gate/admin/settings',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(jar) },
    body: JSON.stringify({ emailTo: 'attacker@example.com' }),
  })
  check('admin settings without the gate header is 403', adminNoHeader.status === 403)

  const adminCrossOrigin = await request({
    method: 'POST',
    path: '/__gate/admin/settings',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(jar),
      origin: 'https://evil.example',
      'x-dsh-gate': 'settings',
    },
    body: JSON.stringify({ emailTo: 'attacker@example.com' }),
  })
  check('admin settings from a foreign Origin is 403', adminCrossOrigin.status === 403)

  const proxied = await request({ path: '/api/session/list', headers: { accept: 'application/json', cookie: cookieHeader(jar) } })
  const payload = JSON.parse(proxied.body)
  check('authenticated api request is proxied', proxied.status === 200 && payload.path === '/api/session/list')
  check('upstream sees the loopback authority', payload.host === `127.0.0.1:${UPSTREAM_PORT}`)
  check('client ip is forwarded, not spoofable by the client', payload.forwardedFor === '127.0.0.1')

  const spoof = await request({
    path: '/api/session/list',
    headers: { accept: 'application/json', cookie: cookieHeader(jar), 'x-forwarded-for': '10.0.0.1' },
  })
  check('client-supplied X-Forwarded-For is replaced', JSON.parse(spoof.body).forwardedFor === '127.0.0.1')

  const authResponse = await request({ path: '/', headers: { accept: 'text/html', cookie: cookieHeader(jar) } })
  check('security headers are present', authResponse.headers['x-content-type-options'] === 'nosniff'
    && authResponse.headers['x-frame-options'] === 'DENY'
    && authResponse.headers['strict-transport-security'] !== undefined)
  check('upstream Set-Cookie never reaches the client', setCookies(authResponse).length === 0)

  /* ---------------- session tampering ---------------- */
  const forgedSession = await request({
    path: '/',
    headers: { accept: 'text/html', cookie: 'dsh_gate_session=forged-session-id' },
  })
  check('forged session id is refused', forgedSession.status === 302)

  /* ---------------- websocket ---------------- */
  const wsNoSession = await rawRequest('GET /api/remote.mux HTTP/1.1', 'upgrade: websocket\r\nconnection: Upgrade\r\n')
  check('websocket without a session is 401', wsNoSession.startsWith('HTTP/1.1 401'))

  const wsWrongPath = await rawRequest('GET /assets/x.js HTTP/1.1', `upgrade: websocket\r\nconnection: Upgrade\r\ncookie: ${cookieHeader(jar)}\r\n`)
  check('websocket to a non-/api path is 404', wsWrongPath.startsWith('HTTP/1.1 404'))

  const wsPost = await rawRequest('POST /api/remote.mux HTTP/1.1', `upgrade: websocket\r\nconnection: Upgrade\r\ncookie: ${cookieHeader(jar)}\r\n`)
  check('non-GET websocket upgrade is 400', wsPost.startsWith('HTTP/1.1 400'))

  /* ---------------- allowlist ---------------- */
  const allowCfg = loadConfig({
    host: '127.0.0.1',
    port: GATE_PORT + 1,
    tls: {
      certFile: join(tempHome, 'gate2', 'cert.pem'),
      keyFile: join(tempHome, 'gate2', 'key.pem'),
      autoGenerate: true,
      subjectAltNames: ['IP:127.0.0.1'],
    },
    security: { username: 'admin', passwordHash, allowPasswordOnly: true, ipAllowlist: ['10.0.0.0/8'] },
    audit: { file: join(tempHome, 'audit2.log'), maxBytes: 1_000_000, syslog: false },
  })
  const allowGate = new GateServer(ctx, allowCfg)
  await allowGate.start()
  try {
    const blocked = await new Promise((resolve, reject) => {
      const req = https.request(
        { host: '127.0.0.1', port: GATE_PORT + 1, path: '/__gate/login', headers: { accept: 'text/html' }, rejectUnauthorized: false },
        (res) => {
          res.resume()
          resolve({ status: res.statusCode })
        },
      )
      req.on('error', reject)
      req.end()
    })
    check('ipAllowlist refuses a source outside the list', blocked.status === 403, String(blocked.status))
  } finally {
    await allowGate.stop()
  }
} finally {
  await gate?.stop()
  upstream?.closeAllConnections?.()
  upstream?.close()
  rmSync(tempHome, { recursive: true, force: true })
}

console.log(`\n${passed} security checks passed`)
process.exit(passed > 0 ? 0 : 1)
