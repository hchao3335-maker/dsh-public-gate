/**
 * Latency/bandwidth behaviour: content-addressed caching, Brotli re-encoding,
 * and the keep-alive/header timeout invariant.
 *
 *   node test/performance-selftest.mjs
 */
import assert from 'node:assert/strict'
import { createServer as createHttpServer } from 'node:http'
import * as https from 'node:https'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import zlib from 'node:zlib'

import { GateServer } from '../lib/gate.js'
import { loadConfig } from '../lib/config.js'
import { hashPassword } from '../lib/security.js'

const UPSTREAM_PORT = 18097
const GATE_PORT = 18457
const PASSWORD = 'performance-suite-password'

let passed = 0
function check(name, ok, detail = '') {
  assert.ok(ok, `${name}${detail ? ` [${detail}]` : ''}`)
  passed += 1
  console.log(`ok - ${name}`)
}

const tempHome = mkdtempSync(join(tmpdir(), 'dsh-gate-perf-'))
process.env.DSH_HOME = tempHome

const JS_BODY = 'console.log("hello performance suite");'.repeat(200)
const JSON_BODY = JSON.stringify({ items: Array.from({ length: 400 }, (_, index) => ({ index, text: 'x'.repeat(120) })) })

function gz(text) {
  return zlib.gzipSync(Buffer.from(text), { level: 1 })
}

function startFakeUpstream() {
  const server = createHttpServer((req, res) => {
    if (req.url.startsWith('/?token=')) {
      res.writeHead(303, { location: './', 'set-cookie': 'dsh_session=s3cret; Path=/; HttpOnly' })
      res.end()
      return
    }
    if (!(req.headers.cookie ?? '').includes('dsh_session=s3cret')) {
      res.writeHead(401)
      res.end('unauthorized')
      return
    }

    const sendGzip = (type, text, extra = {}) => {
      const body = gz(text)
      res.writeHead(200, {
        'content-type': type,
        'content-encoding': 'gzip',
        'content-length': String(body.length),
        vary: 'Accept-Encoding',
        ...extra,
      })
      res.end(body)
    }

    if (req.url.startsWith('/assets/app-9f8e7d6c.js')) {
      sendGzip('application/javascript; charset=utf-8', JS_BODY, { 'cache-control': 'no-cache', etag: 'W/"v1"' })
      return
    }
    if (req.url.startsWith('/assets/plain.js')) {
      sendGzip('application/javascript; charset=utf-8', JS_BODY, { 'cache-control': 'no-cache', etag: 'W/"v1"' })
      return
    }
    if (req.url.startsWith('/plugins/')) {
      sendGzip('application/javascript; charset=utf-8', JS_BODY, { 'cache-control': 'no-cache' })
      return
    }
    if (req.url.startsWith('/api/big')) {
      sendGzip('application/json; charset=utf-8', JSON_BODY, { 'cache-control': 'no-store' })
      return
    }
    if (req.url.startsWith('/api/plain')) {
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
      res.end('{"ok":true}')
      return
    }
    res.writeHead(404)
    res.end('nope')
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
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks),
          }),
        )
      },
    )
    req.on('error', reject)
    if (body !== undefined) req.write(body)
    req.end()
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

function decode(response) {
  const encoding = String(response.headers['content-encoding'] ?? '')
  if (encoding === 'br') return zlib.brotliDecompressSync(response.body).toString('utf8')
  if (encoding === 'gzip') return zlib.gunzipSync(response.body).toString('utf8')
  return response.body.toString('utf8')
}

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

  check('headersTimeout exceeds keepAliveTimeout', cfg.limits.headersTimeoutMs > cfg.limits.keepAliveTimeoutMs,
    `${cfg.limits.headersTimeoutMs} / ${cfg.limits.keepAliveTimeoutMs}`)

  const ctx = {
    webServer: { getOrigin: () => `http://127.0.0.1:${UPSTREAM_PORT}/` },
    connection: { authenticatedUrl: (url) => `${url}${url.includes('?') ? '&' : '?'}token=test-launch-token` },
  }
  gate = new GateServer(ctx, cfg)
  await gate.start()

  // log in (password-only mode keeps the suite fast)
  const jar = {}
  const loginPage = await request({ path: '/__gate/login', headers: { accept: 'text/html' } })
  mergeCookies(jar, loginPage)
  const csrf = csrfFrom(loginPage.body.toString('utf8'))
  const login = await request({
    method: 'POST',
    path: '/__gate/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(jar) },
    body: `username=admin&password=${encodeURIComponent(PASSWORD)}&csrf=${encodeURIComponent(csrf)}`,
  })
  mergeCookies(jar, login)
  check('logged in for the proxy checks', login.status === 303 && typeof jar.dsh_gate_session === 'string')

  const authed = (extra = {}) => ({ accept: '*/*', cookie: cookieHeader(jar), ...extra })

  // 1. content-addressed asset → immutable cache (upstream said no-cache)
  const asset = await request({ path: '/assets/app-9f8e7d6c.js', headers: authed({ 'accept-encoding': 'br, gzip' }) })
  check('hashed asset is cached as immutable', /immutable/.test(String(asset.headers['cache-control'])), asset.headers['cache-control'])
  check('hashed asset is re-encoded to brotli', asset.headers['content-encoding'] === 'br', asset.headers['content-encoding'])
  check('brotli payload decodes to the original', decode(asset) === JS_BODY)

  // 2. a non-fingerprinted asset keeps the upstream policy
  const plain = await request({ path: '/assets/plain.js', headers: authed({ 'accept-encoding': 'gzip' }) })
  check('non-fingerprinted asset keeps the upstream cache policy', plain.headers['cache-control'] === 'no-cache', plain.headers['cache-control'])
  check('gzip-only client still gets gzip', plain.headers['content-encoding'] === 'gzip')

  // 3. plugin bundle combiner is fingerprinted too
  const bundle = await request({ path: '/plugins/??@deepseek-ai/x/client.js&rev=abc123', headers: authed({ 'accept-encoding': 'gzip' }) })
  check('plugin bundle with rev= is cached as immutable', /immutable/.test(String(bundle.headers['cache-control'])))

  // 4. JSON API: brotli + no stale etag
  const api = await request({ path: '/api/big', headers: authed({ 'accept-encoding': 'gzip, br' }) })
  check('json api re-encodes to brotli', api.headers['content-encoding'] === 'br')
  check('json api drops the gzip etag', api.headers.etag === undefined)
  check('json api decodes correctly', decode(api) === JSON_BODY)
  check('brotli payload is smaller than gzip', api.body.length < gz(JSON_BODY).length,
    `${api.body.length} vs ${gz(JSON_BODY).length}`)

  // 5. br;q=0 is not "acceptable"
  const declined = await request({ path: '/api/big', headers: authed({ 'accept-encoding': 'br;q=0, gzip' }) })
  check('br;q=0 keeps the gzip body', declined.headers['content-encoding'] === 'gzip')

  // 6. HEAD requests are not transformed
  const head = await request({ method: 'HEAD', path: '/api/big', headers: authed({ 'accept-encoding': 'br, gzip' }) })
  check('HEAD is not re-encoded', head.headers['content-encoding'] === 'gzip', head.headers['content-encoding'])
  check('HEAD returns no body', head.body.length === 0)

  // 7. plain (uncompressed) upstream responses pass through untouched
  const plainApi = await request({ path: '/api/plain', headers: authed({ 'accept-encoding': 'br, gzip' }) })
  check('uncompressed responses are left alone', plainApi.headers['content-encoding'] === undefined)
  check('uncompressed body is intact', plainApi.body.toString('utf8') === '{"ok":true}')

  // 8. keep-alive advertised to the browser
  check('gate advertises a long keep-alive', /timeout=\d{2,}/.test(String(asset.headers['keep-alive'] ?? '')) || asset.headers.connection === 'keep-alive')
} finally {
  await gate?.stop()
  upstream?.closeAllConnections?.()
  upstream?.close()
  rmSync(tempHome, { recursive: true, force: true })
}

console.log(`\n${passed} performance checks passed`)
process.exit(passed > 0 ? 0 : 1)
