/**
 * TLS material for the public/LAN listener.
 *
 * Prefers operator-supplied PEM files (for example Let's Encrypt), and falls
 * back to generating a self-signed certificate with the openssl CLI so a bare
 * IP deployment still gets transport encryption.
 *
 * The generated certificate covers **every local IPv4 address** (public, LAN and
 * loopback) plus the hostname, and is reissued automatically when the machine's
 * addresses change — otherwise a laptop that moves between networks would keep
 * serving a certificate for an address it no longer has.
 */
import { execFile } from 'node:child_process'
import { X509Certificate, createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, unlinkSync } from 'node:fs'
import { networkInterfaces, hostname as osHostname } from 'node:os'
import { dirname, join } from 'node:path'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

const DAYS = 825
const MARKER = 'self-signed.json'

/** All non-internal IPv4 addresses of this machine. */
export function localAddresses() {
  const addresses = []
  const interfaces = networkInterfaces()
  for (const entries of Object.values(interfaces)) {
    for (const entry of entries ?? []) {
      if (entry.family === 'IPv4' && !entry.internal) addresses.push(entry.address)
    }
  }
  return addresses
}

/** Addresses a phone on the same LAN can reach, i.e. private IPv4 ranges. */
export function lanAddresses() {
  return localAddresses().filter((address) => {
    const [a, b] = address.split('.').map(Number)
    if (a === 10) return true
    if (a === 192 && b === 168) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    return false
  })
}

function isIpLiteral(value) {
  return /^[0-9.]+$/.test(value) || value.includes(':')
}

/** The SAN list a generated certificate should carry. */
export function desiredSubjectAltNames(configured, bindHost) {
  const entries = new Set()
  for (const item of configured ?? []) {
    const text = String(item).trim()
    if (text.length > 0) entries.add(text)
  }
  if (entries.size > 0) return [...entries]

  for (const address of localAddresses()) entries.add(`IP:${address}`)
  if (bindHost !== undefined && bindHost !== '0.0.0.0' && bindHost !== '::' && isIpLiteral(bindHost)) {
    entries.add(`IP:${bindHost}`)
  }
  entries.add('IP:127.0.0.1')
  const name = osHostname()
  if (name.length > 0 && !isIpLiteral(name)) entries.add(`DNS:${name.toLowerCase()}`)
  return [...entries]
}

/** `X509Certificate.subjectAltName` normalises entries as `IP Address:x` / `DNS:y`. */
function sanTokens(pem) {
  try {
    const san = new X509Certificate(pem).subjectAltName ?? ''
    return san.split(/,\s*/).map((entry) => entry.trim()).filter((entry) => entry.length > 0)
  } catch {
    return []
  }
}

/** Whether a certificate already covers every required SAN. */
export function coversAltNames(pem, entries) {
  const tokens = sanTokens(pem)
  if (tokens.length === 0) return false
  const normalised = tokens.map((token) =>
    token.startsWith('IP Address:') ? `IP:${token.slice('IP Address:'.length)}` : token,
  )
  return entries.every((entry) => normalised.includes(entry))
}

function fingerprint(pem) {
  return createHash('sha256').update(pem).digest('hex')
}

/** True only when the marker records this exact certificate (i.e. we made it). */
function isSelfSignedByUs(pem, markerPath) {
  try {
    const marker = JSON.parse(readFileSync(markerPath, 'utf8'))
    return typeof marker.fingerprint === 'string' && marker.fingerprint === fingerprint(pem)
  } catch {
    return false
  }
}

async function generate(tls, entries) {
  const directory = dirname(tls.certFile)
  mkdirSync(directory, { recursive: true, mode: 0o700 })

  const cn = (entries.find((entry) => entry.startsWith('IP:')) ?? entries[0] ?? 'IP:127.0.0.1').split(':').slice(1).join(':')
  try {
    await execFileAsync(
      'openssl',
      [
        'req', '-x509', '-newkey', 'rsa:3072', '-nodes',
        '-days', String(DAYS),
        '-subj', `/CN=${cn}`,
        '-addext', `subjectAltName=${entries.join(',')}`,
        '-keyout', tls.keyFile,
        '-out', tls.certFile,
      ],
      { timeout: 30_000 },
    )
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new Error(`public-gate: could not generate a self-signed certificate (is openssl installed?): ${message}`)
  }

  try {
    chmodSync(tls.keyFile, 0o600)
    chmodSync(tls.certFile, 0o644)
  } catch {
    /* best effort */
  }

  const cert = readFileSync(tls.certFile, 'utf8')
  writeFileSync(
    join(directory, MARKER),
    `${JSON.stringify({ generatedAt: new Date().toISOString(), fingerprint: fingerprint(cert), subjectAltNames: entries }, null, 2)}\n`,
    { mode: 0o600 },
  )
  writeFileSync(join(directory, 'HOW-TO-REPLACE.txt'), replacementNote(entries), { mode: 0o644 })
  return cert
}

/**
 * Resolve TLS material, generating a self-signed pair when needed and
 * reissuing it when the machine's addresses no longer match.
 * @param tls - resolved `tls` config section.
 * @param bindHost - the listener's bind address.
 */
export async function resolveTls(tls, bindHost) {
  const entries = desiredSubjectAltNames(tls.subjectAltNames, bindHost)
  const markerPath = join(dirname(tls.certFile), MARKER)
  const hasFiles = existsSync(tls.certFile) && existsSync(tls.keyFile)

  if (hasFiles) {
    const cert = readFileSync(tls.certFile, 'utf8')
    const key = readFileSync(tls.keyFile, 'utf8')
    if (!cert.includes('BEGIN CERTIFICATE')) {
      throw new Error(`public-gate: ${tls.certFile} does not look like a PEM certificate`)
    }
    if (!key.includes('PRIVATE KEY')) {
      throw new Error(`public-gate: ${tls.keyFile} does not look like an unencrypted PEM private key`)
    }

    const ours = isSelfSignedByUs(cert, markerPath)
    const needsReissue = ours && tls.regenerateOnAddressChange !== false && !coversAltNames(cert, entries)
    if (!needsReissue) {
      return { key, cert, generated: !ours, source: ours ? 'self-signed' : 'configured', subjectAltNames: entries }
    }

    // The machine's addresses changed since this certificate was issued.
    const reissued = await generate(tls, entries)
    return {
      key: readFileSync(tls.keyFile, 'utf8'),
      cert: reissued,
      generated: true,
      regenerated: true,
      source: 'self-signed',
      subjectAltNames: entries,
    }
  }

  if (tls.autoGenerate !== true) {
    throw new Error(
      `public-gate: TLS files missing (${tls.certFile}, ${tls.keyFile}) and tls.autoGenerate is disabled`,
    )
  }

  const cert = await generate(tls, entries)
  return {
    key: readFileSync(tls.keyFile, 'utf8'),
    cert,
    generated: true,
    regenerated: false,
    source: 'self-signed',
    subjectAltNames: entries,
  }
}

/** Remove generated material so the next start issues a fresh pair. */
export function clearGeneratedTls(tls) {
  const directory = dirname(tls.certFile)
  for (const file of [tls.certFile, tls.keyFile, join(directory, MARKER)]) {
    try {
      unlinkSync(file)
    } catch {
      /* not present */
    }
  }
}

function replacementNote(entries) {
  return `This directory holds a self-signed certificate generated by dsh-public-gate.

Browsers warn until you trust it or install a real one. To use a real certificate
(for example Let's Encrypt):

  # 1. point a DNS A record at this host
  # 2. issue the certificate (port 80 must be reachable)
  certbot certonly --standalone -d your.domain.example

  # 3. copy the pair into place (paths from config.json)
  install -m 644 /etc/letsencrypt/live/your.domain.example/fullchain.pem cert.pem
  install -m 600 /etc/letsencrypt/live/your.domain.example/privkey.pem  key.pem

  # 4. restart dsh; the gate reloads the files at startup
  #    (a certificate you place yourself is never reissued automatically)

Current subject alternative names: ${entries.join(', ')}
`
}
