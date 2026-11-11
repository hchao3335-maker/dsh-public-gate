/**
 * Minimal SMTP client (dependency-free).
 *
 * Supports implicit TLS (typically port 465), STARTTLS (587/25), AUTH PLAIN and
 * AUTH LOGIN. It is deliberately small: the gate sends exactly one short
 * message per login attempt and nothing else.
 */
import { connect as netConnect } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { hostname } from 'node:os'

class LineReader {
  #socket
  #buffer = ''
  #lines = []
  #waiter
  #failure

  constructor(socket) {
    this.#socket = socket
    socket.setEncoding('utf8')
    socket.on('data', (chunk) => {
      this.#buffer += chunk
      let index
      while ((index = this.#buffer.indexOf('\n')) !== -1) {
        const line = this.#buffer.slice(0, index).replace(/\r$/, '')
        this.#buffer = this.#buffer.slice(index + 1)
        this.#lines.push(line)
      }
      this.#pump()
    })
    socket.on('error', (error) => {
      this.#failure = error
      this.#pump()
    })
    socket.on('close', () => {
      if (this.#failure === undefined) this.#failure = new Error('smtp: connection closed')
      this.#pump()
    })
  }

  #pump() {
    if (this.#waiter === undefined) return
    if (this.#lines.length > 0) {
      const { resolve } = this.#waiter
      this.#waiter = undefined
      resolve(this.#lines.shift())
      return
    }
    if (this.#failure !== undefined) {
      const { reject } = this.#waiter
      this.#waiter = undefined
      reject(this.#failure)
    }
  }

  readLine() {
    if (this.#lines.length > 0) return Promise.resolve(this.#lines.shift())
    if (this.#failure !== undefined) return Promise.reject(this.#failure)
    return new Promise((resolve, reject) => {
      this.#waiter = { resolve, reject }
    })
  }
}

const code = (line) => Number.parseInt(line.slice(0, 3), 10)
const isFinal = (line) => line.length < 4 || line[3] === ' '

class Session {
  constructor(socket, transcript) {
    this.socket = socket
    this.reader = new LineReader(socket)
    this.transcript = transcript
  }

  async readReply() {
    const lines = []
    for (;;) {
      const line = await this.reader.readLine()
      this.transcript.push(`< ${line}`)
      lines.push(line)
      if (isFinal(line)) break
    }
    return { code: code(lines[0]), text: lines.map((line) => line.slice(4)).join('\n') }
  }

  async expect(expected, label) {
    const reply = await this.readReply()
    if (!expected.includes(reply.code)) {
      throw new Error(`smtp: ${label} failed (${reply.code} ${reply.text.trim().slice(0, 200)})`)
    }
    return reply
  }

  async command(line, expected, label) {
    this.transcript.push(`> ${line.startsWith('AUTH') ? line.split(' ').slice(0, 2).join(' ') : line}`)
    this.socket.write(`${line}\r\n`)
    return this.expect(expected, label)
  }

  write(line) {
    this.socket.write(`${line}\r\n`)
  }
}

function sniFor(host) {
  // RFC 6066 forbids IP literals in SNI; Node warns and drops them.
  return /^[0-9.]+$/.test(host) || host.includes(':') ? undefined : host
}

function connectSocket({ host, port, secure, timeoutMs, servername, rejectUnauthorized }) {
  return new Promise((resolve, reject) => {
    const socket = secure
      ? tlsConnect({ host, port, servername: servername ?? sniFor(host), rejectUnauthorized: rejectUnauthorized !== false })
      : netConnect({ host, port })
    const timer = setTimeout(() => {
      socket.destroy()
      reject(new Error(`smtp: connect to ${host}:${port} timed out`))
    }, timeoutMs)
    const onError = (error) => {
      clearTimeout(timer)
      reject(error)
    }
    socket.once('error', onError)
    socket.once(secure ? 'secureConnect' : 'connect', () => {
      clearTimeout(timer)
      socket.off('error', onError)
      resolve(socket)
    })
  })
}

function upgraded(socket, servername, rejectUnauthorized) {
  return new Promise((resolve, reject) => {
    const secureSocket = tlsConnect({ socket, servername, rejectUnauthorized: rejectUnauthorized !== false })
    secureSocket.once('secureConnect', () => resolve(secureSocket))
    secureSocket.once('error', reject)
  })
}

function encodeAddress(value) {
  if (typeof value !== 'string' || !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(value)) {
    throw new Error(`smtp: invalid address ${JSON.stringify(value)}`)
  }
  return value
}

/**
 * Send one message.
 * @param options - `{ host, port, secure, requireAuth, user, pass, from, to, subject, text, timeoutMs }`
 * @returns `{ accepted: string[], response: string }`
 */
export async function sendMail(options) {
  const {
    host,
    port = 465,
    secure = true,
    requireAuth = true,
    user,
    pass,
    from,
    to,
    subject,
    text,
    timeoutMs = 20_000,
    tlsInsecure = false,
  } = options
  if (typeof host !== 'string' || host.length === 0) throw new Error('smtp: host is required')
  const recipients = (Array.isArray(to) ? to : [to]).map(encodeAddress)
  if (recipients.length === 0) throw new Error('smtp: at least one recipient is required')
  const envelopeFrom = encodeAddress(from)

  const transcript = []
  const rejectUnauthorized = tlsInsecure !== true
  let socket = await connectSocket({ host, port, secure, timeoutMs, rejectUnauthorized })
  socket.setTimeout(timeoutMs, () => socket.destroy(new Error('smtp: socket timeout')))
  let session = new Session(socket, transcript)
  let authenticated = false

  try {
    await session.expect([220], 'greeting')

    const ehloName = hostname() || 'localhost'
    let ehlo = await session.command(`EHLO ${ehloName}`, [250], 'EHLO')
    if (secure !== true) {
      const advertisesStartTls = /STARTTLS/i.test(ehlo.text)
      if (!advertisesStartTls) throw new Error('smtp: server does not offer STARTTLS')
      await session.command('STARTTLS', [220], 'STARTTLS')
      socket = await upgraded(socket, sniFor(host), rejectUnauthorized)
      socket.setTimeout(timeoutMs, () => socket.destroy(new Error('smtp: socket timeout')))
      session = new Session(socket, transcript)
      ehlo = await session.command(`EHLO ${ehloName}`, [250], 'EHLO (after STARTTLS)')
    }

    if (requireAuth !== false) {
      if (typeof user !== 'string' || user.length === 0 || typeof pass !== 'string') {
        throw new Error('smtp: credentials are required but missing')
      }
      const mechanisms = /AUTH[ =]([^\r\n]+)/i.exec(ehlo.text)?.[1]?.toUpperCase() ?? ''
      if (mechanisms.includes('PLAIN')) {
        const blob = Buffer.from(`\0${user}\0${pass}`, 'utf8').toString('base64')
        await session.command(`AUTH PLAIN ${blob}`, [235], 'AUTH PLAIN')
      } else if (mechanisms.includes('LOGIN') || mechanisms === '') {
        await session.command('AUTH LOGIN', [334], 'AUTH LOGIN')
        await session.command(Buffer.from(user, 'utf8').toString('base64'), [334], 'AUTH LOGIN user')
        await session.command(Buffer.from(pass, 'utf8').toString('base64'), [235], 'AUTH LOGIN password')
      } else {
        throw new Error(`smtp: unsupported auth mechanisms: ${mechanisms}`)
      }
      authenticated = true
    }

    await session.command(`MAIL FROM:<${envelopeFrom}>`, [250], 'MAIL FROM')
    for (const recipient of recipients) {
      await session.command(`RCPT TO:<${recipient}>`, [250, 251], `RCPT TO ${recipient}`)
    }
    await session.command('DATA', [354], 'DATA')

    const normalized = String(text).replace(/\r?\n/g, '\r\n')
    const stuffed = normalized.replace(/^\./gm, '..')
    session.write(stuffed)
    session.write('.')
    const delivered = await session.expect([250], 'message body')

    try {
      await session.command('QUIT', [221], 'QUIT')
    } catch {
      /* the message is already accepted; a failed QUIT is not an error */
    }
    return {
      accepted: recipients,
      response: delivered.text.trim(),
      authenticated,
      transcript,
    }
  } finally {
    try {
      socket.destroy()
    } catch {
      /* ignore */
    }
  }
}
