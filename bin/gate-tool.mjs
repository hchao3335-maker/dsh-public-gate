#!/usr/bin/env node
/**
 * dsh-gate-tool — configure dsh-public-gate.
 *
 *   init            create $DSH_HOME/public-gate/config.json (password + TOTP)
 *   set-password    replace the password
 *   set-totp        generate a new TOTP secret
 *   disable-totp    explicitly allow password-only logins
 *   show            print the current configuration summary
 *   gen-tls         (re)generate the self-signed certificate
 *
 * The tool never writes secrets to argv-visible logs; the generated password is
 * printed once to stdout and only its scrypt hash is stored.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, renameSync } from 'node:fs'
import { dirname } from 'node:path'
import { randomInt } from 'node:crypto'

import { gatePaths, loadConfig } from '../lib/config.js'
import { buildMessage } from '../lib/mailer.js'
import { sendMail } from '../lib/smtp.js'
import { generateTotpSecret, hashPassword, otpauthUrl } from '../lib/security.js'
import { resolveTls } from '../lib/tls.js'

const ALPHABET = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%^*-_=+?'

function randomPassword(length = 24) {
  let out = ''
  for (let i = 0; i < length; i += 1) out += ALPHABET[randomInt(ALPHABET.length)]
  return out
}

function parseArgs(argv) {
  const out = { _: [] }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg.startsWith('--')) {
      const [key, inline] = arg.slice(2).split('=')
      if (inline !== undefined) {
        out[key] = inline
        continue
      }
      const next = argv[i + 1]
      if (next !== undefined && !next.startsWith('--')) {
        out[key] = next
        i += 1
      } else {
        out[key] = true
      }
    } else {
      out._.push(arg)
    }
  }
  return out
}

function readConfigFile(paths) {
  if (!existsSync(paths.configFile)) return {}
  return JSON.parse(readFileSync(paths.configFile, 'utf8'))
}

function writeConfigFile(paths, config) {
  mkdirSync(dirname(paths.configFile), { recursive: true, mode: 0o700 })
  const temp = `${paths.configFile}.tmp`
  writeFileSync(temp, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 })
  chmodSync(temp, 0o600)
  renameSync(temp, paths.configFile)
}

function assertPasswordStrength(password, { force = false } = {}) {
  if (password.length > 512) throw new Error('password must be at most 512 characters')
  if (password.length < 12) {
    if (force !== true) {
      throw new Error(
        `password must be at least 12 characters (got ${password.length}); pass --force to override — not recommended`,
      )
    }
    process.stderr.write(
      `WARNING: accepting a ${password.length}-character password because --force was given; ` +
        'TOTP and the brute-force lockout remain your only defence\n',
    )
  }
}

function printSecrets({ username, password, totpSecret, issuer, configFile }) {
  process.stdout.write('\n')
  process.stdout.write('============================================================\n')
  process.stdout.write('  Store these now. The password is not recoverable from disk.\n')
  process.stdout.write('============================================================\n')
  if (password !== undefined) {
    process.stdout.write(`  username : ${username}\n`)
    process.stdout.write(`  password : ${password}\n`)
  }
  if (totpSecret !== undefined) {
    process.stdout.write(`  TOTP     : ${otpauthUrl({ secret: totpSecret, issuer, account: username })}\n`)
    process.stdout.write('             (paste into any authenticator app, or scan the QR)\n')
  }
  process.stdout.write(`  config   : ${configFile} (mode 0600)\n`)
  process.stdout.write('============================================================\n\n')
}

/** Render an otpauth URI as a terminal QR code when qrencode is unavailable. */
function printQrHint() {
  process.stdout.write('Tip: `qrencode -t ANSIUTF8 "<otpauth url>"` renders a scannable QR.\n\n')
}

async function commandInit(args) {
  const paths = gatePaths()
  const existing = readConfigFile(paths)
  if (existing.security?.passwordHash !== undefined && args.force !== true) {
    throw new Error(`${paths.configFile} already has credentials; pass --force to overwrite`)
  }

  const username = String(args.user ?? 'admin')
  let password = typeof args.password === 'string' ? args.password : undefined
  if (password === undefined) password = randomPassword(24)
  assertPasswordStrength(password, { force: args.force === true })

  const totpSecret = args['no-totp'] === true ? '' : generateTotpSecret()
  const issuer = String(args.issuer ?? 'DeepSeek Harness')
  const port = Number(args.port ?? 8443)
  const host = String(args.host ?? '0.0.0.0')

  const passwordHash = await hashPassword(password)

  const config = {
    ...existing,
    host,
    port,
    tls: {
      ...(existing.tls ?? {}),
      certFile: existing.tls?.certFile ?? paths.certFile,
      keyFile: existing.tls?.keyFile ?? paths.keyFile,
      autoGenerate: existing.tls?.autoGenerate ?? true,
      subjectAltNames: args.san === undefined ? (existing.tls?.subjectAltNames ?? []) : String(args.san).split(',').map((s) => s.trim()),
    },
    security: {
      ...(existing.security ?? {}),
      username,
      passwordHash,
      allowPasswordOnly: args['no-totp'] === true,
      totp: {
        ...(existing.security?.totp ?? {}),
        secret: totpSecret,
        issuer,
        account: username,
      },
    },
  }

  writeConfigFile(paths, config)
  // Validate the file the way the plugin will read it (fail here, not at boot).
  loadConfig(undefined)

  printSecrets({
    username,
    password,
    totpSecret: totpSecret.length > 0 ? totpSecret : undefined,
    issuer,
    configFile: paths.configFile,
  })
  if (totpSecret.length > 0) printQrHint()
  else process.stdout.write('WARNING: TOTP disabled; this deployment is protected by a password only.\n\n')
}

async function commandSetPassword(args) {
  const paths = gatePaths()
  const config = readConfigFile(paths)
  if (config.security?.passwordHash === undefined) throw new Error('no configuration yet; run "init" first')
  let password = typeof args.password === 'string' ? args.password : undefined
  if (password === undefined) password = randomPassword(24)
  assertPasswordStrength(password, { force: args.force === true })
  config.security.passwordHash = await hashPassword(password)
  writeConfigFile(paths, config)
  loadConfig(undefined)
  printSecrets({
    username: config.security.username,
    password,
    configFile: paths.configFile,
  })
}

async function commandSetTotp(args) {
  const paths = gatePaths()
  const config = readConfigFile(paths)
  if (config.security?.passwordHash === undefined) throw new Error('no configuration yet; run "init" first')
  const secret = generateTotpSecret()
  const issuer = String(args.issuer ?? config.security.totp?.issuer ?? 'DeepSeek Harness')
  config.security.totp = {
    ...(config.security.totp ?? {}),
    secret,
    issuer,
    account: config.security.username,
  }
  config.security.allowPasswordOnly = false
  writeConfigFile(paths, config)
  loadConfig(undefined)
  printSecrets({
    username: config.security.username,
    totpSecret: secret,
    issuer,
    configFile: paths.configFile,
  })
  printQrHint()
}

function commandDisableTotp(args) {
  const paths = gatePaths()
  const config = readConfigFile(paths)
  if (config.security === undefined) throw new Error('no configuration yet; run "init" first')
  if (args.yes !== true) throw new Error('refusing without --yes; password-only logins are weaker')
  config.security.totp = { ...(config.security.totp ?? {}), secret: '' }
  config.security.allowPasswordOnly = true
  writeConfigFile(paths, config)
  process.stdout.write('TOTP disabled (allowPasswordOnly = true).\n')
}

/**
 * Adjust how long a browser stays logged in.
 *
 *   set-session --absolute-days 7 [--idle-days 7]
 *   set-session --absolute-hours 12 --idle-hours 2
 */
function commandSetSession(args) {
  const paths = gatePaths()
  const config = readConfigFile(paths)
  if (config.security === undefined) throw new Error('no configuration yet; run "init" first')

  const idleDays = args['idle-days'] !== undefined ? Number(args['idle-days']) : undefined
  const absoluteDays = args['absolute-days'] !== undefined ? Number(args['absolute-days']) : undefined
  const idleHours = args['idle-hours'] !== undefined ? Number(args['idle-hours']) : undefined
  const absoluteHours = args['absolute-hours'] !== undefined ? Number(args['absolute-hours']) : undefined

  if ([idleDays, absoluteDays, idleHours, absoluteHours].every((value) => value === undefined)) {
    throw new Error('nothing to change; pass --absolute-days / --absolute-hours (and optionally --idle-days / --idle-hours)')
  }
  for (const [label, value] of [
    ['--idle-days', idleDays],
    ['--absolute-days', absoluteDays],
    ['--idle-hours', idleHours],
    ['--absolute-hours', absoluteHours],
  ]) {
    if (value !== undefined && (!Number.isFinite(value) || value <= 0)) throw new Error(`${label} must be a positive number`)
  }

  config.session = { ...(config.session ?? {}) }
  if (idleDays !== undefined) config.session.idleMinutes = Math.round(idleDays * 24 * 60)
  if (idleHours !== undefined) config.session.idleMinutes = Math.round(idleHours * 60)
  if (absoluteDays !== undefined) config.session.absoluteHours = Math.round(absoluteDays * 24)
  if (absoluteHours !== undefined) config.session.absoluteHours = Math.round(absoluteHours)

  writeConfigFile(paths, config)
  const cfg = loadConfig(undefined)

  const days = (minutes) => (minutes / 1440).toFixed(minutes % 1440 === 0 ? 0 : 2)
  process.stdout.write(`idle timeout     : ${cfg.session.idleMinutes} min (${days(cfg.session.idleMinutes)} day)\n`)
  process.stdout.write(`absolute timeout : ${cfg.session.absoluteHours} h (${(cfg.session.absoluteHours / 24).toFixed(2)} day)\n`)
  process.stdout.write(`cookie Max-Age   : ${Math.round(cfg.session.absoluteHours * 3600)} s\n`)
  process.stdout.write('restart dsh for the change to take effect (active sessions keep their old expiry until re-login).\n')
}

function commandShow() {
  const paths = gatePaths()
  const cfg = loadConfig(undefined)
  process.stdout.write(`config      : ${paths.configFile}\n`)
  process.stdout.write(`listen      : https://${cfg.host}:${cfg.port}\n`)
  process.stdout.write(`login path  : ${cfg.loginPath}\n`)
  process.stdout.write(`username    : ${cfg.security.username}\n`)
  process.stdout.write(`password    : ${cfg.security.passwordHash.slice(0, 24)}… (scrypt)\n`)
  process.stdout.write(`second factor: ${cfg.secondFactor}\n`)
  if (cfg.secondFactor === 'email') {
    process.stdout.write(`email mode  : ${cfg.email.mode}\n`)
    process.stdout.write(`email to    : ${cfg.email.to.join(', ')}\n`)
    process.stdout.write(`smtp        : ${cfg.email.smtp.host}:${cfg.email.smtp.port} (secure=${cfg.email.smtp.secure})\n`)
    process.stdout.write(`code ttl    : ${cfg.email.code.ttlMinutes} min / ${cfg.email.code.maxAttempts} attempts\n`)
  } else {
    process.stdout.write(`totp        : ${cfg.security.totp.secret.length > 0 ? 'enabled' : 'DISABLED'}\n`)
  }
  process.stdout.write(`allowlist   : ${cfg.security.ipAllowlist.length > 0 ? cfg.security.ipAllowlist.join(', ') : '(any)'}\n`)
  process.stdout.write(`session     : idle ${cfg.session.idleMinutes}m / absolute ${cfg.session.absoluteHours}h\n`)
  process.stdout.write(`tls cert    : ${cfg.tls.certFile}\n`)
  process.stdout.write(`audit log   : ${cfg.audit.file}\n`)
  for (const warning of cfg.warnings ?? []) process.stdout.write(`warning     : ${warning}\n`)
}

/**
 * Configure email one-time-code login and optionally send a test message.
 *
 *   set-email --user <smtp user> --pass <smtp auth code> --to <recipient> [--test]
 */
/**
 * Configure email one-time-code login. The SMTP settings are proven with a test
 * message BEFORE anything is written, so a wrong 授权码 can never leave the
 * gate in a state where login mails fail and the owner is locked out.
 *
 *   set-email --user <smtp user> --pass <smtp auth code> --to <recipient> [--no-test]
 */
async function commandSetEmail(args) {
  const paths = gatePaths()
  const config = readConfigFile(paths)
  if (config.security === undefined) throw new Error('no configuration yet; run "init" first')

  const host = String(args.host ?? 'smtp.qq.com')
  const secure = args.starttls !== true
  const port = Number(args.port ?? (secure ? 465 : 587))
  const smtpUser = String(args.user ?? config.security?.username ?? '')
  const smtpPass = typeof args.pass === 'string' ? args.pass : ''
  if (smtpUser.length === 0) throw new Error('--user is required (the sending mailbox)')
  if (smtpPass.length === 0) throw new Error('--pass is required (for QQ mail this is the SMTP 授权码, not the account password)')
  const to = String(args.to ?? smtpUser)
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value.length > 0)
  if (to.length === 0) throw new Error('--to is required')

  const email = {
    ...(config.email ?? {}),
    enabled: true,
    mode: args.mode === 'password+code' ? 'password+code' : 'code-only',
    smtp: {
      ...(config.email?.smtp ?? {}),
      host,
      port,
      secure,
      requireAuth: true,
      user: smtpUser,
      pass: smtpPass,
      timeoutMs: 20_000,
      tlsInsecure: args.insecure === true,
    },
    from: String(args.from ?? smtpUser),
    fromName: String(args.name ?? 'DeepSeek Harness'),
    to,
    subject: String(args.subject ?? 'DeepSeek Harness 登录验证码'),
  }

  const shouldTest = args['no-test'] !== true
  if (shouldTest) {
    process.stdout.write(`testing SMTP ${host}:${port} (secure=${secure})…\n`)
    try {
      const result = await sendMail({
        host: email.smtp.host,
        port: email.smtp.port,
        secure: email.smtp.secure,
        requireAuth: email.smtp.requireAuth,
        user: email.smtp.user,
        pass: email.smtp.pass,
        from: email.from,
        to: email.to,
        subject: 'dsh-public-gate SMTP 测试',
        text: buildMessage({
          from: email.from,
          fromName: email.fromName,
          to: email.to,
          subject: 'dsh-public-gate SMTP 测试',
          text: [
            '这是一封来自 dsh-public-gate 的测试邮件。',
            '',
            '收到它说明 SMTP 配置正确，登录验证码可以正常发送。',
            '',
            `时间：${new Date().toISOString()}`,
          ].join('\n'),
        }),
        timeoutMs: email.smtp.timeoutMs,
        tlsInsecure: email.smtp.tlsInsecure === true,
      })
      process.stdout.write(`smtp accepted : ${result.response}\n`)
      process.stdout.write(`recipients    : ${result.accepted.join(', ')}\n`)
    } catch (error) {
      throw new Error(
        `SMTP 测试失败，配置未改动。请检查授权码/端口/发件权限。原始错误：${error instanceof Error ? error.message : String(error)}`,
      )
    }
  }

  // Email replaces TOTP as the second factor; the TOTP secret stays but unused.
  config.email = email
  writeConfigFile(paths, config)
  const cfg = loadConfig(undefined)

  process.stdout.write(`email enabled : ${cfg.email.mode} -> ${cfg.email.to.join(', ')}\n`)
  process.stdout.write(`smtp          : ${cfg.email.smtp.host}:${cfg.email.smtp.port} secure=${cfg.email.smtp.secure}\n`)
  process.stdout.write(`second factor : ${cfg.secondFactor}\n`)
  process.stdout.write('restart dsh for the change to take effect.\n')
}


async function commandTestEmail() {
  const cfg = loadConfig(undefined)
  if (cfg.email.enabled !== true) throw new Error('email is not enabled; run "set-email" first')
  const result = await sendMail({
    host: cfg.email.smtp.host,
    port: cfg.email.smtp.port,
    secure: cfg.email.smtp.secure,
    requireAuth: cfg.email.smtp.requireAuth,
    user: cfg.email.smtp.user,
    pass: cfg.email.smtp.pass,
    from: cfg.email.from,
    to: cfg.email.to,
    subject: 'dsh-public-gate SMTP 测试',
    text: buildMessage({
      from: cfg.email.from,
      fromName: cfg.email.fromName,
      to: cfg.email.to,
      subject: 'dsh-public-gate SMTP 测试',
      text: `测试邮件 / test message\n\n时间：${new Date().toISOString()}`,
    }),
    timeoutMs: cfg.email.smtp.timeoutMs,
    tlsInsecure: cfg.email.smtp.tlsInsecure === true,
  })
  process.stdout.write(`smtp accepted: ${result.response}\n`)
}

async function commandGenTls(args) {
  const paths = gatePaths()
  const config = readConfigFile(paths)
  const tls = {
    certFile: config.tls?.certFile ?? paths.certFile,
    keyFile: config.tls?.keyFile ?? paths.keyFile,
    autoGenerate: true,
    subjectAltNames:
      args.san === undefined
        ? (config.tls?.subjectAltNames ?? [])
        : String(args.san).split(',').map((s) => s.trim()),
  }
  // Remove existing material so resolveTls regenerates it.
  const { unlinkSync } = await import('node:fs')
  for (const file of [tls.certFile, tls.keyFile]) {
    try {
      unlinkSync(file)
    } catch {
      /* not present */
    }
  }
  const result = await resolveTls(tls, config.host ?? '0.0.0.0')
  process.stdout.write(`certificate : ${tls.certFile} (${result.source})\n`)
  process.stdout.write(`SANs        : ${(result.subjectAltNames ?? tls.subjectAltNames).join(', ')}\n`)
}

function usage() {
  process.stdout.write(`dsh-gate-tool commands:

  init [--user admin] [--password <pw>] [--port 8443] [--host 0.0.0.0]
       [--no-totp] [--san IP:1.2.3.4] [--force]
  set-password [--password <pw>]
  set-totp [--issuer "DeepSeek Harness"]
  disable-totp --yes
  set-email --user <smtp user> --pass <smtp auth code> --to <addr[,addr]>
            [--mode code-only|password+code] [--host smtp.qq.com] [--port 465]
            [--starttls] [--insecure] [--from <addr>] [--name <display>] [--no-test]
  test-email
  set-session --absolute-days 7 [--idle-days 7]   |  --absolute-hours N --idle-hours N
  show
  gen-tls [--san IP:1.2.3.4,IP:127.0.0.1]
`)
}

async function main() {
  const argv = process.argv.slice(2)
  const args = parseArgs(argv)
  const command = args._[0]
  switch (command) {
    case 'init':
      return commandInit(args)
    case 'set-password':
      return commandSetPassword(args)
    case 'set-totp':
      return commandSetTotp(args)
    case 'disable-totp':
      return commandDisableTotp(args)
    case 'set-email':
      return commandSetEmail(args)
    case 'test-email':
      return commandTestEmail()
    case 'set-session':
      return commandSetSession(args)
    case 'show':
      return commandShow()
    case 'gen-tls':
      return commandGenTls(args)
    default:
      usage()
      if (command !== undefined) process.exitCode = 1
  }
}

main().catch((error) => {
  process.stderr.write(`dsh-gate-tool: ${error instanceof Error ? error.message : String(error)}\n`)
  process.exitCode = 1
})

