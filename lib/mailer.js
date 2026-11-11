/**
 * Email composition for the login code.
 *
 * The body is base64-encoded so dot-stuffing, long lines and non-ASCII text are
 * all handled by the transport rather than by SMTP quoting rules.
 */
import { randomUUID } from 'node:crypto'

import { sendMail } from './smtp.js'

function encodeHeaderText(value) {
  const text = String(value)
  // Keep pure-ASCII headers readable; encode anything else per RFC 2047.
  if (/^[\x20-\x7e]*$/.test(text)) return text
  return `=?UTF-8?B?${Buffer.from(text, 'utf8').toString('base64')}?=`
}

function base64Body(text) {
  const encoded = Buffer.from(text, 'utf8').toString('base64')
  const lines = []
  for (let index = 0; index < encoded.length; index += 76) lines.push(encoded.slice(index, index + 76))
  return lines.join('\r\n')
}

/** RFC 5322 message with a base64 text/plain body. */
export function buildMessage({ from, fromName, to, subject, text, date = new Date(), messageId }) {
  const displayName = fromName === undefined || fromName === '' ? '' : `${encodeHeaderText(fromName)} `
  const headers = [
    `From: ${displayName}<${from}>`,
    `To: ${to.join(', ')}`,
    `Subject: ${encodeHeaderText(subject)}`,
    `Date: ${date.toUTCString()}`,
    `Message-ID: <${messageId ?? `${randomUUID()}@dsh-public-gate`}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset="UTF-8"',
    'Content-Transfer-Encoding: base64',
    'Auto-Submitted: auto-generated',
    'X-DSH-Public-Gate: login-code',
  ]
  return `${headers.join('\r\n')}\r\n\r\n${base64Body(text)}\r\n`
}

export function codeEmailText({ code, ttlMinutes, ip, userAgent, issuedAt = new Date(), host }) {
  return [
    '你的 DeepSeek Harness 登录验证码',
    '',
    `    ${code}`,
    '',
    `验证码 ${ttlMinutes} 分钟内有效，只能使用一次。`,
    '',
    '— 请求信息 —',
    `时间：${issuedAt.toISOString()}`,
    `来源 IP：${ip ?? '未知'}`,
    `目标主机：${host ?? '未知'}`,
    `客户端：${String(userAgent ?? '未知').slice(0, 160)}`,
    '',
    '如果这不是你本人操作，说明有人在尝试登录你的服务器：',
    '请立即修改服务器密码、检查登录审计日志，并考虑更换本页面的登录方式。',
    '',
    '此邮件由 dsh-public-gate 自动发送，请勿直接回复。',
  ].join('\n')
}

/**
 * Deliver one login code.
 * @returns the SMTP result plus the message id.
 */
export async function sendCodeEmail({ email, smtp, code, ttlMinutes, ip, userAgent, host, logger }) {
  const messageId = `${randomUUID()}@dsh-public-gate`
  const text = codeEmailText({ code, ttlMinutes, ip, userAgent, host })
  const message = buildMessage({
    from: email.from,
    fromName: email.fromName,
    to: email.to,
    subject: email.subject ?? 'DeepSeek Harness 登录验证码',
    text,
    messageId,
  })
  logger?.('email.sending', { to: email.to.join(','), messageId })
  const result = await sendMail({
    host: smtp.host,
    port: smtp.port,
    secure: smtp.secure,
    requireAuth: smtp.requireAuth,
    user: smtp.user,
    pass: smtp.pass,
    from: email.from,
    to: email.to,
    subject: email.subject,
    text: message,
    timeoutMs: smtp.timeoutMs,
    tlsInsecure: smtp.tlsInsecure === true,
  })
  return { ...result, messageId }
}
