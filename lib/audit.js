/**
 * Append-only audit trail.
 *
 * Writes one JSON object per line to the configured file (rotated by size) and,
 * when enabled, a syslog-style line to stderr so journald and fail2ban can act
 * on it. Secrets — passwords, TOTP codes, session ids, the upstream dsh cookie —
 * are never written.
 */
import { appendFileSync, mkdirSync, renameSync, statSync } from 'node:fs'
import { dirname } from 'node:path'

export class AuditLog {
  #file
  #maxBytes
  #syslog
  #disabled = false

  constructor({ file, maxBytes, syslog }) {
    this.#file = file
    this.#maxBytes = maxBytes
    this.#syslog = syslog !== false
    try {
      mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
    } catch {
      this.#disabled = true
    }
  }

  #rotateIfNeeded() {
    try {
      const stats = statSync(this.#file)
      if (stats.size > this.#maxBytes) renameSync(this.#file, `${this.#file}.1`)
    } catch {
      /* first write or rotation raced; nothing to do */
    }
  }

  /**
   * Record one event.
   * @param event - stable event name, e.g. `login.failed`.
   * @param fields - non-secret context (ip, user, reason, status, ms).
   */
  write(event, fields = {}) {
    const record = { ts: new Date().toISOString(), event, ...fields }
    if (!this.#disabled) {
      try {
        this.#rotateIfNeeded()
        appendFileSync(this.#file, `${JSON.stringify(record)}\n`, { mode: 0o600 })
      } catch {
        this.#disabled = true
      }
    }
    if (this.#syslog) {
      const detail = Object.entries(fields)
        .filter(([, value]) => value !== undefined)
        .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
        .join(' ')
      // One line per event; systemd-journald tags it with the unit name.
      process.stderr.write(`public-gate: ${event} ${detail}\n`)
    }
  }
}
