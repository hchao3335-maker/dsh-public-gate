/**
 * A freshly installed plugin has no credentials yet. Installing it must not
 * break the harness boot, and it must not open a listener before it is
 * configured.
 *
 *   node test/install-selftest.mjs
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const home = mkdtempSync(join(tmpdir(), 'gate-install-'))
process.env.DSH_HOME = home

const messages = []
const originalWrite = process.stderr.write.bind(process.stderr)
process.stderr.write = (chunk) => {
  messages.push(String(chunk))
  return true
}

const { apply } = await import('../lib/index.js')

const effects = []
const ctx = {
  effect(factory) {
    effects.push(factory())
    return () => {}
  },
  on() {
    return () => {}
  },
  get() {
    return undefined
  },
  webServer: { getOrigin: () => 'http://127.0.0.1:3080/' },
  connection: { authenticatedUrl: (url) => `${url}?token=test` },
}

let thrown
try {
  apply(ctx, undefined)
} catch (error) {
  thrown = error
}

process.stderr.write = originalWrite
const stderr = messages.join('')

assert.equal(thrown, undefined, 'an unconfigured install must not throw during activation')
assert.equal(effects.length, 0, 'no listener or injection is registered while unconfigured')
assert.ok(stderr.includes('public-gate: not started'), 'the reason is logged')
assert.ok(stderr.includes('dsh-gate-tool init'), 'the fix (CLI init) is logged')
assert.ok(!stderr.includes('EADDRINUSE'), 'no bind is attempted')

console.log('ok - unconfigured install stays inactive')
console.log('ok - boot is not broken')
console.log('ok - the remediation command is logged')

rmSync(home, { recursive: true, force: true })
console.log('\n3 install checks passed')
process.exit(0)
