/**
 * Smoke-test the browser bundle without a browser: evaluate client.js against a
 * fake `window.__ModuleLoader__`, then call the exported apply() with a fake
 * client context and assert the settings.section registration.
 *
 *   node test/client-selftest.mjs
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import vm from 'node:vm'

const file = join(import.meta.dirname, '..', 'lib', 'client.js')
const source = readFileSync(file, 'utf8')

let registration
const sandbox = {
  window: {
    __ModuleLoader__: {
      load(entry) {
        registration = entry
      },
    },
  },
  fetch: async () => {
    throw new Error('offline')
  },
  console,
  setTimeout,
  clearTimeout,
}
sandbox.globalThis = sandbox
vm.createContext(sandbox)
vm.runInContext(source, sandbox, { filename: 'client.js' })

assert.ok(registration !== undefined, 'bundle registered itself with the module loader')
assert.equal(registration.id, 'dsh-public-gate', 'module id matches the served specifier')

let passed = 0
function check(name, condition, detail = '') {
  assert.ok(condition, `${name}${detail ? ` [${detail}]` : ''}`)
  passed += 1
  console.log(`ok - ${name}`)
}

const stubs = {
  react: {
    createElement: () => undefined,
    useState: () => [undefined, () => {}],
    useEffect: () => {},
    useCallback: (fn) => fn,
  },
}
const exports = registration.factory((specifier) => {
  if (specifier === 'react') return stubs.react
  if (specifier === 'react/jsx-runtime') return { jsx: () => undefined, jsxs: () => undefined }
  throw new Error(`unexpected require: ${specifier}`)
})

check('bundle exports apply()', typeof exports.apply === 'function')
check('bundle declares the slots service', Array.isArray(exports.inject) && exports.inject.includes('slots'))

let registerArgs
const effects = []
const ctx = {
  effect(factory, label) {
    const dispose = factory()
    effects.push({ label, dispose })
    return dispose
  },
  slots: {
    inject(name, factory) {
      assert.equal(name, 'settings.section', 'registered while the section slot is live')
      return factory()
    },
    register(options, component) {
      registerArgs = { options, component }
      return () => {}
    },
  },
}

exports.apply(ctx)

check('apply() registers into settings.section', registerArgs !== undefined && registerArgs.options.name === 'settings.section')
check('section id is public-gate', registerArgs.options.id === 'public-gate')
check('section exposes a nav label', registerArgs.options.label() === '公网访问')
check('section component is a function', typeof registerArgs.component === 'function')
check('registration is owned by an effect', effects.length === 1 && effects[0].label.includes('public-gate'))

console.log(`\n${passed} client checks passed`)
process.exit(0)
