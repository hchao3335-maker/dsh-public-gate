/**
 * dsh-public-gate — plugin entry.
 *
 * Starts the public HTTPS gate after the harness web server is up and keeps
 * dsh's own listener on loopback. See README.md for the security model.
 */
import { GateServer } from './gate.js'
import { loadConfig } from './config.js'

export const name = 'public-gate'

/** The gate needs the HTTP carrier and the authenticated browser connection. */
export const inject = ['webServer', 'connection']

/**
 * @param ctx - cordis plugin context.
 * @param rowConfig - optional `config:` object from the plugin row.
 */
export function apply(ctx, rowConfig) {
  if (process.env.DSH_PUBLIC_GATE_DISABLE === '1') {
    process.stderr.write('public-gate: disabled by DSH_PUBLIC_GATE_DISABLE=1\n')
    return
  }

  // A fresh install has no credentials yet. Stay inactive instead of failing the
  // harness boot: nothing is exposed until the gate is configured, then restart.
  let cfg
  try {
    cfg = loadConfig(rowConfig)
  } catch (error) {
    process.stderr.write(
      `public-gate: not started — ${error instanceof Error ? error.message : String(error)}\n` +
        'public-gate: nothing is exposed while unconfigured. Create the credentials with:\n' +
        'public-gate:   cd <profile dir> && ./node_modules/.bin/dsh-gate-tool init --user admin\n' +
        'public-gate: then restart dsh.\n',
    )
    return
  }

  const gate = new GateServer(ctx, cfg)

  ctx.effect(() => {
    let stopped = false
    const startPromise = gate.start().catch((error) => {
      // Fail closed: without the gate nothing is exposed publicly.
      process.stderr.write(
        `public-gate: failed to start on ${cfg.host}:${cfg.port}: ${error instanceof Error ? error.message : String(error)}\n`,
      )
      throw error
    })
    return () => {
      stopped = true
      void startPromise.catch(() => {})
      return gate.stop()
    }
  }, 'public-gate: public HTTPS listener')

  // Make the SPA believe it owns the host so settings persistence and file
  // opening keep working over the public origin.
  if (cfg.security.emulateLoopback !== false) {
    ctx.effect(
      () =>
        ctx.on('webserver/index-inject', (table) => {
          table.push({
            kind: 'script',
            placement: 'head',
            text: 'globalThis.__DSH_TRANSPORT__=Object.assign({},globalThis.__DSH_TRANSPORT__,{ownsHost:true});',
          })
        }),
      'public-gate: loopback emulation injection',
    )
  }

  process.stderr.write(
    `public-gate: listening on https://${cfg.host}:${cfg.port} (login ${cfg.loginPath}, ` +
      `factor ${cfg.secondFactor}, allowlist ${cfg.security.ipAllowlist.length})\n`,
  )
}
