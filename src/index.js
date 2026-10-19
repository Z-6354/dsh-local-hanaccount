import { createDshAdapter } from './lib/dsh-adapter.js'
import { API_PREFIX } from './lib/util.js'
import { createStore } from './lib/store.js'
import { createGate, wrapWebServer } from './gate.js'
import { createApiHandler } from './api.js'
import { installOutboundFetch } from './lib/outbound-fetch.js'
import { installAuthBootstrap } from './lib/auth-bootstrap.js'
import { createRpcAuthorization } from './lib/rpc-authorization.js'
import { applyInitialPassword, PASSWORD_ENV, PASSWORD_FILE_ENV } from './lib/initial-password.js'

export const name = 'dsh-local-hanaccount'
export const inject = ['webServer', 'connection']

const DEFAULTS = {
  enabled: true,
  dataDir: '',
  outboundFetchEnabled: false,
  rpcGrantTtlMs: 120_000,
}

export async function apply(ctx, config = {}) {
  const cfg = { ...DEFAULTS, ...config }
  const webServer = ctx.get('webServer')
  const adapter = createDshAdapter(webServer, ctx.get('connection'), cfg)
  let store, gate, unpatchFetch, routeDisposer, bootstrapDisposer, rpcAuthorization, disposed = false
  const securityState = () => ({...adapter.state(), rpcAuthorization:rpcAuthorization?.state()})
  function dispose(code = 'auth_disposed') {
    if (disposed) return
    disposed = true
    rpcAuthorization?.dispose()
    store?.retire()
    adapter.stop(code)
    gate?.dispose()
    try { routeDisposer?.() } catch {}
    try { bootstrapDisposer?.() } catch {}
    try { unpatchFetch?.() } catch {}
  }
  try {
    if (cfg.enabled === false) throw Object.assign(new Error('auth_disabled'), {code:'auth_disabled'})
    if (typeof ctx.effect !== 'function') throw Object.assign(new Error('context_unsupported'), {code:'context_unsupported'})
    store = createStore(cfg, {onStorageFailure:() => dispose('storage_unavailable')})
    // Browser setup is closed; the first password comes from the environment (or scripts/set-password.mjs).
    try { applyInitialPassword(store, { logger: ctx.logger }) }
    catch { ctx.logger?.warn?.('[dsh-local-hanaccount] initial password could not be applied') }
    if (!store.cfg.passwordHash) ctx.logger?.warn?.(`[dsh-local-hanaccount] no access password is set; set ${PASSWORD_FILE_ENV} (or ${PASSWORD_ENV}) and restart, or run scripts/set-password.mjs while DSH is stopped`)
    const bridge = adapter.bridge
    gate = createGate(store, bridge)
    rpcAuthorization = createRpcAuthorization({ store, connection: ctx.get('connection'), bridge, gate, isCurrent:() => !disposed && adapter.isCurrent(), ttlMs:cfg.rpcGrantTtlMs })
    if (!rpcAuthorization.state().available) ctx.logger?.warn?.(`[dsh-local-hanaccount] RPC grants unavailable; missing ${rpcAuthorization.state().missingCapabilities.join(', ')}. Password login remains available; use a DSH connection with admit and browserPeer (or legacy operator) for RPC grants.`)
    routeDisposer = webServer.register({
      kind: 'prefix',
      path: API_PREFIX,
      handler: createApiHandler({ store, gate, bridge, rpcAuthorization, securityState, isCurrent:() => !disposed && adapter.isCurrent(), onSecurityFailure:() => dispose('storage_unavailable') }),
    })
    ctx.effect(() => dispose, 'hanaccount: security lifecycle')
    ctx.provide?.('dshLocalHanaccount', {
      dataDir: store.dataDir,
      store: () => store,
      peers: store.peers,
      securityState,
    })
    ctx.provide?.('hanaccountRpcAuthorization', rpcAuthorization)
    adapter.activate(gate)
    bootstrapDisposer = installAuthBootstrap(ctx)
  } catch (err) {
    dispose(err.code || 'auth_initialization_failed')
    throw err
  }
  // Optional outbound peer enhancement has its own failure boundary. It is not
  // needed by a browser's password login or by the official page protocol.
  if (cfg.outboundFetchEnabled) {
    try { unpatchFetch = installOutboundFetch(store.peers) }
    catch { ctx.logger?.warn?.('[dsh-local-hanaccount] outbound enhancement unavailable') }
  }
}

export const _internals = {
  createStore,
  createGate,
  wrapWebServer,
  createApiHandler,
}
