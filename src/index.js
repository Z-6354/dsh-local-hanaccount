import { createDshAdapter } from './lib/dsh-adapter.js'
import { API_PREFIX } from './lib/util.js'
import { createStore } from './lib/store.js'
import { createGate, wrapWebServer } from './gate.js'
import { createApiHandler } from './api.js'
import { installOutboundFetch } from './lib/outbound-fetch.js'

export const name = 'dsh-local-hanaccount'
export const inject = ['webServer', 'connection']

const DEFAULTS = {
  enabled: true,
  dataDir: '',
  outboundFetchEnabled: false,
}

export async function apply(ctx, config = {}) {
  const cfg = { ...DEFAULTS, ...config }
  const webServer = ctx.get('webServer')
  const adapter = createDshAdapter(webServer, ctx.get('connection'), cfg)
  let store, gate, unpatchFetch, disposer, disposed = false
  function dispose(code = 'auth_disposed') {
    if (disposed) return
    disposed = true
    store?.retire()
    adapter.stop(code)
    gate?.dispose()
    try { disposer?.() } catch {}
    try { unpatchFetch?.() } catch {}
  }
  try {
    if (cfg.enabled === false) throw Object.assign(new Error('auth_disabled'), {code:'auth_disabled'})
    if (typeof ctx.effect !== 'function') throw Object.assign(new Error('context_unsupported'), {code:'context_unsupported'})
    store = createStore(cfg, {onStorageFailure:() => dispose('storage_unavailable')})
    const bridge = adapter.bridge
    gate = createGate(store, bridge)
    disposer = webServer.register({
      kind: 'prefix',
      path: API_PREFIX,
      handler: createApiHandler({ store, gate, bridge, securityState:adapter.state, isCurrent:() => !disposed && adapter.isCurrent(), onSecurityFailure:() => dispose('storage_unavailable') }),
    })
    ctx.effect(() => dispose, 'hanaccount: security lifecycle')
    ctx.provide?.('dshLocalHanaccount', {
      dataDir: store.dataDir,
      store: () => store,
      peers: store.peers,
      securityState: adapter.state,
    })
    adapter.activate(gate)
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
