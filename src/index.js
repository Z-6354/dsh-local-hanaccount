import { API_PREFIX } from './lib/util.js'
import { createStore } from './lib/store.js'
import { createGate, wrapWebServer } from './gate.js'
import { createApiHandler } from './api.js'
import { installOutboundFetch } from './lib/outbound-fetch.js'

export const name = 'dsh-local-hanaccount'
export const inject = ['webServer']

const DEFAULTS = {
  enabled: true,
  dataDir: '',
}

export async function apply(ctx, config = {}) {
  const cfg = { ...DEFAULTS, ...config }
  if (cfg.enabled === false) return

  const webServer = ctx.get('webServer')
  if (!webServer) {
    ctx.logger?.warn?.('[dsh-local-hanaccount] webServer unavailable; not mounting')
    return
  }

  const store = createStore(cfg)
  const gate = createGate(store)
  const unpatchWeb = wrapWebServer(webServer, gate, store)
  const unpatchFetch = installOutboundFetch(store.peers)

  const disposer = webServer.register({
    kind: 'prefix',
    path: API_PREFIX,
    handler: createApiHandler({ store, gate }),
  })

  ctx.provide?.('dshLocalHanaccount', {
    dataDir: store.dataDir,
    store: () => store,
    peers: store.peers,
  })

  ctx.on('dispose', () => {
    try { disposer() } catch {}
    try { unpatchWeb() } catch {}
    try { unpatchFetch() } catch {}
  })
}

export const _internals = {
  createStore,
  createGate,
  wrapWebServer,
  createApiHandler,
}
