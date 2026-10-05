export const AUTH_PROTOCOL = 'password-native-v1'
export const ADAPTER_ID = 'dsh-0a15e36-web-auth-v1'
export const AUDITED_BUILD = '0a15e36e7f82b6ed45af6fa9759f29b40dcd965d'

function failure(code = 'native_bridge_unavailable', status = 503) {
  return Object.assign(new Error(code), { code, status })
}

// Only the public connection owner can mint and verify its native cookie.
export function createNativeBridge(connection) {
  for (const method of ['requestRejection', 'authenticatedUrl', 'authorizeIndex']) {
    if (typeof connection?.[method] !== 'function') throw failure()
  }
  let disposed = false
  function fence(req) {
    if (disposed) throw failure()
    const rejection = connection.requestRejection(req)
    if (rejection === 403) throw failure('access_denied', 403)
    if (rejection !== undefined && rejection !== 401) throw failure()
    return rejection
  }
  function mint(req, secure = false) {
    fence(req)
    let status, headers, ended = false
    try {
      const internal = new URL(connection.authenticatedUrl(`http://${req.headers.host}`))
      const request = Object.create(req)
      Object.defineProperties(request, {
        method: { value: 'GET' }, url: { value: internal.pathname + internal.search },
      })
      const allowed = connection.authorizeIndex(request, {
        writeHead(code, values) { status = code; headers = values },
        end() { ended = true },
      })
      const cookie = headers?.['set-cookie']
      if (allowed !== false || !ended || status !== 303 || headers?.location !== '/'
        || typeof cookie !== 'string' || !/^dsh-auth-[^=;\s]+=/.test(cookie)
        || cookie.includes('\r') || cookie.includes('\n')) throw failure()
      const check = Object.create(req)
      Object.defineProperty(check, 'headers', { value: { ...req.headers, cookie: cookie.split(';')[0] } })
      if (connection.requestRejection(check) !== undefined) throw failure()
      return secure && !/;\s*Secure(?:;|$)/i.test(cookie) ? `${cookie}; Secure` : cookie
    } catch (err) {
      if (err?.code === 'access_denied') throw err
      throw failure()
    }
  }
  return {
    fence, mint,
    authenticated(req) { return fence(req) === undefined },
    clear(req, secure = false) {
      const name = mint(req, secure).split('=')[0]
      return `${name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? '; Secure' : ''}`
    },
    dispose() { disposed = true },
  }
}

// Wrap Map.set synchronously: official WebServer.register uses these maps.
// Direct mutation of a route.handler or replacement of a map is unsupported.
const installations = new WeakMap()
export function installRouteGate(webServer, gate, {permanent = false} = {}) {
  // Audited Cordis 4.0.2 service reads return fresh traceable proxies. Route
  // ownership belongs to the original instance, not a caller's proxy identity.
  webServer = webServer?.[Symbol.for('cordis.original')] || webServer
  if (installations.has(webServer)) throw new Error('hanaccount gate already installed')
  for (const slot of ['prefixes', 'exact', 'upgrades']) {
    if (!(webServer[slot] instanceof Map)) throw new Error(`unsupported WebServer route table: ${slot}`)
    const ownSet = Object.getOwnPropertyDescriptor(webServer[slot], 'set')
    if (ownSet && (!ownSet.configurable || !ownSet.writable)) throw new Error('unsupported route table setter')
    if (!ownSet && !Object.isExtensible(webServer[slot])) throw new Error('unsupported route table setter')
    for (const route of webServer[slot].values()) {
      const handler = Object.getOwnPropertyDescriptor(route, 'handler')
      if (!handler || typeof handler.value !== 'function' || !handler.writable || !handler.configurable || !Object.isExtensible(route)) throw new Error('unsupported route handler')
    }
  }
  const restores = []
  const tableIdentities = []
  const descriptor = Object.getOwnPropertyDescriptor(webServer, 'fallback')
  if (!descriptor || !descriptor.configurable || !('value' in descriptor)
    || (descriptor.value !== undefined && typeof descriptor.value !== 'function')) throw new Error('unsupported WebServer fallback seat')
  let fallbackOriginal = descriptor.value
  let fallbackWrapped = fallbackOriginal && gate.wrapHttpHandler(fallbackOriginal)
  Object.defineProperty(webServer, 'fallback', {configurable:true, enumerable:descriptor.enumerable,
    get() { return fallbackWrapped },
    set(handler) {
      if (handler !== undefined && typeof handler !== 'function') throw new Error('unsupported WebServer fallback handler')
      fallbackOriginal = handler; fallbackWrapped = handler && gate.wrapHttpHandler(handler)
    },
  })
  if (!permanent) restores.push(() => Object.defineProperty(webServer, 'fallback', {...descriptor, value:fallbackOriginal}))
  else descriptor.value = undefined
  const wrappers = new WeakSet()
  const slots = ['prefixes', 'exact', 'upgrades']
  for (const slot of slots) {
    const map = webServer[slot]
    if (!map?.set || !map?.entries) continue
    const originalSet = map.set
    const ownSet = Object.getOwnPropertyDescriptor(map, 'set')
    function wrap(path, route) {
      if (!route || typeof route.handler !== 'function') throw new Error('unsupported route handler')
      if (wrappers.has(route.handler)) return
      const handler = Object.getOwnPropertyDescriptor(route, 'handler')
      if (!handler || !handler.writable || !handler.configurable || !Object.isExtensible(route)) throw new Error('unsupported route handler')
      const original = route.handler
      const wrapped = slot === 'upgrades' ? gate.wrapUpgradeHandler(original) : gate.wrapHttpHandler(original)
      wrappers.add(wrapped)
      route.handler = wrapped
      route.__dshGateWrapped = true
      if (!permanent) restores.push(() => { if (route.handler === wrapped) { route.handler = original; delete route.__dshGateWrapped } })
    }
    for (const [path, route] of map.entries()) wrap(path, route)
    const patchedSet = function(path, route) {
      try { wrap(path, route); return originalSet.call(this, path, route) }
      catch (error) { gate.onAdapterFailure?.(); throw error }
    }
    map.set = patchedSet
    tableIdentities.push([slot, map, patchedSet])
    if (!permanent) restores.push(() => {
      if (map.set !== patchedSet) return
      if (ownSet) Object.defineProperty(map, 'set', ownSet)
      else delete map.set
    })
  }
  let disposed = false
  const dispose = () => {
    if (permanent) throw new Error('permanent auth guard cannot be unwrapped')
    if (disposed) return
    disposed = true
    for (const undo of restores.reverse()) undo()
    installations.delete(webServer)
  }
  installations.set(webServer, dispose)
  dispose.intact = () => tableIdentities.every(([slot, map, set]) => webServer[slot] === map && map.set === set
    && [...map.values()].every(route => wrappers.has(route.handler)))
    && webServer.fallback === fallbackWrapped
    && typeof Object.getOwnPropertyDescriptor(webServer, 'fallback')?.get === 'function'
  return dispose
}

// This protects only the audited dispatcher. An optional plugin cannot prevent
// import/activation failures from leaving the official listener available.
// Retaining a closed gate is intentional: removing it on unload revives copied
// official cookies. Only disposal of the listener releases this tombstone.
const guards = new WeakMap()
export function createDshAdapter(webServer, connection, config = {}) {
  webServer = webServer?.[Symbol.for('cordis.original')] || webServer
  const previous = guards.get(webServer)
  if (config.officialBuild !== AUDITED_BUILD) {
    previous?.stop('official_build_unsupported')
    throw failure('official_build_unsupported')
  }
  if (config.enabled === false) previous?.stop('auth_disabled')
  if (previous?.ready) throw failure('auth_already_active')
  previous?.stop('auth_reapplying')
  for (const method of ['register', 'registerUpgrade', 'registerFallback']) {
    if (typeof webServer?.[method] !== 'function') throw failure('webserver_unsupported')
  }
  let guard = previous
  if (!guard) {
    let gate, owner, ready = false, code = 'auth_starting'
    let installation
    function stop(reason = 'auth_unavailable') {
      ready = false; code = reason
      if (owner) owner.code = reason
      owner = undefined
      const retiring = gate; gate = undefined
      retiring?.dispose()
    }
    function intact() {
      return installation.intact()
    }
    function available() {
      if (ready && !intact()) stop('route_adapter_changed')
      return ready && gate
    }
    const wrappers = {
      onAdapterFailure() { stop('route_adapter_changed') },
      wrapHttpHandler(original) {
        return (req, res) => {
          const current = available()
          if (!current) { res.writeHead(503, {'content-type':'application/json', 'cache-control':'no-store'}); res.end(JSON.stringify({code:'auth_unavailable',error:'auth_unavailable'})); return }
          return current.wrapHttpHandler(original)(req, res)
        }
      },
      wrapUpgradeHandler(original) {
        return (req, socket, head) => {
          const current = available()
          if (!current) { socket.destroy(); return }
          return current.wrapUpgradeHandler(original)(req, socket, head)
        }
      },
    }
    installation = installRouteGate(webServer, wrappers, {permanent:true})
    guard = {stop, get ready() { return !!available() },
      claim(epoch) { owner = epoch; code = epoch.code },
      owns(epoch) { return owner === epoch },
      activate(value, epoch) {
        if (owner !== epoch) throw failure('auth_retired')
        gate = value; ready = true; code = epoch.code = 'auth_ready'
      },
      isCurrent(epoch) { return owner === epoch && !!available() },
      state() { return {adapterId:ADAPTER_ID, officialBuild:AUDITED_BUILD, buildIdentity:'operator-attestation', ready:!!available(), code, deploymentReady:false} },
    }
    guards.set(webServer, guard)
  }
  const epoch = {code:'auth_starting'}
  guard.claim(epoch)
  let bridge
  try { bridge = createNativeBridge(connection) }
  catch (error) { guard.stop('native_bridge_unavailable'); throw error }
  let stopped = false
  return {
    bridge,
    isCurrent: () => !stopped && guard.isCurrent(epoch),
    state() {
      const state = guard.state()
      return guard.owns(epoch) ? state : {...state, ready:false, code:epoch.code}
    },
    activate(gate) { if (stopped) throw failure(); guard.activate(gate, epoch) },
    stop(code) {
      if (stopped) return
      stopped = true
      if (guard.owns(epoch)) guard.stop(code)
      bridge.dispose()
    },
  }
}
