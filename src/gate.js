import { detectNginxMisconfig, evaluateIpAccess, ipInList, resolveClientIp } from './lib/ip.js'
import {
  BUILTIN_AUTH_EXCLUDE_PREFIXES,
  isAuthExcluded,
  shouldWrapPrefix,
} from './lib/route-policy.js'
import { parseCookies, sendJson, sendText, COOKIE } from './lib/util.js'
import { randomBytes } from 'node:crypto'
import { renderLoginPage } from './lib/login-page.js'

const PUBLIC_API_SUFFIXES = [
  'auth/me',
  'auth/login',
  'auth/setup',
  'auth/key/challenge',
  'auth/key/verify',
  'auth/passkey/login/options',
  'auth/passkey/login/verify',
  'peers/pair',
  'nginx/snippet',
  'status',
]

function isPublicPluginApi(pathname) {
  if (!pathname.startsWith('/dsh-local-hanaccount/api/')) return false
  const sub = pathname.slice('/dsh-local-hanaccount/api/'.length).replace(/^\/+/, '')
  return PUBLIC_API_SUFFIXES.includes(sub)
}

function bearerToken(req) {
  const auth = String(req.headers?.authorization || '')
  if (!auth.startsWith('Bearer ')) return ''
  return auth.slice(7).trim()
}

export function createGate(store, bridge) {
  const active = new Map()
  function recheckSockets() {
    for (const [socket, req] of active) {
      const session = parseCookies(req)[COOKIE]
      if (ipContext(req).verdict.action === 'block' || (session && !store.sessionFromToken(session, {touch:false})) || !isAuthenticated(req, false)) {
        active.delete(socket)
        socket.destroy()
      }
    }
  }
  const unsubscribe = store.onSecurityChange?.(recheckSockets)
  const expiryTimer = setInterval(recheckSockets, 60000)
  expiryTimer.unref()
  function clientIp(req) {
    return resolveClientIp(req, { trustProxy: store.cfg.trustProxy })
  }

  function ipContext(req) {
    const ip = clientIp(req)
    const verdict = evaluateIpAccess(ip, store.cfg)
    return { ip, verdict }
  }

  function isSessionAuthenticated(req, touch = true) {
    if (!store.cfg.passwordHash) return false
    const token = parseCookies(req)[COOKIE]
    return !!store.sessionFromToken(token, {touch})
  }

  function isBearerAuthenticated(req) {
    const raw = bearerToken(req)
    if (!raw) return false
    return !!store.tokens.verifyAny(raw, store.peers.inboundVerifierEntries())
  }

  function isAuthenticated(req, touch = true) {
    const gateAuthenticated = isSessionAuthenticated(req, touch) || isBearerAuthenticated(req)
    if (!gateAuthenticated) return false
    try { return !bridge || bridge.authenticated(req) } catch { return false }
  }

  function recordIfSuspicious(ip, reason, req, { whitelisted = false } = {}) {
    if (whitelisted || ipInList(ip, store.cfg.allow)) return
    store.visitors.record(ip, reason, {
      path: new URL(req.url ?? '/', 'http://x').pathname,
      userAgent: String(req.headers?.['user-agent'] || ''),
    })
  }

  function blockIp(res, ip, reason, req, whitelisted) {
    recordIfSuspicious(ip, reason, req, { whitelisted })
    sendJson(res, 403, {error:'access_denied', code:'access_denied'})
    return true
  }

  function checkNginxGate(req, res) {
    const info = detectNginxMisconfig(req)
    if (!info.misconfigured) return false
    sendJson(res, 503, { error: 'proxy_misconfigured', code:'proxy_misconfigured', nginxMisconfig: info })
    return true
  }

  function checkIpGate(req, res) {
    const { ip, verdict } = ipContext(req)
    if (verdict.action === 'block') {
      return blockIp(res, ip, verdict.reason, req, verdict.whitelisted)
    }
    return { ip, whitelisted: !!verdict.whitelisted }
  }

  function checkAuthGate(req, res, { ip, whitelisted }) {
    if (isAuthenticated(req)) return true
    recordIfSuspicious(ip, 'unauthenticated', req, { whitelisted })
    sendJson(res, 401, { error: 'login required' })
    return false
  }

  function shouldSkipAuth(pathname) {
    if (isAuthExcluded(pathname, BUILTIN_AUTH_EXCLUDE_PREFIXES)) return true
    return false
  }

  function wrapHttpHandler(originalHandler) {
    return function gatedHandler(req, res) {
      const url = new URL(req.url ?? '/', 'http://x')
      const pathname = url.pathname

      if (isPublicPluginApi(pathname)) return originalHandler(req, res)
      if (checkNginxGate(req, res)) return

      const ipResult = checkIpGate(req, res)
      if (ipResult === true) return
      const { ip, whitelisted } = ipResult

      if (bridge) {
        try { bridge.fence(req) } catch (err) { sendJson(res, err.status || 503, {code:err.code, error:err.code}); return }
        if (['/', '/index.html'].includes(pathname) && ['GET','HEAD'].includes(req.method)) {
          if (url.searchParams.has('token')) {
            res.writeHead(303, {location:'/', 'cache-control':'no-store', 'referrer-policy':'no-referrer'}); res.end(); return
          }
          if (!isSessionAuthenticated(req) || !bridge.authenticated(req)) {
            const nonce = randomBytes(18).toString('base64')
            res.writeHead(200, {'content-type':'text/html; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','content-security-policy':`default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`})
            res.end(req.method === 'HEAD' ? undefined : renderLoginPage(nonce))
            return
          }
        }
      }

      const publicStaticRead = ['GET', 'HEAD'].includes(req.method) && shouldSkipAuth(pathname)
      if (!publicStaticRead && !checkAuthGate(req, res, { ip, whitelisted })) return
      return originalHandler(req, res)
    }
  }

  function wrapUpgradeHandler(originalHandler) {
    return function gatedUpgrade(req, socket, head) {
      const pathname = new URL(req.url ?? '/', 'http://x').pathname

      if (detectNginxMisconfig(req).misconfigured) {
        socket.destroy()
        return
      }
      const { ip, verdict } = ipContext(req)
      if (verdict.action === 'block') {
        recordIfSuspicious(ip, verdict.reason, req, { whitelisted: verdict.whitelisted })
        socket.destroy()
        return
      }
      try { bridge?.fence(req) } catch { socket.destroy(); return }
      if (!isAuthenticated(req)) {
        recordIfSuspicious(ip, 'unauthenticated', req, { whitelisted: verdict.whitelisted })
        socket.destroy()
        return
      }
      active.set(socket, req)
      socket.once?.('close', () => active.delete(socket))
      return originalHandler(req, socket, head)
    }
  }

  return {
    clientIp,
    ipContext,
    isAuthenticated,
    checkIpGate,
    checkNginxGate,
    recordIfSuspicious,
    wrapHttpHandler,
    wrapUpgradeHandler,
    dispose() { clearInterval(expiryTimer); unsubscribe?.(); for (const socket of active.keys()) socket.destroy(); active.clear() },
  }
}

// Wrap Map.set synchronously: official WebServer.register uses these maps.
// Direct mutation of a route.handler or replacement of a map is unsupported.
const installations = new WeakMap()
export function wrapWebServer(webServer, gate, store) {
  if (installations.has(webServer)) throw new Error('hanaccount gate already installed')
  for (const slot of ['prefixes', 'exact', 'upgrades']) {
    if (!(webServer[slot] instanceof Map)) throw new Error(`unsupported WebServer route table: ${slot}`)
  }
  const restores = []
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
  restores.push(() => Object.defineProperty(webServer, 'fallback', {...descriptor, value:fallbackOriginal}))
  const wrappers = new WeakSet()
  const slots = ['prefixes', 'exact', 'upgrades']
  for (const slot of slots) {
    const map = webServer[slot]
    if (!map?.set || !map?.entries) continue
    const originalSet = map.set
    const ownSet = Object.getOwnPropertyDescriptor(map, 'set')
    function wrap(path, route) {
      if (!route || typeof route.handler !== 'function') return
      if (slot !== 'upgrades' && !shouldWrapPrefix(path, store.cfg.routePolicy)) return
      if (wrappers.has(route.handler)) return
      const original = route.handler
      const wrapped = slot === 'upgrades' ? gate.wrapUpgradeHandler(original) : gate.wrapHttpHandler(original)
      wrappers.add(wrapped)
      route.handler = wrapped
      route.__dshGateWrapped = true
      restores.push(() => { if (route.handler === wrapped) { route.handler = original; delete route.__dshGateWrapped } })
    }
    for (const [path, route] of map.entries()) wrap(path, route)
    const patchedSet = function(path, route) { wrap(path, route); return originalSet.call(this, path, route) }
    map.set = patchedSet
    restores.push(() => {
      if (map.set !== patchedSet) return
      if (ownSet) Object.defineProperty(map, 'set', ownSet)
      else delete map.set
    })
  }
  let disposed = false
  const dispose = () => {
    if (disposed) return
    disposed = true
    for (const undo of restores.reverse()) undo()
    installations.delete(webServer)
  }
  installations.set(webServer, dispose)
  return dispose
}
