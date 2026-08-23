import { detectNginxMisconfig, evaluateIpAccess, ipInList, resolveClientIp } from './lib/ip.js'
import {
  BUILTIN_AUTH_EXCLUDE_PREFIXES,
  isAuthExcluded,
  shouldWrapPrefix,
} from './lib/route-policy.js'
import { parseCookies, sendJson, sendText, COOKIE } from './lib/util.js'

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

export function createGate(store) {
  function clientIp(req) {
    return resolveClientIp(req, { trustProxy: store.cfg.trustProxy })
  }

  function ipContext(req) {
    const ip = clientIp(req)
    const verdict = evaluateIpAccess(ip, store.cfg)
    return { ip, verdict }
  }

  function isSessionAuthenticated(req) {
    if (!store.cfg.passwordHash) return false
    const token = parseCookies(req)[COOKIE]
    return !!store.sessionFromToken(token)
  }

  function isBearerAuthenticated(req) {
    const raw = bearerToken(req)
    if (!raw) return false
    return !!store.tokens.verifyAny(raw, store.peers.inboundVerifierEntries())
  }

  function isAuthenticated(req) {
    return isSessionAuthenticated(req) || isBearerAuthenticated(req)
  }

  function tryNginxBasic(req) {
    if (!store.cfg.nginxBasicAutoLogin) return false
    const auth = req.headers?.authorization || ''
    return auth.startsWith('Basic ')
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
    sendText(res, 403, 'Forbidden')
    return true
  }

  function checkNginxGate(req, res) {
    const info = detectNginxMisconfig(req)
    if (!info.misconfigured) return false
    sendJson(res, 503, { error: info.code, message: info.message, nginxMisconfig: info })
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
    if (tryNginxBasic(req)) {
      const token = store.issueSession()
      res.setHeader('set-cookie', requireSetCookie(token))
      return true
    }
    recordIfSuspicious(ip, 'unauthenticated', req, { whitelisted })
    sendJson(res, 401, { error: 'login required' })
    return false
  }

  function requireSetCookie(token) {
    const maxAge = Math.max(1, Number(store.cfg.sessionMaxAgeDays) || 7) * 24 * 60 * 60
    return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`
  }

  function shouldSkipAuth(pathname) {
    if (isAuthExcluded(pathname, BUILTIN_AUTH_EXCLUDE_PREFIXES)) return true
    return isAuthExcluded(pathname, store.cfg.routePolicy?.excludePrefixes)
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

      if (!shouldSkipAuth(pathname) && !checkAuthGate(req, res, { ip, whitelisted })) return
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
      if (!shouldSkipAuth(pathname) && !isAuthenticated(req) && !tryNginxBasic(req)) {
        recordIfSuspicious(ip, 'unauthenticated', req, { whitelisted: verdict.whitelisted })
        socket.destroy()
        return
      }
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
  }
}

function wrapRouteHandler(route, gate) {
  if (!route || typeof route.handler !== 'function' || route.__dshGateWrapped) {
    return !!route?.__dshGateWrapped
  }
  const original = route.handler
  route.handler = gate.wrapHttpHandler(original)
  route.__dshGateWrapped = true
  return { original, route }
}

function wrapUpgradeRoute(route, gate) {
  if (!route || typeof route.handler !== 'function' || route.__dshGateWrapped) {
    return !!route?.__dshGateWrapped
  }
  const original = route.handler
  route.handler = gate.wrapUpgradeHandler(original)
  route.__dshGateWrapped = true
  return { original, route }
}

export function wrapWebServer(webServer, gate, store) {
  const restored = []
  let stopped = false
  let timer = null
  const wrappedPrefixes = new Set()
  const wrappedUpgrades = new Set()

  function shouldWrap(prefixPath) {
    return shouldWrapPrefix(prefixPath, store.cfg.routePolicy)
  }

  function undoWrap(entry) {
    if (!entry) return
    entry.route.handler = entry.original
    delete entry.route.__dshGateWrapped
  }

  function wrapHttpPrefix(prefixPath) {
    if (wrappedPrefixes.has(prefixPath)) return true
    if (!shouldWrap(prefixPath)) {
      wrappedPrefixes.add(prefixPath)
      return true
    }
    const route = webServer?.prefixes?.get?.(prefixPath)
    const entry = wrapRouteHandler(route, gate)
    if (entry === true) {
      wrappedPrefixes.add(prefixPath)
      return true
    }
    if (!entry) return false
    wrappedPrefixes.add(prefixPath)
    restored.push(() => undoWrap(entry))
    return true
  }

  function wrapExact(path) {
    if (wrappedPrefixes.has(`exact:${path}`)) return true
    if (!shouldWrap(path)) {
      wrappedPrefixes.add(`exact:${path}`)
      return true
    }
    const route = webServer?.exacts?.get?.(path)
    if (!route) return false
    const entry = wrapRouteHandler(route, gate)
    if (entry === true) {
      wrappedPrefixes.add(`exact:${path}`)
      return true
    }
    if (!entry) return false
    wrappedPrefixes.add(`exact:${path}`)
    restored.push(() => undoWrap(entry))
    return true
  }

  function wrapUpgrade(path) {
    if (wrappedUpgrades.has(path)) return true
    const route = webServer?.upgrades?.get?.(path)
    const entry = wrapUpgradeRoute(route, gate)
    if (entry === true) {
      wrappedUpgrades.add(path)
      return true
    }
    if (!entry) return false
    wrappedUpgrades.add(path)
    restored.push(() => undoWrap(entry))
    return true
  }

  function attachAll() {
    let ok = true
    for (const prefixPath of webServer?.prefixes?.keys?.() ?? []) {
      if (!wrapHttpPrefix(prefixPath)) ok = false
    }
    for (const exactPath of webServer?.exacts?.keys?.() ?? []) {
      if (!wrapExact(exactPath)) ok = false
    }
    if (!wrapUpgrade('/api/events.host')) ok = false
    if (!wrapUpgrade('/api/events.mux')) ok = false
    return ok
  }

  attachAll()
  timer = setInterval(() => {
    if (stopped) return
    attachAll()
  }, 500)

  return () => {
    stopped = true
    if (timer) clearInterval(timer)
    for (const undo of restored.splice(0)) {
      try { undo() } catch {}
    }
    wrappedPrefixes.clear()
    wrappedUpgrades.clear()
  }
}
