import { detectNginxMisconfig, detectProxy, evaluateIpAccess, ipInList, resolveClientIp } from './lib/ip.js'
import { loginStyle } from './lib/login-style.js'
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

function traceIndex(decision) {
  if (process.env.HANACCOUNT_STARTUP_TRACE !== '1') return
  console.info('[hanaccount-trace]', JSON.stringify({ event: 'index', decision, identity: 'omitted' }))
}

function bearerToken(req) {
  const auth = String(req.headers?.authorization || '')
  if (!auth.startsWith('Bearer ')) return ''
  return auth.slice(7).trim()
}

export function createGate(store, bridge) {
  const style = loginStyle(store.cfg)
  let disposed = false
  const active = new Map()
  function recheckSockets() {
    for (const [socket, req] of active) {
      const session = parseCookies(req)[COOKIE]
      let allowed = false
      try { allowed = ipContext(req).verdict.action !== 'block' && (!session || !!store.sessionFromToken(session, {touch:false})) && isAuthenticated(req, false) } catch {}
      if (!allowed) {
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
    if (disposed) return false
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
    return !!style && pathname === style.path
  }

  function stylesheetFor(req) {
    const secure = !!req.socket?.encrypted || (store.cfg.trustProxy && detectProxy(req).viaTrustedProxy && req.headers?.['x-forwarded-proto'] === 'https')
    return style && secure && req.headers?.host === style.host ? style.url : ''
  }

  function wrapHttpHandler(originalHandler) {
    return function gatedHandler(req, res) {
      if (disposed) { sendJson(res, 503, {code:'auth_unavailable'}); return }
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
            traceIndex('strip_token')
            res.writeHead(303, {location:'/', 'cache-control':'no-store', 'referrer-policy':'no-referrer'}); res.end(); return
          }
          // A persistent, server-validated account session can restore the official
          // session cookie after process exit. Revoked/expired identities never mint.
          if (isSessionAuthenticated(req, false) && !bridge.authenticated(req)) {
            try {
              const secure = !!req.socket?.encrypted || (store.cfg.trustProxy && detectProxy(req).viaTrustedProxy && req.headers?.['x-forwarded-proto'] === 'https')
              const native = bridge.mint(req, secure)
              if (disposed || !isSessionAuthenticated(req, false) || ipContext(req).verdict.action === 'block') throw Error('identity_revoked')
              traceIndex('restore_native')
              res.writeHead(303, {location:'/', 'set-cookie':native, 'cache-control':'no-store'})
              res.end(); return
            } catch { traceIndex('restore_failed'); sendJson(res, 503, {code:'native_bridge_unavailable'}); return }
          }
          if (!isSessionAuthenticated(req) || !bridge.authenticated(req)) {
            traceIndex('login_page')
            const nonce = randomBytes(18).toString('base64')
            const stylesheet = stylesheetFor(req)
            res.writeHead(200, {'content-type':'text/html; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','content-security-policy':`default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'${stylesheet ? ` ${stylesheet}` : ''}; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`})
            res.end(req.method === 'HEAD' ? undefined : renderLoginPage(nonce, stylesheet))
            return
          }
          traceIndex('home')
        }
      }

      const publicStaticRead = ['GET', 'HEAD'].includes(req.method) && shouldSkipAuth(pathname) && !!stylesheetFor(req) && !url.search
      if (!publicStaticRead && !checkAuthGate(req, res, { ip, whitelisted })) return
      // Account control responses are bounded JSON. The logout/password-change
      // acknowledgement must remain writable while its own session is revoked.
      const accountControl = pathname.startsWith('/dsh-local-hanaccount/api/')
      if (!publicStaticRead && !accountControl && typeof res.once === 'function') {
        active.set(res, req)
        const release = () => active.delete(res)
        res.once('finish', release)
        res.once('close', release)
      }
      return originalHandler(req, res)
    }
  }

  function wrapUpgradeHandler(originalHandler) {
    return function gatedUpgrade(req, socket, head) {
      if (disposed) { socket.destroy(); return }

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
    dispose() { if (disposed) return; disposed = true; store.retire?.(); clearInterval(expiryTimer); unsubscribe?.(); for (const socket of active.keys()) socket.destroy(); active.clear() },
  }
}

// Compatibility helper for isolated gate tests. Production uses createDshAdapter.
export { installRouteGate as wrapWebServer } from './lib/dsh-adapter.js'
