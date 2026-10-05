import { AUTH_PROTOCOL } from './lib/native-bridge.js'
import {
  API_PREFIX,
  COOKIE,
  clearCookieHeader,
  httpError,
  parseCookies,
  readBody,
  sendJson,
  setCookieHeader,
} from './lib/util.js'
import { hashPassword, verifyPassword, checkLockout, recordFailedAttempt, resetLockout } from './lib/password.js'
import {
  addPublicKey,
  createChallengeStore,
  loadAuthorizedKeys,
  saveAuthorizedKeys,
  verifyKeySignature,
} from './lib/key-auth.js'
import { isLoopbackIp, requestHost, detectNginxMisconfig, detectProxy, nginxSnippet, applyIpListChange } from './lib/ip.js'
import { passkeyStatus } from './lib/passkey-context.js'
import {
  authenticationOptions,
  registrationOptions,
  verifyAuthentication,
  verifyRegistration,
} from './lib/passkey.js'

export function createApiHandler({ store, gate, bridge, verifyPasskey = verifyAuthentication, securityState, isCurrent = () => true, onSecurityFailure }) {
  const challenges = createChallengeStore()
  const pairFailures = new Map()
  const PAIR_FAIL_LIMIT = 10
  const PAIR_FAIL_WINDOW_MS = 10 * 60 * 1000

  function pairRateLimited(ip) {
    const now = Date.now()
    const row = pairFailures.get(ip) || { count: 0, resetAt: now + PAIR_FAIL_WINDOW_MS }
    if (now > row.resetAt) {
      row.count = 0
      row.resetAt = now + PAIR_FAIL_WINDOW_MS
    }
    if (row.count >= PAIR_FAIL_LIMIT) return true
    return false
  }

  function recordPairFailure(ip) {
    const now = Date.now()
    const row = pairFailures.get(ip) || { count: 0, resetAt: now + PAIR_FAIL_WINDOW_MS }
    if (now > row.resetAt) {
      row.count = 0
      row.resetAt = now + PAIR_FAIL_WINDOW_MS
    }
    row.count += 1
    for (const [key, entry] of pairFailures) if (entry.resetAt <= now) pairFailures.delete(key)
    if (!pairFailures.has(ip) && pairFailures.size >= 1024) pairFailures.delete(pairFailures.keys().next().value)
    pairFailures.set(ip, row)
  }

  function authToken(req) {
    return parseCookies(req)[COOKIE]
  }
  function secureCookie(req) {
    return !!req.socket?.encrypted || (store.cfg.trustProxy && detectProxy(req).viaTrustedProxy && req.headers?.['x-forwarded-proto'] === 'https')
  }

  function assertLive() {
    store.assertActive?.()
    if (!isCurrent()) throw Object.assign(new Error('auth_unavailable'), {status:503, code:'auth_unavailable'})
  }

  function grant(req, res, extra = {}, expectedVersion = store.cfg.passwordHash, identityValid = () => true) {
    assertLive()
    if (!bridge) throw Object.assign(new Error('native_bridge_unavailable'), {status:503, code:'native_bridge_unavailable'})
    if (expectedVersion !== store.cfg.passwordHash) throw Object.assign(new Error('native_bridge_unavailable'), {status:503, code:'native_bridge_unavailable'})
    if (!identityValid()) throw Object.assign(new Error('identity_revoked'), {status:401, code:'identity_revoked'})
    const version = store.cfg.passwordHash
    const native = bridge.mint(req, secureCookie(req))
    if (!identityValid()) throw Object.assign(new Error('identity_revoked'), {status:401, code:'identity_revoked'})
    if (version !== store.cfg.passwordHash) throw Object.assign(new Error('native_bridge_unavailable'), {status:503})
    const previous = new Set(Object.keys(store.state.sessions))
    let token
    try { token = store.issueSession() }
    catch { for (const key of Object.keys(store.state.sessions)) if (!previous.has(key)) delete store.state.sessions[key]; throw Object.assign(new Error('storage_unavailable'), {status:503, code:'storage_unavailable'}) }
    sendJson(res, 200, {ok:true, protocol:AUTH_PROTOCOL, ...extra}, {'set-cookie':[setCookieHeader(token, store.cfg.sessionMaxAgeDays, secureCookie(req)), native]})
  }

  function requireAuth(req, res) {
    const token = authToken(req)
    if (!store.sessionFromToken(token) || (bridge && !bridge.authenticated(req))) {
      sendJson(res, 401, { error: 'login required' })
      return null
    }
    return token
  }

  function ipMeta(req) {
    const ip = gate.clientIp(req)
    const { verdict } = gate.ipContext(req)
    return { ip, whitelisted: !!verdict.whitelisted }
  }

  return async (req, res) => {
    let authenticatedToken
    const authenticationVersion = store.cfg.passwordHash
    function revalidate() {
      assertLive()
      bridge?.fence(req)
      if (gate.ipContext(req).verdict.action === 'block') throw Object.assign(new Error('access_denied'), {status:403, code:'access_denied'})
      if (store.cfg.passwordHash !== authenticationVersion) throw Object.assign(new Error('identity_revoked'), {status:401, code:'identity_revoked'})
      if (authenticatedToken && (!store.sessionFromToken(authenticatedToken, {touch:false}) || (bridge && !bridge.authenticated(req)))) {
        throw Object.assign(new Error('identity_revoked'), {status:401, code:'identity_revoked'})
      }
    }
    async function readOperationBody() {
      const body = await readBody(req)
      revalidate()
      return body
    }
    try {
      assertLive()
      const url = new URL(req.url ?? '/', 'http://x')
      const sub = url.pathname.slice(API_PREFIX.length).replace(/^\/+/, '')
      bridge?.fence(req)
      const nginxInfo = detectNginxMisconfig(req)
      const isProbe = sub === 'status' || sub === 'auth/me' || sub === 'nginx/snippet'

      if (nginxInfo.misconfigured && !isProbe) {
        sendJson(res, 503, { error: 'proxy_misconfigured', code:'proxy_misconfigured', nginxMisconfig: nginxInfo })
        return
      }

      if (req.method === 'POST' && ['auth/login','auth/setup'].includes(sub) && !/^application\/json(?:;|$)/i.test(String(req.headers?.['content-type'] || ''))) throw httpError(415, 'application/json required')
      const meta = ipMeta(req)

      // IP gate for plugin API (public auth routes still blocked if IP denied)
      const ipCheck = gate.checkIpGate(req, res)
      if (ipCheck === true) return
      const { ip, whitelisted } = ipCheck

      const passkey = { ...passkeyStatus(req), count: store.passkeys.count() }

      if (req.method === 'GET' && sub === 'status') {
        sendJson(res, 200, {
          ip: meta.ip,
          whitelisted: meta.whitelisted,
          ipLimitEnabled: store.cfg.ipLimitEnabled,
          passwordConfigured: !!store.cfg.passwordHash,
          proxy: detectProxy(req),
          nginxMisconfig: nginxInfo.misconfigured ? nginxInfo : null,
          passkey,
          routePolicy: store.publicConfig().routePolicy,
          auth: { protocol: AUTH_PROTOCOL, passwordOnly: !!bridge, nativeSessionBridge: !!bridge },
          security: securityState?.() || {ready:false, deploymentReady:false, code:'isolated_fixture'},
          deviceIntegration: { ready: false, nativeAuthBridge: false, scopedCredentials: false, durableNotifications: false },
        })
        return
      }

      if (req.method === 'GET' && sub === 'auth/me') {
        const token = authToken(req)
        const session = store.cfg.passwordHash ? store.sessionFromToken(token) : null
        sendJson(res, 200, {
          authenticated: !!session,
          nativeAuthenticated: bridge ? bridge.authenticated(req) : false,
          protocol: AUTH_PROTOCOL,
          passwordConfigured: !!store.cfg.passwordHash,
          ip: meta.ip,
          whitelisted: meta.whitelisted,
          nginxMisconfig: nginxInfo.misconfigured ? nginxInfo : null,
          passkey,
        })
        return
      }

      if (req.method === 'GET' && sub === 'nginx/snippet') {
        sendJson(res, 200, { snippet: nginxSnippet(), nginxMisconfig: nginxInfo.misconfigured ? nginxInfo : null })
        return
      }

      if (req.method === 'POST' && sub === 'peers/pair') {
        const ip = gate.clientIp(req)
        if (pairRateLimited(ip)) {
          sendJson(res, 429, { error: 'too many pairing attempts' })
          return
        }
        const body = await readOperationBody()
        const result = store.peers.claimPairingCode({
          code: body.code,
          peerName: body.peerName || body.name,
          peerBaseUrl: body.peerBaseUrl || body.baseUrl,
        })
        if (!result.ok) {
          recordPairFailure(ip)
          sendJson(res, 400, { error: result.error })
          return
        }
        sendJson(res, 200, { ok: true, peerId: result.peerId, token: result.token })
        return
      }

      if (req.method === 'POST' && sub === 'auth/setup') {
        const localHost = ['localhost', '127.0.0.1', '::1'].includes(requestHost(req))
        let sameOrigin = true
        if (req.headers?.origin) {
          try { sameOrigin = new URL(req.headers.origin).host === req.headers.host } catch { sameOrigin = false }
        }
        if (!isLoopbackIp(req.socket?.remoteAddress) || !localHost || !sameOrigin || detectProxy(req).hasForwardedHeaders) {
          sendJson(res, 403, { error: 'setup requires direct loopback' }); return
        }
        if (store.cfg.passwordHash) {
          sendJson(res, 400, { error: 'password already configured' })
          return
        }
        const body = await readOperationBody()
        const password = String(body.password ?? '')
        if (store.cfg.passwordHash) throw httpError(409, 'password already configured')
        if (password.length < 8) throw httpError(400, 'password must be at least 8 characters')
        store.setPasswordHash(hashPassword(password))
        grant(req, res)
        return
      }

      if (req.method === 'POST' && sub === 'auth/login') {
        if (!store.cfg.passwordHash) {
          sendJson(res, 400, { error: 'password_not_configured', code: 'password_not_configured' })
          return
        }
        const loginVersion = store.cfg.passwordHash
        const lockout = store.getLockout(ip)
        const lock = checkLockout(lockout, store.cfg.lockout)
        if (lock.locked) {
          sendJson(res, 429, { error: 'rate_limited', code: 'rate_limited', retryAfterSec: lock.retryAfterSec })
          return
        }
        const body = await readOperationBody()
        const password = String(body.password ?? '')
        if (store.cfg.passwordHash !== loginVersion) throw Object.assign(new Error('identity_revoked'), {status:401, code:'identity_revoked'})
        if (!verifyPassword(password, store.cfg.passwordHash)) {
          const fail = recordFailedAttempt(lockout, ip, store.cfg.lockout)
          if (!whitelisted) gate.recordIfSuspicious(ip, fail.reason, req, { whitelisted })
          store.saveState()
          sendJson(res, 401, { error: 'invalid_password', code: 'invalid_password' })
          return
        }
        resetLockout(lockout)
        store.saveState()
        grant(req, res)
        return
      }

      if (req.method === 'POST' && sub === 'auth/logout') {
        store.logout(authToken(req))
        sendJson(res, 200, { ok: true }, { 'set-cookie': [clearCookieHeader(), bridge.clear(req, secureCookie(req))] })
        return
      }

      if (req.method === 'GET' && sub === 'auth/key/challenge') {
        if (!store.cfg.keyAuthEnabled) {
          sendJson(res, 400, { error: 'key auth disabled' })
          return
        }
        challenges.purge()
        sendJson(res, 200, challenges.issue())
        return
      }

      if (req.method === 'POST' && sub === 'auth/passkey/login/options') {
        const options = await authenticationOptions(req, store.passkeys, revalidate)
        revalidate()
        sendJson(res, 200, options)
        return
      }

      if (req.method === 'POST' && sub === 'auth/passkey/login/verify') {
        const version = store.cfg.passwordHash
        const body = await readOperationBody()
        let authenticatedCredential
        try {
          authenticatedCredential = await verifyPasskey(req, store.passkeys, body, undefined, revalidate)
          revalidate()
        } catch (e) {
          revalidate()
          if (!whitelisted) gate.recordIfSuspicious(ip, 'login_failed', req, { whitelisted })
          throw e
        }
        resetLockout(store.getLockout(ip))
        store.saveState()
        grant(req, res, {}, version, () => store.passkeys.findByCredentialId(authenticatedCredential.credentialId) === authenticatedCredential)
        return
      }

      if (req.method === 'POST' && sub === 'auth/key/verify') {
        const version = store.cfg.passwordHash
        if (!store.cfg.keyAuthEnabled) {
          sendJson(res, 400, { error: 'key auth disabled' })
          return
        }
        const body = await readOperationBody()
        if (!store.cfg.keyAuthEnabled) throw Object.assign(new Error('key_auth_disabled'), {status:401, code:'key_auth_disabled'})
        const consumed = challenges.consume(body.challengeId, body.signature)
        if (!consumed.ok) {
          sendJson(res, 401, { error: consumed.error || 'invalid challenge' })
          return
        }
        const keys = loadAuthorizedKeys(store.keysFile)
        const matched = verifyKeySignature(keys, consumed.nonce, consumed.signature)
        if (!matched) {
          if (!whitelisted) gate.recordIfSuspicious(ip, 'login_failed', req, { whitelisted })
          sendJson(res, 401, { error: 'signature verification failed' })
          return
        }
        grant(req, res, {keyId: matched.id}, version, () => store.cfg.keyAuthEnabled && loadAuthorizedKeys(store.keysFile).some(key => key.key.equals(matched.key)))
        return
      }

      const token = requireAuth(req, res)
      if (!token) return
      authenticatedToken = token
      revalidate()

      if (req.method === 'GET' && sub === 'config') {
        sendJson(res, 200, store.publicConfig())
        return
      }

      if (req.method === 'PUT' && sub === 'config') {
        const body = await readOperationBody()
        if (body.password) {
          if (String(body.password).length < 8) throw httpError(400, 'password must be at least 8 characters')
          store.setPasswordHash(hashPassword(body.password))
        }
        store.updateConfig(body)
        sendJson(res, 200, { ok: true, config: store.publicConfig() })
        return
      }

      if (req.method === 'GET' && sub === 'security-visitors/stats') {
        sendJson(res, 200, store.visitors.getStats())
        return
      }

      if (req.method === 'POST' && sub === 'security-visitors/stats/reset') {
        store.visitors.resetStats()
        sendJson(res, 200, { ok: true })
        return
      }

      if (req.method === 'GET' && sub === 'security-visitors') {
        sendJson(res, 200, { visitors: store.visitors.listVisitors() })
        return
      }

      const visitorAction = sub.match(/^security-visitors\/([^/]+)\/(allow|deny|dismiss)$/)
      if (req.method === 'POST' && visitorAction) {
        const targetIp = decodeURIComponent(visitorAction[1])
        const action = visitorAction[2]
        if (action === 'allow' || action === 'deny') {
          const next = applyIpListChange(store.cfg, { listKey: action, entry: targetIp })
          if (next.error) throw httpError(400, next.error === 'loopback' ? 'cannot block loopback' : next.error === 'invalid' ? 'invalid ip' : 'empty ip')
          store.updateConfig({ allow: next.allow, deny: next.deny })
        }
        store.visitors.dismiss(targetIp)
        sendJson(res, 200, { ok: true, config: store.publicConfig() })
        return
      }

      if (req.method === 'POST' && sub === 'auth/passkey/register/options') {
        const options = await registrationOptions(req, store.passkeys, revalidate)
        revalidate()
        sendJson(res, 200, options)
        return
      }

      if (req.method === 'POST' && sub === 'auth/passkey/register/verify') {
        const body = await readOperationBody()
        const row = await verifyRegistration(req, store.passkeys, body, revalidate)
        revalidate()
        sendJson(res, 200, { ok: true, passkey: { id: row.id, name: row.name } })
        return
      }

      if (req.method === 'GET' && sub === 'passkeys') {
        sendJson(res, 200, { passkeys: store.passkeys.listPublic(), passkey: passkeyStatus(req) })
        return
      }

      const passkeyDelete = sub.match(/^passkeys\/([^/]+)$/)
      if (req.method === 'DELETE' && passkeyDelete) {
        const removed = store.passkeys.removeCredential(decodeURIComponent(passkeyDelete[1]))
        if (!removed) {
          sendJson(res, 404, { error: 'passkey not found' })
          return
        }
        sendJson(res, 200, { ok: true })
        return
      }

      if (req.method === 'GET' && sub === 'keys') {
        const keys = loadAuthorizedKeys(store.keysFile)
        sendJson(res, 200, {
          keys: keys.map((k) => ({ id: k.id, comment: k.comment, fingerprint: k.key.toString('hex').slice(0, 16) })),
        })
        return
      }

      if (req.method === 'POST' && sub === 'keys') {
        const body = await readOperationBody()
        const keys = loadAuthorizedKeys(store.keysFile)
        const next = addPublicKey(keys, body.publicKey || body.line || '')
        saveAuthorizedKeys(store.keysFile, next)
        sendJson(res, 200, { ok: true, count: next.length })
        return
      }

      const keyDelete = sub.match(/^keys\/([^/]+)$/)
      if (req.method === 'DELETE' && keyDelete) {
        const keyId = decodeURIComponent(keyDelete[1])
        const keys = loadAuthorizedKeys(store.keysFile).filter((k) => k.id !== keyId)
        saveAuthorizedKeys(store.keysFile, keys)
        sendJson(res, 200, { ok: true })
        return
      }

      if (req.method === 'GET' && sub === 'peers') {
        sendJson(res, 200, { peers: store.peers.listPeersPublic() })
        return
      }

      if (req.method === 'POST' && sub === 'peers/pairing-code') {
        const created = store.peers.createPairingCode()
        sendJson(res, 200, { ok: true, ...created })
        return
      }

      if (req.method === 'POST' && sub === 'peers/connect') {
        const body = await readOperationBody()
        const remoteBaseUrl = store.peers.normalizeBaseUrl(body.remoteBaseUrl || body.baseUrl)
        const code = String(body.code ?? '').trim()
        if (!remoteBaseUrl || !code) throw httpError(400, 'remoteBaseUrl and code are required')
        const pairRes = await fetch(`${remoteBaseUrl}${API_PREFIX}/peers/pair`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            code,
            peerName: body.localName || body.peerName || 'DSH',
            peerBaseUrl: body.localBaseUrl || body.peerBaseUrl || '',
          }),
        })
        revalidate()
        const pairBody = await pairRes.json().catch(() => ({}))
        revalidate()
        if (!pairRes.ok || !pairBody?.token) {
          sendJson(res, pairRes.status || 502, { error: pairBody?.error || 'pairing failed' })
          return
        }
        const peer = store.peers.addOutboundPeer({
          name: body.name || remoteBaseUrl,
          baseUrl: remoteBaseUrl,
          token: pairBody.token,
        })
        sendJson(res, 200, { ok: true, peer: { id: peer.id, name: peer.name, baseUrl: peer.baseUrl } })
        return
      }

      const peerDelete = sub.match(/^peers\/([^/]+)$/)
      if (req.method === 'DELETE' && peerDelete) {
        const removed = store.peers.removePeer(decodeURIComponent(peerDelete[1]))
        if (!removed) {
          sendJson(res, 404, { error: 'peer not found' })
          return
        }
        sendJson(res, 200, { ok: true })
        return
      }

      if (req.method === 'GET' && sub === 'api-tokens') {
        sendJson(res, 200, { tokens: store.tokens.listApiTokensPublic() })
        return
      }

      if (req.method === 'POST' && sub === 'api-tokens') {
        const body = await readOperationBody()
        const created = store.tokens.createApiToken(body.name)
        sendJson(res, 200, { ok: true, token: created })
        return
      }

      const tokenDelete = sub.match(/^api-tokens\/([^/]+)$/)
      if (req.method === 'DELETE' && tokenDelete) {
        const removed = store.tokens.revokeApiToken(decodeURIComponent(tokenDelete[1]))
        if (!removed) {
          sendJson(res, 404, { error: 'token not found' })
          return
        }
        sendJson(res, 200, { ok: true })
        return
      }

      sendJson(res, 404, { error: 'not found' })
    } catch (err) {
      if (err?.code === 'storage_unavailable') onSecurityFailure?.()
      sendJson(res, err?.status || 500, { error: err?.code || (err?.status ? String(err.message) : 'internal_error'), code: err?.code || (err?.status === 403 ? 'access_denied' : 'internal_error') }, [408, 413].includes(err?.status) ? {connection:'close'} : {})
    }
  }
}
