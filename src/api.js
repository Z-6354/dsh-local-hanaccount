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
import { detectNginxMisconfig, detectProxy, nginxSnippet, applyIpListChange } from './lib/ip.js'
import { passkeyStatus } from './lib/passkey-context.js'
import {
  authenticationOptions,
  registrationOptions,
  verifyAuthentication,
  verifyRegistration,
} from './lib/passkey.js'

export function createApiHandler({ store, gate }) {
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
    pairFailures.set(ip, row)
  }

  function authToken(req) {
    return parseCookies(req)[COOKIE]
  }

  function requireAuth(req, res) {
    const token = authToken(req)
    if (!store.sessionFromToken(token)) {
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
    try {
      const url = new URL(req.url ?? '/', 'http://x')
      const sub = url.pathname.slice(API_PREFIX.length).replace(/^\/+/, '')
      const nginxInfo = detectNginxMisconfig(req)
      const isProbe = sub === 'status' || sub === 'auth/me' || sub === 'nginx/snippet'

      if (nginxInfo.misconfigured && !isProbe) {
        sendJson(res, 503, { error: nginxInfo.code, message: nginxInfo.message, nginxMisconfig: nginxInfo })
        return
      }

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
        })
        return
      }

      if (req.method === 'GET' && sub === 'auth/me') {
        const token = authToken(req)
        const session = store.cfg.passwordHash ? store.sessionFromToken(token) : null
        sendJson(res, 200, {
          authenticated: !!session,
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
        const body = await readBody(req)
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
        if (store.cfg.passwordHash) {
          sendJson(res, 400, { error: 'password already configured' })
          return
        }
        const body = await readBody(req)
        const password = String(body.password ?? '')
        if (password.length < 8) throw httpError(400, 'password must be at least 8 characters')
        store.setPasswordHash(hashPassword(password))
        const token = store.issueSession()
        sendJson(res, 200, { ok: true }, { 'set-cookie': setCookieHeader(token, store.cfg.sessionMaxAgeDays) })
        return
      }

      if (req.method === 'POST' && sub === 'auth/login') {
        if (!store.cfg.passwordHash) {
          sendJson(res, 400, { error: 'password not configured; use setup first' })
          return
        }
        const lockout = store.getLockout(ip)
        const lock = checkLockout(lockout, store.cfg.lockout)
        if (lock.locked) {
          sendJson(res, 429, { error: 'too many attempts', retryAfterSec: lock.retryAfterSec })
          return
        }
        const body = await readBody(req)
        const password = String(body.password ?? '')
        if (!verifyPassword(password, store.cfg.passwordHash)) {
          const fail = recordFailedAttempt(lockout, ip, store.cfg.lockout)
          if (!whitelisted) gate.recordIfSuspicious(ip, fail.reason, req, { whitelisted })
          store.saveState()
          sendJson(res, 401, { error: 'invalid password' })
          return
        }
        resetLockout(lockout)
        store.saveState()
        const token = store.issueSession()
        sendJson(res, 200, { ok: true }, { 'set-cookie': setCookieHeader(token, store.cfg.sessionMaxAgeDays) })
        return
      }

      if (req.method === 'POST' && sub === 'auth/logout') {
        store.logout(authToken(req))
        sendJson(res, 200, { ok: true }, { 'set-cookie': clearCookieHeader() })
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
        const options = await authenticationOptions(req, store.passkeys)
        sendJson(res, 200, options)
        return
      }

      if (req.method === 'POST' && sub === 'auth/passkey/login/verify') {
        const body = await readBody(req)
        try {
          await verifyAuthentication(req, store.passkeys, body)
        } catch (e) {
          if (!whitelisted) gate.recordIfSuspicious(ip, 'login_failed', req, { whitelisted })
          throw e
        }
        resetLockout(store.getLockout(ip))
        store.saveState()
        const token = store.issueSession()
        sendJson(res, 200, { ok: true }, { 'set-cookie': setCookieHeader(token, store.cfg.sessionMaxAgeDays) })
        return
      }

      if (req.method === 'POST' && sub === 'auth/key/verify') {
        if (!store.cfg.keyAuthEnabled) {
          sendJson(res, 400, { error: 'key auth disabled' })
          return
        }
        const body = await readBody(req)
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
        const token = store.issueSession()
        sendJson(res, 200, { ok: true, keyId: matched.id }, { 'set-cookie': setCookieHeader(token, store.cfg.sessionMaxAgeDays) })
        return
      }

      const token = requireAuth(req, res)
      if (!token) return

      if (req.method === 'GET' && sub === 'config') {
        sendJson(res, 200, store.publicConfig())
        return
      }

      if (req.method === 'PUT' && sub === 'config') {
        const body = await readBody(req)
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
        const options = await registrationOptions(req, store.passkeys)
        sendJson(res, 200, options)
        return
      }

      if (req.method === 'POST' && sub === 'auth/passkey/register/verify') {
        const body = await readBody(req)
        const row = await verifyRegistration(req, store.passkeys, body)
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
        const body = await readBody(req)
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
        const body = await readBody(req)
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
        const pairBody = await pairRes.json().catch(() => ({}))
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
        const body = await readBody(req)
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
      sendJson(res, err?.status || 500, { error: String(err?.message || err) })
    }
  }
}
