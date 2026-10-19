import { randomBytes } from 'node:crypto'
import { COOKIE, parseCookies } from './util.js'

const DEFAULT_TTL_MS = 120_000
const MAX_GRANTS = 4096
const MAX_GRANTS_PER_SCOPE = 32

function authError(code, status = 401) {
  return Object.assign(new Error(code), { code, status })
}

function browserIdentity(connection) {
  // rc.2 admits both browser and API peers. A browser grant must bind only to
  // its public browserPeer; the former connection exposes the shared operator.
  const field = connection?.browserPeer !== undefined ? 'browserPeer' : 'operator'
  const peer = connection?.[field]
  const missing = []
  if (typeof connection?.admit !== 'function') missing.push('connection.admit')
  if (!peer || !['object', 'function'].includes(typeof peer)) missing.push(`connection.${field}`)
  return { peer, field, missing }
}

/** Own short-lived in-memory proofs for authenticated browser RPC calls. */
export function createRpcAuthorization({ store, connection, bridge, gate, isCurrent = () => true, ttlMs = DEFAULT_TTL_MS, clock = globalThis } = {}) {
  if (typeof store?.sessionFromToken !== 'function' || typeof store?.resumeScope !== 'function'
    || typeof bridge?.authenticated !== 'function' || typeof isCurrent !== 'function') {
    throw new TypeError('rpc_authorization_dependencies_missing')
  }
  const ttl = Number(ttlMs)
  if (!Number.isSafeInteger(ttl) || ttl < 1_000 || ttl > 300_000) throw new RangeError('rpc_grant_ttl_invalid')
  const grants = new Map()
  let disposed = false
  let checking = false
  const now = () => clock.Date?.now?.() ?? Date.now()

  function assertLive() {
    store.assertActive?.()
    if (disposed || !isCurrent()) throw authError('auth_unavailable', 503)
  }

  function retire(grant, row, reason = 'rpc_grant_retired') {
    if (grants.get(grant) !== row) return
    grants.delete(grant)
    clock.clearTimeout(row.timer)
    row.controller.abort(authError(reason))
  }

  function currentAccount(row) {
    assertLive()
    if (!row) return false
    let session
    try { session = store.sessionFromToken(row.token, { touch: false }) }
    catch { return false }
    return session && store.resumeScope(row.token) === row.scope
  }

  function validRow(row) {
    return row?.expiresAt > now() && Boolean(currentAccount(row))
  }

  function sweep() {
    if (checking) return
    checking = true
    try {
      for (const [grant, row] of grants) {
        if (!currentAccount(row)) retire(grant, row, 'rpc_grant_revoked')
        else if (row.expiresAt <= now()) retire(grant, row, 'rpc_grant_expired')
      }
    } finally { checking = false }
  }

  function securityChanged() {
    if (checking || disposed) return
    sweep()
  }

  const removeSecurityListener = store.onSecurityChange?.(securityChanged) || (() => {})

  function issueForRequest(req) {
    assertLive()
    if (bridge.authenticated(req) !== true) throw authError('rpc_grant_unauthorized')
    if (gate?.ipContext?.(req)?.verdict?.action === 'block') throw authError('access_denied', 403)
    const token = parseCookies(req)[COOKIE]
    const session = store.sessionFromToken(token, { touch: false })
    const scope = session && store.resumeScope(token)
    if (!session || !/^[a-f0-9]{48}$/.test(scope || '')) throw authError('rpc_grant_unauthorized')
    const identity = browserIdentity(connection)
    if (identity.missing.length) throw Object.assign(authError('rpc_authorization_unavailable', 503), { missingCapabilities: identity.missing })
    const admission = connection.admit(req)
    if (!admission || 'rejection' in admission || admission.peer !== identity.peer) throw authError('rpc_grant_unauthorized')

    sweep()
    if (grants.size >= MAX_GRANTS) throw authError('rpc_grant_capacity', 429)
    let scoped = 0
    for (const row of grants.values()) if (row.scope === scope) scoped += 1
    if (scoped >= MAX_GRANTS_PER_SCOPE) throw authError('rpc_grant_capacity', 429)
    const grant = randomBytes(32).toString('hex')
    const controller = new AbortController()
    const row = { token, scope, peer: admission.peer, expiresAt: now() + ttl, controller, timer: null }
    row.timer = clock.setTimeout(() => {
      let accountIsCurrent = false
      try { accountIsCurrent = Boolean(currentAccount(row)) } catch {}
      if (!accountIsCurrent) retire(grant, row, 'rpc_grant_revoked')
      else if (row.expiresAt <= now()) retire(grant, row, 'rpc_grant_expired')
      else row.timer = clock.setTimeout(() => {
        let stillCurrent = false
        try { stillCurrent = Boolean(currentAccount(row)) } catch {}
        retire(grant, row, stillCurrent ? 'rpc_grant_expired' : 'rpc_grant_revoked')
      }, row.expiresAt - now())
    }, ttl)
    row.timer.unref?.()
    grants.set(grant, row)
    if (!validRow(row)) {
      retire(grant, row, 'rpc_grant_revoked')
      throw authError('rpc_grant_unauthorized')
    }
    return { protocol: 1, grant, scope, expiresAt: row.expiresAt }
  }

  function authorizeGrant({ peer, grant, expectedScope } = {}) {
    assertLive()
    const row = grants.get(grant)
    if (!row || peer !== row.peer || (expectedScope !== undefined && expectedScope !== row.scope)) {
      if (row) retire(grant, row, 'rpc_grant_revoked')
      throw authError('rpc_grant_unauthorized')
    }
    if (!currentAccount(row)) {
      retire(grant, row, 'rpc_grant_revoked')
      throw authError('rpc_grant_unauthorized')
    }
    if (row.expiresAt <= now()) {
      retire(grant, row, 'rpc_grant_expired')
      throw authError('rpc_grant_expired')
    }
    return {
      scope: row.scope,
      expiresAt: row.expiresAt,
      signal: row.controller.signal,
      isCurrent() {
        if (grants.get(grant) !== row) return false
        if (!currentAccount(row)) {
          retire(grant, row, 'rpc_grant_revoked')
          return false
        }
        if (row.expiresAt <= now()) {
          retire(grant, row, 'rpc_grant_expired')
          return false
        }
        return true
      },
    }
  }

  function dispose() {
    if (disposed) return
    disposed = true
    removeSecurityListener()
    for (const [grant, row] of grants) retire(grant, row, 'auth_unavailable')
  }

  return { issueForRequest, authorizeGrant, dispose,
    state() {
      const { field, missing } = browserIdentity(connection)
      return { available:!disposed && missing.length === 0, identityInterface:field, missingCapabilities:missing,
        code:disposed ? 'auth_unavailable' : missing.length ? 'rpc_authorization_unavailable' : 'rpc_authorization_ready' }
    },
    get size() { return grants.size } }
}
