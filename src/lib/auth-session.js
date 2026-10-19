/** Client auth recovery: classify /auth/me without treating transport errors as logout. */

export const AUTH_STATUS = {
  unknown: 'unknown',
  checking: 'checking',
  authenticated: 'authenticated',
  unauthenticated: 'unauthenticated',
  unavailable: 'unavailable',
}

export function classifyMeResponse(me) {
  if (me?.nginxMisconfig?.misconfigured) {
    return { status: AUTH_STATUS.unavailable, reason: 'nginx', substatus: null, me }
  }
  if (me && me.authenticated === true && me.nativeAuthenticated === true) {
    return { status: AUTH_STATUS.authenticated, reason: 'ok', substatus: null, me }
  }
  if (me && me.authenticated === true && me.nativeAuthenticated !== true) {
    return { status: AUTH_STATUS.unavailable, reason: 'nativeMissing', substatus: 'nativeMissing', me }
  }
  if (me && (me.authenticated === false || me.passwordConfigured === false)) {
    return { status: AUTH_STATUS.unauthenticated, reason: me.passwordConfigured === false ? 'setup_required' : 'unauthenticated', substatus: null, me }
  }
  return { status: AUTH_STATUS.unavailable, reason: 'malformed', substatus: null, me }
}

export function classifyMeFailure(error) {
  const status = Number(error?.status) || 0
  const name = error?.name || ''
  if (name === 'AbortError' || name === 'TimeoutError') {
    return { status: AUTH_STATUS.unavailable, reason: 'timeout', substatus: null, me: null }
  }
  if (status === 403 && error?.code === 'access_denied') {
    return { status: AUTH_STATUS.unavailable, reason: 'access_denied', substatus: 'access_denied', me: null }
  }
  if (status === 401 || status === 403) {
    return { status: AUTH_STATUS.unauthenticated, reason: `http_${status}`, substatus: null, me: null }
  }
  if (status === 502 || status === 503 || status === 504) {
    return { status: AUTH_STATUS.unavailable, reason: `http_${status}`, substatus: null, me: null }
  }
  return { status: AUTH_STATUS.unavailable, reason: 'network', substatus: null, me: null }
}

export function loginGateDecision(snapshot) {
  if (!snapshot || snapshot.status === AUTH_STATUS.unknown || snapshot.status === AUTH_STATUS.checking) {
    return { overlay: 'loading', redirect: false }
  }
  if (snapshot.me?.nginxMisconfig?.misconfigured) {
    return { overlay: 'nginx', redirect: false }
  }
  if (snapshot.status === AUTH_STATUS.unavailable) {
    return { overlay: 'unavailable', redirect: false }
  }
  if (snapshot.status === AUTH_STATUS.unauthenticated) {
    return { overlay: snapshot.redirectsRemaining > 0 ? null : 'unauthenticated', redirect: snapshot.redirectsRemaining > 0 }
  }
  return { overlay: null, redirect: false }
}

export function createAuthSession({ request, timeoutMs = 5000 } = {}) {
  const listeners = new Set()
  let disposed = false
  let revision = 0
  let scope = null
  const emit = () => { revision += 1; for (const listener of listeners) listener(getSnapshot()) }
  function getSnapshot() { return { status, reason, scope, revision } }
  let status = AUTH_STATUS.unknown
  let reason = null
  let substatus = null
  let me = null
  let lastConfirmed = null
  let version = 0
  let inflight = null
  let redirectsUsed = 0
  let controller = null
  let rpcGrant = null
  let rpcGrantFlight = null
  let rpcGrantController = null
  let rpcGrantGeneration = 0

  function retireRpcGrant() {
    rpcGrantGeneration += 1
    rpcGrant = null
    rpcGrantController?.abort()
    rpcGrantController = null
    rpcGrantFlight = null
  }

  function snapshot() {
    return {
      status,
      reason,
      substatus,
      me,
      lastConfirmed,
      loading: status === AUTH_STATUS.unknown || status === AUTH_STATUS.checking,
      redirectsRemaining: Math.max(0, 1 - redirectsUsed),
    }
  }

  function apply(classified) {
    if (classified.status === AUTH_STATUS.unavailable) {
      if (classified.substatus === 'access_denied') retireRpcGrant()
      status = AUTH_STATUS.unavailable
      reason = classified.reason
      substatus = classified.substatus
      if (classified.me) me = classified.me
      return
    }
    status = classified.status
    reason = classified.reason
    substatus = classified.substatus
    me = classified.me
    const nextScope = status === AUTH_STATUS.authenticated && /^[a-f0-9]{48}$/.test(me?.resumeScope || '') ? me.resumeScope : null
    if (scope !== nextScope) retireRpcGrant()
    scope = nextScope
    lastConfirmed = classified
  }

  async function refresh() {
    if (disposed) return snapshot()
    if (inflight) return inflight
    const mine = ++version
    if (status !== AUTH_STATUS.authenticated) status = AUTH_STATUS.checking
    const requestController = typeof AbortController === 'function' ? new AbortController() : null
    controller = requestController
    const timer = timeoutMs > 0 && requestController ? setTimeout(() => requestController.abort(), timeoutMs) : null
    let resolveFlight
    const flight = new Promise(resolve => { resolveFlight = resolve })
    inflight = flight // Publish ownership before any subscriber can reenter refresh.
    emit()
    ;(async () => {
      try {
        const body = await request('/auth/me', { signal: requestController?.signal })
        if (mine === version) apply(classifyMeResponse(body))
      } catch (error) {
        if (mine === version) apply(classifyMeFailure(error))
      } finally {
        if (timer) clearTimeout(timer)
        if (mine === version) { inflight = null; emit() }
        resolveFlight(snapshot())
      }
    })()
    return flight
  }

  function noteRedirect() {
    if (status !== AUTH_STATUS.unauthenticated || redirectsUsed >= 1) return false
    redirectsUsed += 1
    return true
  }

  // A successful local logout is an authoritative revocation even though the
  // follow-up navigation may happen before another /auth/me request completes.
  // Retire any older response so it cannot restore the just-revoked scope.
  function invalidate(why = 'invalidated') {
    if (disposed) return snapshot()
    version += 1
    controller?.abort()
    controller = null
    retireRpcGrant()
    inflight = null
    status = AUTH_STATUS.unauthenticated
    scope = null
    substatus = null
    me = { authenticated: false, nativeAuthenticated: false }
    lastConfirmed = null
    redirectsUsed = 0
    reason = String(why || 'invalidated').slice(0, 80)
    emit()
    return snapshot()
  }

  function dispose() {
    disposed = true
    version += 1
    listeners.clear()
    inflight = null
    controller?.abort()
    retireRpcGrant()
  }

  async function requestRpcGrant({ signal, force = false } = {}) {
    const abortError = () => Object.assign(new Error('The operation was aborted'), { name: 'AbortError', code: 'aborted' })
    if (signal?.aborted) throw abortError()
    if (disposed || status !== AUTH_STATUS.authenticated || !scope) throw Object.assign(new Error('auth_required'), { code: 'auth_required' })
    const expectedScope = scope
    if (!force && rpcGrant?.scope === expectedScope && rpcGrant.expiresAt > Date.now() + 2_000) return { ...rpcGrant }
    let flight = !force ? rpcGrantFlight : null
    if (!flight) {
      rpcGrantController?.abort()
      const requestController = typeof AbortController === 'function' ? new AbortController() : null
      const generation = ++rpcGrantGeneration
      rpcGrantController = requestController
      flight = { waiters: new Set(), controller: requestController, generation, promise: null }
      flight.promise = (async () => {
      try {
        const value = await request('/auth/rpc-grant', { method: 'POST', body: '{}', ...(requestController ? { signal: requestController.signal } : {}) })
        if (disposed || generation !== rpcGrantGeneration || status !== AUTH_STATUS.authenticated || scope !== expectedScope || flight.waiters.size === 0) {
          throw Object.assign(new Error('auth_scope_changed'), { code: 'auth_scope_changed' })
        }
        if (value?.protocol !== 1 || typeof value.grant !== 'string' || !/^[a-f0-9]{64}$/.test(value.grant)
          || value.scope !== expectedScope || !Number.isSafeInteger(value.expiresAt)
          || value.expiresAt <= Date.now() || value.expiresAt > Date.now() + 300_000) {
          throw Object.assign(new Error('invalid_rpc_grant'), { code: 'invalid_rpc_grant' })
        }
        rpcGrant = { protocol: 1, grant: value.grant, scope: value.scope, expiresAt: value.expiresAt }
        return { ...rpcGrant }
      } finally {
        if (generation === rpcGrantGeneration) {
          rpcGrantFlight = null
          rpcGrantController = null
        }
      }
      })()
      rpcGrantFlight = flight
    }
    const current = flight
    const waiter = {}
    current.waiters.add(waiter)
    return new Promise((resolve, reject) => {
      let settled = false
      const finish = (fn, value) => {
        if (settled) return
        settled = true
        signal?.removeEventListener?.('abort', onAbort)
        current.waiters.delete(waiter)
        if (current.waiters.size === 0 && rpcGrantFlight === current) {
          current.controller?.abort()
          rpcGrantFlight = null
          rpcGrantController = null
          rpcGrantGeneration += 1
        }
        fn(value)
      }
      const onAbort = () => finish(reject, abortError())
      signal?.addEventListener?.('abort', onAbort, { once: true })
      if (signal?.aborted) { onAbort(); return }
      current.promise.then(value => finish(resolve, value), error => finish(reject, error))
    })
  }

  return { refresh, snapshot, getSnapshot, subscribe(listener) { if (disposed) return () => {}; listeners.add(listener); return () => listeners.delete(listener) }, noteRedirect, invalidate, dispose, requestRpcGrant, get version() { return version } }
}
