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
  let status = AUTH_STATUS.unknown
  let reason = null
  let substatus = null
  let me = null
  let lastConfirmed = null
  let version = 0
  let inflight = null
  let redirectsUsed = 0
  let controller = null

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
    lastConfirmed = classified
  }

  async function refresh() {
    if (inflight) return inflight
    const mine = ++version
    if (status !== AUTH_STATUS.authenticated) status = AUTH_STATUS.checking
    controller = typeof AbortController === 'function' ? new AbortController() : null
    const timer = timeoutMs > 0 && controller ? setTimeout(() => controller.abort(), timeoutMs) : null
    inflight = (async () => {
      try {
        const body = await request('/auth/me', { signal: controller?.signal })
        if (mine !== version) return snapshot()
        apply(classifyMeResponse(body))
      } catch (error) {
        if (mine !== version) return snapshot()
        apply(classifyMeFailure(error))
      } finally {
        if (timer) clearTimeout(timer)
        if (mine === version) inflight = null
      }
      return snapshot()
    })()
    return inflight
  }

  function noteRedirect() {
    if (status !== AUTH_STATUS.unauthenticated || redirectsUsed >= 1) return false
    redirectsUsed += 1
    return true
  }

  function dispose() {
    version += 1
    inflight = null
    controller?.abort()
  }

  return { refresh, snapshot, noteRedirect, dispose, get version() { return version } }
}
