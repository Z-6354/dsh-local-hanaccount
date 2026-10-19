import test from 'node:test'
import assert from 'node:assert/strict'
import {
  AUTH_STATUS,
  classifyMeFailure,
  classifyMeResponse,
  createAuthSession,
  loginGateDecision,
} from '../src/lib/auth-session.js'

function wait() {
  return new Promise((resolve) => setImmediate(resolve))
}

test('only an explicit unauthenticated /auth/me fact redirects LoginGate, and only once', async () => {
  const session = createAuthSession({
    request: async () => ({ authenticated: false, nativeAuthenticated: false, passwordConfigured: true }),
  })
  await session.refresh()
  const first = loginGateDecision(session.snapshot())
  assert.equal(first.redirect, true)
  assert.equal(first.overlay, null)
  assert.equal(session.noteRedirect(), true)
  const second = loginGateDecision(session.snapshot())
  assert.equal(second.redirect, false)
  assert.equal(second.overlay, 'unauthenticated')
})

test('network, 503 and parse-class failures stay unavailable and do not replace', async () => {
  for (const error of [
    Object.assign(new Error('offline'), { name: 'TypeError' }),
    Object.assign(new Error('bad gateway'), { status: 503 }),
    Object.assign(new Error('aborted'), { name: 'AbortError' }),
  ]) {
    const classified = classifyMeFailure(error)
    assert.equal(classified.status, AUTH_STATUS.unavailable)
    assert.equal(loginGateDecision({ status: classified.status, me: null, redirectsRemaining: 1 }).redirect, false)
    assert.equal(loginGateDecision({ status: classified.status, me: null, redirectsRemaining: 1 }).overlay, 'unavailable')
  }
})

test('403 access_denied is temporary unavailability, retires RPC grants, and preserves the confirmed scope', async () => {
  const scope = '8'.repeat(48)
  let meCalls = 0
  let grantCalls = 0
  const session = createAuthSession({
    request: async path => {
      if (path === '/auth/me') {
        meCalls += 1
        if (meCalls === 2) throw Object.assign(new Error('access_denied'), { status: 403, code: 'access_denied' })
        return { authenticated: true, nativeAuthenticated: true, resumeScope: scope }
      }
      grantCalls += 1
      return { protocol: 1, grant: '8'.repeat(64), scope, expiresAt: Date.now() + 60_000 }
    },
  })
  await session.refresh()
  await session.requestRpcGrant()
  await session.refresh()
  assert.equal(session.getSnapshot().status, AUTH_STATUS.unavailable)
  assert.equal(session.getSnapshot().scope, scope)
  assert.equal(session.snapshot().lastConfirmed.status, AUTH_STATUS.authenticated)
  await assert.rejects(session.requestRpcGrant(), { code: 'auth_required' })
  assert.equal(grantCalls, 1)
  await session.refresh()
  assert.equal(session.getSnapshot().status, AUTH_STATUS.authenticated)
  assert.equal(session.getSnapshot().scope, scope)
  session.invalidate('logout')
  assert.equal(session.getSnapshot().status, AUTH_STATUS.unauthenticated)
  assert.equal(session.getSnapshot().scope, null)
  session.dispose()
})

test('only a 403 with access_denied uses the recoverable denial classification', () => {
  assert.equal(classifyMeFailure(Object.assign(new Error('denied'), { status: 403, code: 'access_denied' })).status, AUTH_STATUS.unavailable)
  assert.equal(classifyMeFailure(Object.assign(new Error('forbidden'), { status: 403, code: 'identity_revoked' })).status, AUTH_STATUS.unauthenticated)
  assert.equal(classifyMeFailure(Object.assign(new Error('unauthorized'), { status: 401, code: 'identity_revoked' })).status, AUTH_STATUS.unauthenticated)
})

test('refreshMe keeps the last confirmed identity when the next check fails', async () => {
  let calls = 0
  const session = createAuthSession({
    request: async () => {
      calls += 1
      if (calls === 1) return { authenticated: true, nativeAuthenticated: true, passwordConfigured: true }
      throw Object.assign(new Error('HTTP 503'), { status: 503 })
    },
  })
  await session.refresh()
  assert.equal(session.snapshot().status, AUTH_STATUS.authenticated)
  await session.refresh()
  const snap = session.snapshot()
  assert.equal(snap.status, AUTH_STATUS.unavailable)
  assert.equal(snap.lastConfirmed.status, AUTH_STATUS.authenticated)
  assert.equal(snap.me.authenticated, true)
  assert.equal(loginGateDecision(snap).redirect, false)
})

test('concurrent refreshMe shares one in-flight request', async () => {
  let inflight = 0
  let started = 0
  let release
  const session = createAuthSession({
    request: async () => {
      started += 1
      inflight += 1
      await new Promise((resolve) => { release = resolve })
      inflight -= 1
      return { authenticated: true, nativeAuthenticated: true, passwordConfigured: true }
    },
  })
  const first = session.refresh()
  const second = session.refresh()
  await wait()
  assert.equal(started, 1)
  assert.equal(inflight, 1)
  release()
  await Promise.all([first, second])
  assert.equal(started, 1)
  assert.equal(session.snapshot().status, AUTH_STATUS.authenticated)
})

test('a disposed session discards a late /auth/me result', async () => {
  let finish
  const session = createAuthSession({
    request: () => new Promise((resolve) => { finish = resolve }),
  })
  const pending = session.refresh()
  session.dispose()
  finish({ authenticated: false, nativeAuthenticated: false, passwordConfigured: true })
  await pending
  assert.notEqual(session.snapshot().status, AUTH_STATUS.unauthenticated)
  assert.equal(loginGateDecision(session.snapshot()).redirect, false)
})

test('requestRpcGrant is in-memory, coalesces calls, and rejects a response from a retired auth scope', async () => {
  const scope = 'a'.repeat(48)
  let grantCalls = 0
  let releaseGrant
  const session = createAuthSession({
    request: async (path, options = {}) => {
      if (path === '/auth/me') return { authenticated: true, nativeAuthenticated: true, resumeScope: scope }
      assert.equal(path, '/auth/rpc-grant')
      assert.equal(options.method, 'POST')
      assert.equal(options.body, '{}')
      grantCalls += 1
      return new Promise(resolve => { releaseGrant = resolve })
    },
  })
  await session.refresh()
  const first = session.requestRpcGrant()
  const second = session.requestRpcGrant()
  await wait()
  assert.equal(grantCalls, 1)
  session.invalidate('logout')
  releaseGrant({ protocol: 1, grant: 'c'.repeat(64), scope, expiresAt: Date.now() + 10_000 })
  await assert.rejects(first, { code: 'auth_scope_changed' })
  await assert.rejects(second, { code: 'auth_scope_changed' })
  await assert.rejects(session.requestRpcGrant(), { code: 'auth_required' })
  session.dispose()
})

test('requestRpcGrant rejects an identity mismatch and keeps a valid lease in memory', async () => {
  const scope = 'a'.repeat(48)
  let grantCalls = 0
  const session = createAuthSession({
    request: async path => {
      if (path === '/auth/me') return { authenticated: true, nativeAuthenticated: true, resumeScope: scope }
      grantCalls += 1
      return { protocol: 1, grant: 'd'.repeat(64), scope, expiresAt: Date.now() + 60_000 }
    },
  })
  await session.refresh()
  const first = await session.requestRpcGrant()
  const second = await session.requestRpcGrant()
  assert.equal(first.grant, second.grant)
  assert.equal(grantCalls, 1)
  session.invalidate('logout')
  await assert.rejects(session.requestRpcGrant(), { code: 'auth_required' })
  session.dispose()

  const mismatch = createAuthSession({
    request: async path => path === '/auth/me'
      ? { authenticated: true, nativeAuthenticated: true, resumeScope: scope }
      : { protocol: 1, grant: 'e'.repeat(64), scope: 'b'.repeat(48), expiresAt: Date.now() + 60_000 },
  })
  await mismatch.refresh()
  await assert.rejects(mismatch.requestRpcGrant(), { code: 'invalid_rpc_grant' })
  mismatch.dispose()
})

test('requestRpcGrant cancellation is waiter-local while another coalesced caller remains', async () => {
  const scope = 'f'.repeat(48)
  let grantCalls = 0
  let release
  let requestSignal
  const session = createAuthSession({
    request: async path => {
      if (path === '/auth/me') return { authenticated: true, nativeAuthenticated: true, resumeScope: scope }
      grantCalls += 1
      return new Promise(resolve => { release = resolve })
    },
  })
  await session.refresh()
  const a = new AbortController()
  const b = new AbortController()
  const first = session.requestRpcGrant({ signal: a.signal })
  const second = session.requestRpcGrant({ signal: b.signal })
  await wait()
  assert.equal(grantCalls, 1)
  b.abort()
  await assert.rejects(second, { code: 'aborted' })
  assert.equal(a.signal.aborted, false)
  release({ protocol: 1, grant: '1'.repeat(64), scope, expiresAt: Date.now() + 60_000 })
  assert.equal((await first).scope, scope)
  session.dispose()

  const thirdSession = createAuthSession({
    request: async path => path === '/auth/me'
      ? { authenticated: true, nativeAuthenticated: true, resumeScope: scope }
      : new Promise(resolve => { release = resolve }),
  })
  await thirdSession.refresh()
  const c = new AbortController()
  const fourth = thirdSession.requestRpcGrant()
  const fifth = thirdSession.requestRpcGrant({ signal: c.signal })
  await wait()
  c.abort()
  await assert.rejects(fifth, { code: 'aborted' })
  release({ protocol: 1, grant: '2'.repeat(64), scope, expiresAt: Date.now() + 60_000 })
  assert.equal((await fourth).scope, scope)
  thirdSession.dispose()
})

test('requestRpcGrant rejects already-aborted cached and in-flight waiters', async () => {
  const scope = 'b'.repeat(48)
  const session = createAuthSession({
    request: async path => path === '/auth/me'
      ? { authenticated: true, nativeAuthenticated: true, resumeScope: scope }
      : { protocol: 1, grant: '3'.repeat(64), scope, expiresAt: Date.now() + 60_000 },
  })
  await session.refresh()
  await session.requestRpcGrant()
  const aborted = new AbortController()
  aborted.abort()
  await assert.rejects(session.requestRpcGrant({ signal: aborted.signal }), { code: 'aborted' })
  session.dispose()
})

test('nativeMissing is not treated as logout', () => {
  const classified = classifyMeResponse({ authenticated: true, nativeAuthenticated: false, passwordConfigured: true })
  assert.equal(classified.status, AUTH_STATUS.unavailable)
  assert.equal(classified.substatus, 'nativeMissing')
  assert.equal(loginGateDecision({ status: classified.status, me: classified.me, redirectsRemaining: 1 }).redirect, false)
})

test('LoginGate in the client plugin uses classified auth instead of treating errors as logout', async () => {
  const { readFileSync } = await import('node:fs')
  const client = readFileSync(new URL('../src/client.js', import.meta.url), 'utf8')
  assert.match(client, /function loginGateDecision/)
  assert.match(client, /overlay: 'unavailable'/)
  assert.doesNotMatch(client, /me: \{ authenticated: false, error/)
  assert.match(client, /if \(decision\.redirect && session\.noteRedirect\(\)\) window\.location\.replace\('\/'\)/)
  assert.match(client, /overlay === 'loading'[\s\S]{0,300}'data-lha-checking'/)
  assert.doesNotMatch(client, /overlay === 'loading'[\s\S]{0,300}'data-lha-loading'/)
})
