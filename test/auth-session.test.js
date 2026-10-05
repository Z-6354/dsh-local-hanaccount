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
})
