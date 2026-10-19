import assert from 'node:assert/strict'
import test from 'node:test'
import vm from 'node:vm'
import { AUTH_BOOTSTRAP_SCRIPT } from '../src/lib/auth-bootstrap.generated.js'
import { createAuthSession } from '../src/lib/auth-session.js'

function bootstrapContext({ fetchImpl, origin = 'https://fixture.invalid' }) {
  const events = new Map()
  const window = { location: { origin }, addEventListener(type, fn) { events.set(type, fn) } }
  const context = vm.createContext({ window, location: window.location, fetch: fetchImpl, URL, AbortController, setTimeout, clearTimeout })
  return { window, events, context }
}

test('early bootstrap starts one /auth/me request and transfers the same AuthSession once', async () => {
  let finish, calls = 0, request
  const { window, context } = bootstrapContext({
    fetchImpl: (url, options) => {
      calls++; request = { url, options }
      return new Promise(resolve => { finish = () => resolve({ ok: true, redirected: false, text: async () => JSON.stringify({ authenticated: true, nativeAuthenticated: true, resumeScope: 'a'.repeat(48) }) }) })
    },
  })
  vm.runInContext(AUTH_BOOTSTRAP_SCRIPT, context)
  assert.equal(calls, 1)
  assert.equal(request.url, 'https://fixture.invalid/dsh-local-hanaccount/api/auth/me')
  assert.equal(request.options.credentials, 'same-origin')
  assert.equal(request.options.cache, 'no-store')
  assert.equal(request.options.redirect, 'error')
  const holder = Object.getOwnPropertyDescriptor(window, '__HANACCOUNT_BOOTSTRAP_V1__').value
  const adopted = holder.claim()
  assert.ok(adopted)
  assert.equal(holder.claim(), null)
  vm.runInContext(AUTH_BOOTSTRAP_SCRIPT, context)
  assert.equal(calls, 1)
  finish()
  await adopted.refresh()
  assert.equal(adopted.getSnapshot().status, 'authenticated')
  assert.equal(adopted.getSnapshot().scope, 'a'.repeat(48))
  adopted.dispose()
})

test('unclaimed bootstrap retires on pagehide and cannot later be adopted', async () => {
  let finish
  const { window, events, context } = bootstrapContext({ fetchImpl: () => new Promise(resolve => { finish = resolve }) })
  vm.runInContext(AUTH_BOOTSTRAP_SCRIPT, context)
  const holder = Object.getOwnPropertyDescriptor(window, '__HANACCOUNT_BOOTSTRAP_V1__').value
  events.get('pagehide')()
  assert.equal(holder.claim(), null)
  finish?.({ ok: true, redirected: false, text: async () => JSON.stringify({ authenticated: true, nativeAuthenticated: true, resumeScope: 'b'.repeat(48) }) })
})

test('local logout invalidation revokes scope and retires an older successful refresh', async () => {
  let finish
  const auth = createAuthSession({ request: () => new Promise(resolve => { finish = resolve }) })
  const pending = auth.refresh()
  auth.invalidate('logout')
  assert.equal(auth.getSnapshot().status, 'unauthenticated')
  assert.equal(auth.getSnapshot().reason, 'logout')
  assert.equal(auth.getSnapshot().scope, null)
  finish({ authenticated: true, nativeAuthenticated: true, resumeScope: 'c'.repeat(48) })
  await pending
  assert.equal(auth.getSnapshot().status, 'unauthenticated')
  assert.equal(auth.getSnapshot().scope, null)
  auth.dispose()
})
