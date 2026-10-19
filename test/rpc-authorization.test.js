import test from 'node:test'
import assert from 'node:assert/strict'
import { createRpcAuthorization } from '../src/lib/rpc-authorization.js'

function fixture(clock = globalThis) {
  const tokens = new Map([
    ['token-a', { scope: 'a'.repeat(48) }],
    ['token-b', { scope: 'b'.repeat(48) }],
  ])
  const listeners = new Set()
  const operator = { id: 'operator' }
  const store = {
    assertActive() {},
    sessionFromToken(token) { return tokens.get(token) || null },
    resumeScope(token) { return tokens.get(token)?.scope },
    onSecurityChange(listener) { listeners.add(listener); return () => listeners.delete(listener) },
    logout(token) { tokens.delete(token); for (const listener of listeners) listener() },
  }
  const connection = { operator, admit: () => ({ peer: operator }) }
  const bridge = { authenticated: () => true }
  const gate = { ipContext: () => ({ verdict: { action: 'allow' } }) }
  const authorization = createRpcAuthorization({ store, connection, bridge, gate, ttlMs: 1_000, clock })
  const issue = token => authorization.issueForRequest({ headers: { cookie: `dsh_gate_token=${token}` } })
  return { tokens, operator, store, connection, bridge, gate, authorization, issue }
}

test('a grant binds the authenticated account scope and the admitted operator peer', () => {
  const f = fixture()
  const lease = f.issue('token-a')
  assert.equal(lease.protocol, 1)
  assert.equal(lease.scope, 'a'.repeat(48))
  assert.match(lease.grant, /^[a-f0-9]{64}$/)
  assert.equal(f.authorization.size, 1)
  const authorized = f.authorization.authorizeGrant({ peer: f.operator, grant: lease.grant, expectedScope: lease.scope })
  assert.equal(authorized.scope, lease.scope)
  assert.equal(authorized.isCurrent(), true)
  assert.throws(() => f.authorization.authorizeGrant({ peer: {}, grant: lease.grant }), { code: 'rpc_grant_unauthorized' })
  assert.throws(() => f.authorization.authorizeGrant({ peer: f.operator, grant: lease.grant, expectedScope: 'b'.repeat(48) }), { code: 'rpc_grant_unauthorized' })
  f.authorization.dispose()
  assert.equal(authorized.signal.aborted, true)
})

test('different accounts on the shared OperatorPeer receive independent grants', () => {
  const f = fixture()
  const a = f.issue('token-a')
  const b = f.issue('token-b')
  assert.notEqual(a.grant, b.grant)
  assert.equal(f.authorization.authorizeGrant({ peer: f.operator, grant: a.grant }).scope, 'a'.repeat(48))
  assert.equal(f.authorization.authorizeGrant({ peer: f.operator, grant: b.grant }).scope, 'b'.repeat(48))
  f.authorization.dispose()
})

test('rc.2 browserPeer grants bind the browser peer and refuse other admitted API peers', () => {
  const f = fixture()
  const browserPeer = { id: 'browser', principal: { kind: 'owner' } }
  f.connection.browserPeer = browserPeer
  f.connection.admit = () => ({ peer: browserPeer })
  assert.equal(f.authorization.state().identityInterface, 'browserPeer')
  const lease = f.issue('token-a')
  assert.equal(f.authorization.authorizeGrant({ peer: browserPeer, grant: lease.grant, expectedScope: lease.scope }).scope, lease.scope)
  f.connection.admit = () => ({ peer: f.operator })
  assert.throws(() => f.issue('token-a'), { code: 'rpc_grant_unauthorized' })
  f.store.logout('token-a')
  assert.throws(() => f.authorization.authorizeGrant({ peer: browserPeer, grant: lease.grant }), { code: 'rpc_grant_unauthorized' })
  f.authorization.dispose()
})

test('missing RPC identity capabilities disable grant issuance with an explicit diagnostic', () => {
  const f = fixture()
  delete f.connection.admit
  assert.deepEqual(f.authorization.state().missingCapabilities, ['connection.admit'])
  assert.throws(() => f.issue('token-a'), { code: 'rpc_authorization_unavailable', status: 503 })
  f.connection.admit = () => ({ peer: undefined })
  delete f.connection.operator
  assert.deepEqual(f.authorization.state().missingCapabilities, ['connection.operator'])
  assert.throws(() => f.issue('token-a'), { code: 'rpc_authorization_unavailable', status: 503 })
  assert.equal(f.authorization.size, 0)
  f.authorization.dispose()
})

test('a missing cookie, forged scope, denied native bridge, or rejected peer cannot mint a grant', () => {
  const f = fixture()
  assert.throws(() => f.authorization.issueForRequest({ headers: {} }), { code: 'rpc_grant_unauthorized' })
  f.bridge.authenticated = () => false
  assert.throws(() => f.issue('token-a'), { code: 'rpc_grant_unauthorized' })
  f.bridge.authenticated = () => true
  f.connection.admit = () => ({ rejection: 401 })
  assert.throws(() => f.issue('token-a'), { code: 'rpc_grant_unauthorized' })
  assert.equal(f.authorization.size, 0)
  f.authorization.dispose()
})

test('logout immediately aborts active calls and expired grants fail closed', () => {
  const f = fixture()
  const lease = f.issue('token-a')
  const active = f.authorization.authorizeGrant({ peer: f.operator, grant: lease.grant })
  f.store.logout('token-a')
  assert.equal(active.signal.aborted, true)
  assert.throws(() => f.authorization.authorizeGrant({ peer: f.operator, grant: lease.grant }), { code: 'rpc_grant_unauthorized' })

  const next = f.issue('token-b')
  const activeNext = f.authorization.authorizeGrant({ peer: f.operator, grant: next.grant })
  const originalNow = Date.now
  Date.now = () => next.expiresAt + 1
  try {
    assert.equal(activeNext.isCurrent(), false)
    assert.equal(activeNext.signal.aborted, true)
  } finally { Date.now = originalNow }
  f.authorization.dispose()
})

test('a delayed expiry timer reports expiry only while the same peer and account scope remain current', () => {
  const f = fixture()
  const lease = f.issue('token-a')
  const revoked = f.issue('token-b')
  const active = f.authorization.authorizeGrant({ peer: f.operator, grant: lease.grant, expectedScope: lease.scope })
  const revokedActive = f.authorization.authorizeGrant({ peer: f.operator, grant: revoked.grant, expectedScope: revoked.scope })
  f.store.logout('token-b')
  assert.equal(revokedActive.signal.reason.code, 'rpc_grant_revoked')
  const originalNow = Date.now
  Date.now = () => lease.expiresAt + 1
  try {
    assert.equal(active.isCurrent(), false)
    assert.equal(active.signal.aborted, true)
    assert.equal(active.signal.reason.code, 'rpc_grant_expired')
    assert.throws(() => f.authorization.authorizeGrant({ peer: f.operator, grant: lease.grant, expectedScope: lease.scope }), { code: 'rpc_grant_unauthorized' })
  } finally {
    Date.now = originalNow
    f.authorization.dispose()
  }
})

test('a delayed expiry callback classifies a silently revoked account as revoked, never renewable expiry', () => {
  let now = 50_000
  let next = 0
  const tasks = new Map()
  const clock = {
    Date: { now: () => now },
    setTimeout(fn, delay) { const id = ++next; tasks.set(id, { fn, due: now + delay }); return id },
    clearTimeout(id) { tasks.delete(id) },
  }
  const f = fixture(clock)
  const lease = f.issue('token-a')
  const active = f.authorization.authorizeGrant({ peer: f.operator, grant: lease.grant, expectedScope: lease.scope })
  // Model a lost security-change notification: only the delayed timer can observe this retirement.
  f.tokens.delete('token-a')
  now = lease.expiresAt + 1
  for (const [id, task] of [...tasks]) if (task.due <= now) { tasks.delete(id); task.fn() }
  assert.equal(active.signal.aborted, true)
  assert.equal(active.signal.reason.code, 'rpc_grant_revoked')
  f.authorization.dispose()
})

test('grant count is bounded per account', () => {
  const f = fixture()
  for (let i = 0; i < 32; i += 1) f.issue('token-a')
  assert.throws(() => f.issue('token-a'), { code: 'rpc_grant_capacity' })
  assert.equal(f.authorization.size, 32)
  f.authorization.dispose()
})
