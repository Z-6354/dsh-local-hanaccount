import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createStore } from '../src/lib/store.js'
import { createAuthSession } from '../src/lib/auth-session.js'

test('resume scope persists per session, rotates on new login, and cannot authenticate', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hanaccount-scope-'))
  try {
    const store = createStore({ dataDir: dir, passwordHash: 'fixture' })
    const token = store.issueSession()
    const scope = store.resumeScope(token)
    assert.match(scope, /^[a-f0-9]{48}$/)
    assert.equal(createStore({ dataDir: dir, passwordHash: 'fixture' }).resumeScope(token), scope)
    assert.equal(store.sessionFromToken(scope), null)
    assert.notEqual(store.resumeScope(store.issueSession()), scope)
    store.logout(token)
    assert.equal(store.resumeScope(token), undefined)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('legacy session scope migration commits once without extending timestamps', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hanaccount-scope-'))
  try {
    const store = createStore({ dataDir: dir, passwordHash: 'fixture' })
    const token = store.issueSession()
    const session = store.sessionFromToken(token, { touch: false })
    delete session.resumeScope
    const before = { createdAt: session.createdAt, lastSeenAt: session.lastSeenAt }
    store.saveState()
    const first = store.resumeScope(token)
    const disk = readFileSync(join(dir, 'state.json'), 'utf8')
    assert.equal(store.resumeScope(token), first)
    assert.equal(readFileSync(join(dir, 'state.json'), 'utf8'), disk)
    assert.equal(session.createdAt, before.createdAt)
    assert.equal(session.lastSeenAt, before.lastSeenAt)
    store.setPasswordHash('rotated')
    assert.equal(store.resumeScope(token), undefined)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('public auth snapshot has no credentials and pauses recovery on temporary error', async () => {
  let body = { authenticated: true, nativeAuthenticated: true, resumeScope: 'a'.repeat(48), secret: 'never-public' }
  const auth = createAuthSession({ request: async () => { if (body instanceof Error) throw body; return body } })
  const events = []
  const off = auth.subscribe(s => events.push(s))
  await auth.refresh()
  assert.equal(auth.getSnapshot().scope, 'a'.repeat(48))
  assert.deepEqual(Object.keys(auth.getSnapshot()).sort(), ['reason', 'revision', 'scope', 'status'])
  body = new Error('offline')
  await auth.refresh()
  assert.equal(auth.getSnapshot().status, 'unavailable')
  assert.equal(auth.getSnapshot().scope, 'a'.repeat(48))
  body = { authenticated: false, nativeAuthenticated: false }
  await auth.refresh()
  assert.equal(auth.getSnapshot().scope, null)
  off(); auth.dispose()
  const count = events.length
  await auth.refresh()
  assert.equal(events.length, count)
})
