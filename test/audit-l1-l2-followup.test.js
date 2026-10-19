/**
 * L-01 remainder (first-visitor takeover through a header-less tunnel) and L-02 remainder (distributed guessing and
 * event-loop blocking), 2026-10-09 audit.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { Readable } from 'node:stream'
import { createNativeBridge } from '../src/lib/native-bridge.js'
import { createStore } from '../src/lib/store.js'
import { hashPassword, verifyPassword, verifyPasswordAsync } from '../src/lib/password.js'
import { createGate } from '../src/gate.js'
import { createApiHandler } from '../src/api.js'
import { createLoginGuard } from '../src/lib/login-guard.js'
import { applyInitialPassword, readInitialPassword, PASSWORD_ENV, PASSWORD_FILE_ENV } from '../src/lib/initial-password.js'

// Same shape as the official connection used in password-native.test.js: minting a native cookie must succeed for a
// successful login to complete.
const owner = () => ({
  requestRejection(req) { return String(req.headers.cookie || '').split(/;\s*/).includes('dsh-auth-fixture=native') ? undefined : 401 },
  authenticatedUrl() { return 'http://localhost/?token=internal-only' },
  authorizeIndex(_req, res) { res.writeHead(303, { location: '/', 'set-cookie': 'dsh-auth-fixture=native; Path=/; HttpOnly; SameSite=Strict' }); res.end(); return false },
})

async function withApi(config, fn, { loginGuard, password = 'correct-password' } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'audit-follow-'))
  const store = createStore({ dataDir: dir, ...config })
  if (password) store.setPasswordHash(hashPassword(password))
  const bridge = createNativeBridge(owner())
  const gate = createGate(store, bridge)
  const handler = createApiHandler({ store, gate, bridge, ...(loginGuard ? { loginGuard } : {}) })
  try { return await fn({ store, handler, dir }) }
  finally { gate.dispose(); bridge.dispose(); rmSync(dir, { recursive: true, force: true }) }
}
async function call(handler, { method = 'POST', path, remote = '203.0.113.9', headers = {}, body }) {
  const r = Readable.from(body === undefined ? [] : [JSON.stringify(body)])
  Object.assign(r, { method, url: `/dsh-local-hanaccount/api/${path}`, headers: { host: 'localhost', 'content-type': 'application/json', ...headers }, socket: { remoteAddress: remote } })
  const out = {}
  await handler(r, { writeHead(status, h) { out.status = status; out.headers = h }, setHeader() {}, getHeader() {}, end(text) { try { out.body = JSON.parse(text) } catch { out.body = text } } })
  return out
}
const login = (handler, remote, password = 'wrong') => call(handler, { path: 'auth/login', remote, body: { password } })

// ---------------------------------------------------------------- L-01: browser setup is closed

test('L-01: auth/setup never sets a password, even for a clean direct loopback request', async () => {
  await withApi({ ipLimitEnabled: false }, async ({ store, handler }) => {
    assert.equal(store.cfg.passwordHash, '')
    // Exactly what a header-less tunnel (frp tcp, ssh -R) looks like: loopback peer, Host: localhost, no forwarding headers.
    const r = await call(handler, { path: 'auth/setup', remote: '127.0.0.1', body: { password: 'attacker-password' } })
    assert.equal(r.status, 403)
    assert.equal(r.body.code, 'setup_disabled')
    assert.equal(store.cfg.passwordHash, '', 'the first visitor must not be able to claim the instance')
    assert.equal(Object.keys(store.state.sessions).length, 0)
  }, { password: '' })
})

test('L-01: with no password, login says so and cannot be used to set one', async () => {
  await withApi({ ipLimitEnabled: false }, async ({ store, handler }) => {
    const r = await login(handler, '127.0.0.1', 'attacker-password')
    assert.equal(r.status, 400)
    assert.equal(r.body.code, 'password_not_configured')
    assert.equal(store.cfg.passwordHash, '')
  }, { password: '' })
})

test('L-01: the initial password comes from the environment, once, and never replaces an existing one', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'audit-initpw-'))
  try {
    const store = createStore({ dataDir: dir })
    assert.deepEqual(applyInitialPassword(store, { env: {} }), { applied: false, reason: 'not_provided' })
    assert.deepEqual(applyInitialPassword(store, { env: { [PASSWORD_ENV]: 'short' } }), { applied: false, reason: 'too_short' })
    assert.equal(store.cfg.passwordHash, '')
    assert.deepEqual(applyInitialPassword(store, { env: { [PASSWORD_ENV]: 'initial-password' } }), { applied: true })
    assert.equal(verifyPassword('initial-password', store.cfg.passwordHash), true)
    const hash = store.cfg.passwordHash
    assert.deepEqual(applyInitialPassword(store, { env: { [PASSWORD_ENV]: 'another-password' } }), { applied: false, reason: 'already_configured' })
    assert.equal(store.cfg.passwordHash, hash, 'a leftover environment variable must not overwrite the real password')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('L-01: the password file wins over the variable, loses its trailing newline, and an unreadable file is reported', () => {
  const dir = mkdtempSync(join(tmpdir(), 'audit-initpw-file-'))
  try {
    const file = join(dir, 'pw')
    writeFileSync(file, 'file-password\r\n')
    assert.equal(readInitialPassword({ [PASSWORD_FILE_ENV]: file, [PASSWORD_ENV]: 'env-password' }), 'file-password')
    const store = createStore({ dataDir: join(dir, 'data') })
    const warnings = []
    const result = applyInitialPassword(store, { env: { [PASSWORD_FILE_ENV]: join(dir, 'missing') }, logger: { warn: (m) => warnings.push(m) } })
    assert.deepEqual(result, { applied: false, reason: 'unreadable' })
    assert.equal(store.cfg.passwordHash, '')
    assert.equal(warnings.length, 1)
    assert.ok(!warnings[0].includes('file-password'))
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

// ---------------------------------------------------------------- L-02: asynchronous verification

test('L-02: async verification agrees with the synchronous one', async () => {
  const hash = hashPassword('some-password')
  assert.equal(await verifyPasswordAsync('some-password', hash), true)
  assert.equal(await verifyPasswordAsync('other-password', hash), false)
  assert.equal(await verifyPasswordAsync('x', ''), false)
  assert.equal(await verifyPasswordAsync('x', '$scrypt$bad'), false)
})

test('L-02: the event loop keeps running while a password is being verified', async () => {
  const hash = hashPassword('some-password')
  let ticks = 0
  const timer = setInterval(() => { ticks++ }, 5)
  try { await Promise.all(Array.from({ length: 8 }, () => verifyPasswordAsync('wrong', hash))) }
  finally { clearInterval(timer) }
  assert.ok(ticks >= 3, `the loop only ticked ${ticks} times during 8 verifications: it was blocked`)
})

test('L-02: concurrent wrong passwords are counted one by one, so a burst cannot outrun the lockout', async () => {
  await withApi({ ipLimitEnabled: true }, async ({ handler, store }) => {
    const max = store.cfg.lockout.maxAttempts
    const results = await Promise.all(Array.from({ length: 30 }, () => login(handler, '203.0.113.50')))
    const verified = results.filter((r) => r.status === 401).length
    assert.equal(verified, max, `only ${max} guesses may reach verification, ${verified} did`)
    assert.ok(results.every((r) => [401, 429].includes(r.status)))
    assert.ok(store.getLockout('203.0.113.50').lockedUntil > Date.now())
  }, { loginGuard: createLoginGuard({ failureLimit: 1000, maxQueue: 100 }) })
})

test('L-02: a correct password still works after earlier failures, and clears the counter', async () => {
  await withApi({ ipLimitEnabled: true }, async ({ handler, store }) => {
    for (let n = 0; n < 3; n++) assert.equal((await login(handler, '203.0.113.60')).status, 401)
    assert.equal((await login(handler, '203.0.113.60', 'correct-password')).status, 200)
    assert.equal(store.getLockout('203.0.113.60').attempts, 0)
  })
})

// ---------------------------------------------------------------- L-02: global budget

test('L-02: many addresses with a few guesses each hit a global cooldown that doubles under pressure', () => {
  let clock = 1_000_000
  const guard = createLoginGuard({ now: () => clock, failureLimit: 5, windowMs: 60_000, baseCooldownMs: 60_000, maxCooldownMs: 240_000 })
  assert.equal(guard.check().ok, true)
  for (let n = 0; n < 5; n++) guard.recordFailure()
  const first = guard.check()
  assert.equal(first.ok, false)
  assert.equal(first.retryAfterSec, 60)
  clock += 61_000
  assert.equal(guard.check().ok, true, 'the cooldown ends')
  for (let n = 0; n < 5; n++) guard.recordFailure()
  assert.equal(guard.check().retryAfterSec, 120, 'second trigger inside the calm period doubles')
  clock += 121_000
  for (let n = 0; n < 5; n++) guard.recordFailure()
  assert.equal(guard.check().retryAfterSec, 240)
  clock += 241_000
  for (let n = 0; n < 5; n++) guard.recordFailure()
  assert.equal(guard.check().retryAfterSec, 240, 'capped')
  clock += 241_000 + 2 * 3600_000
  for (let n = 0; n < 5; n++) guard.recordFailure()
  assert.equal(guard.check().retryAfterSec, 60, 'a calm hour resets the escalation')
})

test('L-02: failures spread over time never trip the budget', () => {
  let clock = 0
  const guard = createLoginGuard({ now: () => clock, failureLimit: 5, windowMs: 60_000 })
  for (let n = 0; n < 50; n++) { guard.recordFailure(); clock += 20_000 }
  assert.equal(guard.check().ok, true)
})

test('L-02 end to end: a distributed guess is stopped by the global cooldown even though no address reached its own limit', async () => {
  const guard = createLoginGuard({ failureLimit: 6, maxQueue: 100 })
  await withApi({ ipLimitEnabled: true }, async ({ handler }) => {
    const statuses = []
    for (let n = 0; n < 10; n++) statuses.push((await login(handler, `198.51.100.${n + 1}`)).status)
    assert.deepEqual(statuses, [401, 401, 401, 401, 401, 401, 429, 429, 429, 429])
    const blocked = await login(handler, '198.51.100.99', 'correct-password')
    assert.equal(blocked.status, 429, 'while cooling down even the right password from a new address waits')
    assert.ok(blocked.body.retryAfterSec > 0)
  }, { loginGuard: guard })
})

test('L-02 end to end: an explicitly allow-listed address is exempt from the global cooldown and cannot trip it', async () => {
  const guard = createLoginGuard({ failureLimit: 3, maxQueue: 100 })
  await withApi({ ipLimitEnabled: true, allow: ['203.0.113.77'] }, async ({ handler }) => {
    for (let n = 0; n < 3; n++) await login(handler, '203.0.113.77')
    assert.equal(guard.check().ok, true, 'a trusted address failing must not lock everyone else out')
    for (let n = 0; n < 3; n++) await login(handler, `198.51.100.${n + 1}`)
    assert.equal(guard.check().ok, false)
    const trusted = await login(handler, '203.0.113.77', 'correct-password')
    assert.equal(trusted.status, 200, 'the allow-listed address still logs in during the global cooldown')
  }, { loginGuard: guard })
})

test('L-02: the verification queue is bounded and refused attempts are not charged to the client', async () => {
  const guard = createLoginGuard({ maxConcurrent: 1, maxQueue: 2, failureLimit: 1000 })
  const release = []
  const gate = () => new Promise((resolve) => release.push(resolve))
  const running = [guard.run(gate), guard.run(gate), guard.run(gate)]
  await assert.rejects(guard.run(gate), (error) => error.code === 'login_busy' && error.status === 429)
  assert.deepEqual(guard._state(), { running: 1, queued: 2, cooldownUntil: 0, level: 0 })
  while (release.length || guard._state().running) { release.shift()?.(); await new Promise((r) => setImmediate(r)) }
  await Promise.all(running)
  assert.equal(guard._state().running, 0)

  await withApi({ ipLimitEnabled: true }, async ({ handler, store }) => {
    const results = await Promise.all(Array.from({ length: 40 }, (_, n) => login(handler, `192.0.2.${n + 1}`)))
    const busy = results.filter((r) => r.body?.code === 'login_busy')
    assert.ok(busy.length > 0, 'a flood must be turned away rather than queued without bound')
    for (const [index, r] of results.entries()) {
      if (r.body?.code === 'login_busy') assert.equal(store.getLockout(`192.0.2.${index + 1}`).attempts, 0, 'a refused attempt is not a failed guess')
    }
  }, { loginGuard: createLoginGuard({ maxConcurrent: 1, maxQueue: 2, failureLimit: 1000 }) })
})
