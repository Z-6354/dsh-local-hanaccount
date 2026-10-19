/**
 * L-01 (loopback proxy fails open) and L-02 (lockout defeated by address rotation), 2026-10-09 audit.
 * Policy: IPv4 only; loopback is the local operator only when `loopbackOperator` is set; forwarding headers on a
 * loopback peer never fall back to "local operator".
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { Readable } from 'node:stream'
import { createNativeBridge } from '../src/lib/native-bridge.js'
import { createStore } from '../src/lib/store.js'
import { hashPassword, recordFailedAttempt } from '../src/lib/password.js'
import { createGate } from '../src/gate.js'
import { createApiHandler } from '../src/api.js'
import { evaluateIpAccess, resolveClientIp, UNRESOLVED_PROXY_CLIENT } from '../src/lib/ip.js'

const req = (remote, headers = {}) => ({ socket: { remoteAddress: remote }, headers })
const resolve = (remote, headers) => resolveClientIp(req(remote, headers), { trustProxy: true })

test('L-01: a headerless loopback peer is still the direct local connection', () => {
  assert.equal(resolve('127.0.0.1', { host: 'localhost' }), '127.0.0.1')
})

test('L-01: any forwarding header on a loopback peer fails closed instead of becoming the local operator', () => {
  for (const headers of [
    { forwarded: 'for=203.0.113.7' },
    { via: '1.1 cloudflared' },
    { 'x-forwarded-proto': 'https' },
    { 'x-forwarded-host': 'dsh.example.test' },
    { 'cf-connecting-ip': '203.0.113.7' },
    { 'x-forwarded-for': 'garbage' },
    { 'x-forwarded-for': '127.0.0.1' },
    { 'x-real-ip': '127.0.0.1' },
    { 'x-real-ip': '0.0.0.0' },
    { 'x-real-ip': 'not-an-ip' },
  ]) {
    assert.equal(resolve('127.0.0.1', headers), UNRESOLVED_PROXY_CLIENT, JSON.stringify(headers))
  }
})

test('L-01: X-Forwarded-For uses the proxy-appended right-most hop, never the client-controlled left-most one', () => {
  // A client sends "X-Forwarded-For: 10.0.0.1"; the proxy appends the real peer.
  assert.equal(resolve('127.0.0.1', { 'x-forwarded-for': '10.0.0.1, 203.0.113.9' }), '203.0.113.9')
  // The client cannot pose as a local/allow-listed address by putting it first.
  assert.equal(resolve('127.0.0.1', { 'x-forwarded-for': '127.0.0.1, 203.0.113.9' }), '203.0.113.9')
  // Our own proxy chain (loopback hops on the right) is skipped, but nothing further left is trusted blindly.
  assert.equal(resolve('127.0.0.1', { 'x-forwarded-for': '203.0.113.9, 127.0.0.1' }), '203.0.113.9')
  assert.equal(resolve('127.0.0.1', { 'x-forwarded-for': '203.0.113.9, junk' }), UNRESOLVED_PROXY_CLIENT)
})

test('L-01: X-Real-IP and the proxy hop must agree; a disagreement means a client header leaked through', () => {
  assert.equal(resolve('127.0.0.1', { 'x-real-ip': '203.0.113.9', 'x-forwarded-for': '10.0.0.1, 203.0.113.9' }), '203.0.113.9')
  assert.equal(resolve('127.0.0.1', { 'x-real-ip': '203.0.113.9', 'x-forwarded-for': '203.0.113.9' }), '203.0.113.9')
  assert.equal(resolve('127.0.0.1', { 'x-real-ip': '198.51.100.1', 'x-forwarded-for': '10.0.0.1, 203.0.113.9' }), UNRESOLVED_PROXY_CLIENT)
})

test('L-01: a non-loopback peer can never choose its address through headers', () => {
  assert.equal(resolve('203.0.113.9', { 'x-real-ip': '127.0.0.1', 'x-forwarded-for': '127.0.0.1' }), '203.0.113.9')
})

test('L-01: loopback is not 免登录 by default, and the unresolved proxy client never is', () => {
  const cfg = { ipLimitEnabled: true, allow: ['127.0.0.1', '::1', '203.0.113.9'], deny: [] }
  assert.equal(evaluateIpAccess('127.0.0.1', cfg).whitelisted, false)
  assert.equal(evaluateIpAccess('::1', cfg).whitelisted, false)
  assert.equal(evaluateIpAccess(UNRESOLVED_PROXY_CLIENT, { ...cfg, loopbackOperator: true }).whitelisted, false)
  assert.equal(evaluateIpAccess('127.0.0.1', { ...cfg, loopbackOperator: true }).whitelisted, true)
  assert.equal(evaluateIpAccess('203.0.113.9', cfg).whitelisted, true, 'explicit remote allow entries still work')
})

test('L-02: IPv6 clients are refused; ::1 and IPv4-mapped IPv4 are not', () => {
  const cfg = { ipLimitEnabled: true, allow: [], deny: [] }
  for (const ip of ['2001:db8::1', '2001:db8::2', 'fe80::1', '2a00:1450:4001::200e']) {
    const verdict = evaluateIpAccess(ip, cfg)
    assert.equal(verdict.action, 'block', ip)
    assert.equal(verdict.reason, 'ipv6_not_supported', ip)
  }
  assert.equal(evaluateIpAccess('::1', cfg).action, 'pass')
  assert.equal(evaluateIpAccess('', cfg).action, 'block', 'no client address is never allowed through')
  assert.equal(resolve('::ffff:203.0.113.9', {}), '203.0.113.9')
  assert.equal(evaluateIpAccess(resolve('::ffff:203.0.113.9', {}), cfg).action, 'pass')
})

function owner() {
  return {
    requestRejection() { return undefined },
    authenticatedUrl() { return 'http://localhost/?token=internal-only' },
    authorizeIndex(r, res) { res.writeHead(303, { location: '/' }); res.end(); return false },
  }
}
async function withApi(config, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'audit-l1l2-'))
  const store = createStore({ dataDir: dir, ...config })
  store.setPasswordHash(hashPassword('correct-password'))
  const bridge = createNativeBridge(owner())
  const gate = createGate(store, bridge)
  try { return await fn({ store, bridge, gate, handler: createApiHandler({ store, gate, bridge }) }) }
  finally { gate.dispose(); bridge.dispose(); rmSync(dir, { recursive: true, force: true }) }
}
async function call(handler, { method = 'GET', path, remote, headers = {}, body }) {
  const r = Readable.from(body === undefined ? [] : [JSON.stringify(body)])
  Object.assign(r, { method, url: `/dsh-local-hanaccount/api/${path}`, headers: { host: 'localhost', 'content-type': 'application/json', ...headers }, socket: { remoteAddress: remote } })
  const out = {}
  await handler(r, { writeHead(status, h) { out.status = status; out.headers = h }, setHeader() {}, getHeader() {}, end(text) { try { out.body = JSON.parse(text) } catch { out.body = text } } })
  return out
}

test('L-01 end to end: a tunnel into loopback is not reported as whitelisted through the real API handler', async () => {
  await withApi({ ipLimitEnabled: true }, async ({ handler }) => {
    const direct = await call(handler, { path: 'status', remote: '127.0.0.1' })
    assert.equal(direct.status, 200)
    assert.equal(direct.body.whitelisted, false, 'default: even the local browser must log in')
    const tunnel = await call(handler, { path: 'status', remote: '127.0.0.1', headers: { 'x-forwarded-for': 'junk', via: 'frp' } })
    assert.equal(tunnel.body.whitelisted, false)
    assert.equal(tunnel.body.ip, UNRESOLVED_PROXY_CLIENT)
  })
})

test('L-01 end to end: auth/setup refuses any request that carries forwarding evidence', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'audit-setup-'))
  const store = createStore({ dataDir: dir, ipLimitEnabled: false })
  const bridge = createNativeBridge(owner())
  const gate = createGate(store, bridge)
  const handler = createApiHandler({ store, gate, bridge })
  try {
    for (const headers of [{ via: '1.1 tunnel' }, { forwarded: 'for=203.0.113.7' }, { 'x-forwarded-proto': 'https' }, { 'cf-ray': 'abc' }]) {
      const r = await call(handler, { method: 'POST', path: 'auth/setup', remote: '127.0.0.1', headers, body: { password: 'attacker-password' } })
      assert.equal(r.status, 403, JSON.stringify(headers))
    }
    assert.equal(store.cfg.passwordHash, '', 'no password may be set through a forwarded request')
  } finally { gate.dispose(); bridge.dispose(); rmSync(dir, { recursive: true, force: true }) }
})

test('L-02 end to end: rotating IPv6 addresses cannot mint fresh lockout buckets or any state', async () => {
  await withApi({ ipLimitEnabled: true }, async ({ handler, store }) => {
    const before = Object.keys(store.state.lockouts).length
    for (let n = 0; n < 40; n++) {
      const r = await call(handler, { method: 'POST', path: 'auth/login', remote: `2001:db8::${n.toString(16)}`, body: { password: 'wrong' } })
      assert.equal(r.status, 403, `attempt ${n}`)
    }
    assert.equal(Object.keys(store.state.lockouts).length, before, 'no lockout rows may be created for refused IPv6 clients')
  })
})

test('L-02 end to end: an IPv4 client is still locked out after maxAttempts', async () => {
  await withApi({ ipLimitEnabled: true }, async ({ handler, store }) => {
    const max = store.cfg.lockout.maxAttempts
    const statuses = []
    for (let n = 0; n < max + 2; n++) statuses.push((await call(handler, { method: 'POST', path: 'auth/login', remote: '203.0.113.9', body: { password: 'wrong' } })).status)
    assert.deepEqual(statuses, [...Array(max).fill(401), 429, 429])
    const other = await call(handler, { method: 'POST', path: 'auth/login', remote: '203.0.113.10', body: { password: 'wrong' } })
    assert.equal(other.status, 401, 'a different IPv4 address has its own bucket')
  })
})

test('L-02: the persisted lockout table is bounded and never evicts a live lock first', async () => {
  await withApi({ ipLimitEnabled: true }, async ({ store }) => {
    const victim = '198.51.100.1'
    const locked = store.getLockout(victim)
    for (let n = 0; n < store.cfg.lockout.maxAttempts; n++) recordFailedAttempt(locked, victim, store.cfg.lockout)
    assert.ok(locked.lockedUntil > Date.now())
    for (let n = 0; n < 5000; n++) {
      const row = store.getLockout(`10.${(n >> 16) & 255}.${(n >> 8) & 255}.${n & 255}`)
      recordFailedAttempt(row, 'x', store.cfg.lockout)
    }
    const size = Object.keys(store.state.lockouts).length
    assert.ok(size <= 2048, `lockout table grew to ${size}`)
    assert.ok(store.getLockout(victim).lockedUntil > Date.now(), 'an active lock must survive eviction pressure')
  })
})

test('L-02: __proto__ / constructor are not lockout keys that alias inherited objects', async () => {
  await withApi({ ipLimitEnabled: true }, async ({ store }) => {
    const row = store.getLockout('__proto__')
    assert.equal(Object.getPrototypeOf(row), Object.prototype)
    assert.notEqual(row, Object.prototype)
    assert.equal(row.attempts, 0)
  })
})
