/**
 * Attack simulation — gate-level (offline) + optional live probe against running DSH.
 *
 * Live: set DSH_ATTACK_TARGET=http://127.0.0.1:3080 (default when reachable).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { createStore } from '../src/lib/store.js'
import { createGate, wrapWebServer } from '../src/gate.js'
import { hashPassword } from '../src/lib/password.js'
import { resolveClientIp } from '../src/lib/ip.js'

function mockRes() {
  let statusCode = 0
  let body = ''
  const headers = {}
  return {
    statusCode,
    body,
    headers,
    writeHead(code, hdrs) {
      statusCode = code
      this.statusCode = code
      if (hdrs) Object.assign(headers, hdrs)
    },
    setHeader(k, v) { headers[k.toLowerCase()] = v },
    end(text) { body = text ?? ''; this.body = body },
  }
}

function mockReq({ url = '/api/foo', remote = '127.0.0.1', headers = {} } = {}) {
  return {
    url,
    socket: { remoteAddress: remote },
    headers,
  }
}

function runIpGate(store, req) {
  const gate = createGate(store)
  const res = mockRes()
  const blocked = gate.checkIpGate(req, res)
  return { gate, res, blocked }
}

function runHttpGate(store, req) {
  const gate = createGate(store)
  let hit = false
  const inner = gate.wrapHttpHandler(() => { hit = true })
  const res = mockRes()
  inner(req, res)
  return { res, hit }
}

test('attack: non-whitelisted IP gets 403 (ip_blocked)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-atk-'))
  try {
    const store = createStore({ dataDir: dir, allow: ['127.0.0.1'], ipLimitEnabled: true })
    const req = mockReq({ remote: '203.0.113.50' })
    const { res, blocked } = runIpGate(store, req)
    assert.equal(blocked, true)
    assert.equal(res.statusCode, 403)
    assert.match(res.body, /Forbidden/)
    const visitors = store.visitors.listVisitors()
    assert.ok(visitors.some((v) => v.ip === '203.0.113.50' && v.lastReason === 'ip_blocked'))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('attack: blacklisted IP gets 403 (ip_blacklisted)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-atk-'))
  try {
    const store = createStore({
      dataDir: dir,
      allow: ['127.0.0.1'],
      deny: ['198.51.100.77'],
      ipLimitEnabled: true,
    })
    const req = mockReq({ remote: '198.51.100.77' })
    const { res, blocked } = runIpGate(store, req)
    assert.equal(blocked, true)
    assert.equal(res.statusCode, 403)
    const stats = store.visitors.getStats()
    assert.ok(stats.totalBlacklistedHits >= 1)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('attack: unauthenticated external IP gets 401 and is recorded', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-atk-'))
  try {
    const store = createStore({ dataDir: dir, ipLimitEnabled: false })
    store.setPasswordHash(hashPassword('test-password-123'))
    const req = mockReq({ url: '/api/events.host', remote: '203.0.113.50' })
    const { res, hit } = runHttpGate(store, req)
    assert.equal(hit, false)
    assert.equal(res.statusCode, 401)
    const row = store.visitors.listVisitors().find((v) => v.ip === '203.0.113.50')
    assert.ok(row)
    assert.ok(row.reasons.unauthenticated >= 1)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('attack: X-Real-IP spoof ignored on direct (non-proxy) connection', () => {
  const req = mockReq({
    remote: '203.0.113.9',
    headers: { 'x-real-ip': '127.0.0.1' },
  })
  assert.equal(resolveClientIp(req, { trustProxy: true }), '203.0.113.9')
})

test('attack: X-Real-IP honored only from trusted proxy (127.0.0.1)', () => {
  const req = mockReq({
    remote: '127.0.0.1',
    headers: { 'x-real-ip': '203.0.113.55' },
  })
  assert.equal(resolveClientIp(req, { trustProxy: true }), '203.0.113.55')
  const dir = mkdtempSync(join(tmpdir(), 'lha-atk-'))
  try {
    const store = createStore({ dataDir: dir, allow: ['127.0.0.1'], ipLimitEnabled: true })
    const { res, blocked } = runIpGate(store, req)
    assert.equal(blocked, true)
    assert.equal(res.statusCode, 403)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('attack: nginx misconfig blocks API with 503', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-atk-'))
  try {
    const store = createStore({ dataDir: dir })
    const gate = createGate(store)
    const req = mockReq({
      url: '/api/foo',
      remote: '127.0.0.1',
      headers: { host: 'dsh.example.com' },
    })
    const res = mockRes()
    assert.equal(gate.checkNginxGate(req, res), true)
    assert.equal(res.statusCode, 503)
    assert.match(res.body, /nginx_missing_x_real_ip/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('attack: websocket upgrade destroyed for blocked IP', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-atk-'))
  try {
    const store = createStore({ dataDir: dir, allow: ['127.0.0.1'], ipLimitEnabled: true })
    const gate = createGate(store)
    let destroyed = false
    const req = mockReq({ url: '/api/events.host', remote: '203.0.113.60' })
    gate.wrapUpgradeHandler(() => { throw new Error('should not reach handler') })(req, { destroy() { destroyed = true } }, Buffer.alloc(0))
    assert.equal(destroyed, true)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('attack: wrapWebServer protects dynamically registered routes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-atk-'))
  try {
    const store = createStore({ dataDir: dir, allow: ['127.0.0.1'], ipLimitEnabled: true })
    store.setPasswordHash(hashPassword('test-password-123'))
    const gate = createGate(store)
    const webServer = {
      prefixes: new Map([
        ['/api', { handler() {} }],
      ]),
      exact: new Map(),
      upgrades: new Map([
        ['/api/events.host', { handler() {} }],
      ]),
    }
    const unpatch = wrapWebServer(webServer, gate, store)
    const req = mockReq({ url: '/api/secret', remote: '203.0.113.61' })
    const res = mockRes()
    webServer.prefixes.get('/api').handler(req, res)
    assert.equal(res.statusCode, 403)
    unpatch()
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

const LIVE_DEFAULT = 'http://127.0.0.1:3080'
let liveTarget = process.env.DSH_ATTACK_TARGET || ''
let liveOk = false

test('live probe: detect running DSH', async (t) => {
  if (liveTarget) {
    liveOk = true
    return
  }
  try {
    const r = await fetch(`${LIVE_DEFAULT}/dsh-local-hanaccount/api/status`, { signal: AbortSignal.timeout(3000) })
    if (r.ok) {
      liveTarget = LIVE_DEFAULT
      liveOk = true
    }
  } catch {
    t.skip('DSH not reachable; set DSH_ATTACK_TARGET to run live attack probes')
  }
})

test('live: attacker IP blocked on protected API', async (t) => {
  if (!liveOk) t.skip()
  const attacker = '203.0.113.99'
  const r = await fetch(`${liveTarget}/api/events.host`, {
    headers: { 'X-Real-IP': attacker, 'User-Agent': 'lha-attack-sim/1.0' },
  })
  assert.equal(r.status, 403)
})

test('live: attacker IP blocked even on plugin status', async (t) => {
  if (!liveOk) t.skip()
  const attacker = '198.51.100.42'
  const r = await fetch(`${liveTarget}/dsh-local-hanaccount/api/status`, {
    headers: { 'X-Real-IP': attacker },
  })
  assert.equal(r.status, 403)
})

test('live: localhost unauthenticated gets 401 not 403', async (t) => {
  if (!liveOk) t.skip()
  const r = await fetch(`${liveTarget}/api/events.host`)
  assert.equal(r.status, 401)
  const body = await r.json()
  assert.equal(body.error, 'login required')
})

test('attack: IP limit blocks login endpoint for external IP', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-atk-'))
  try {
    const store = createStore({ dataDir: dir, allow: ['127.0.0.1'], ipLimitEnabled: true })
    const req = mockReq({ url: '/dsh-local-hanaccount/api/auth/login', remote: '203.0.113.88' })
    const { res, blocked } = runIpGate(store, req)
    assert.equal(blocked, true)
    assert.equal(res.statusCode, 403)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('live: wrong password from localhost returns 401', async (t) => {
  if (!liveOk) t.skip()
  const r = await fetch(`${liveTarget}/dsh-local-hanaccount/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'definitely-wrong-password-xyz' }),
  })
  assert.equal(r.status, 401)
  const body = await r.json()
  assert.equal(body.error, 'invalid password')
})

test('live: attacker IP blocked before login (403 not 401)', async (t) => {
  if (!liveOk) t.skip()
  const r = await fetch(`${liveTarget}/dsh-local-hanaccount/api/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Real-IP': '203.0.113.88',
    },
    body: JSON.stringify({ password: 'wrong' }),
  })
  assert.equal(r.status, 403)
})

test('live: direct XFF spoof from attacker remote cannot bypass (offline verify)', () => {
  const req = mockReq({
    remote: '203.0.113.88',
    headers: { 'x-forwarded-for': '127.0.0.1' },
  })
  assert.equal(resolveClientIp(req, { trustProxy: true }), '203.0.113.88')
})
