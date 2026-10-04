import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { createStore } from '../src/lib/store.js'
import { evaluateIpAccess, ipInList, ipMatchesEntry, resolveClientIp, detectNginxMisconfig, requestHost, applyIpListChange, isValidIpOrCidr, normalizeIpEntry, isLoopbackIp } from '../src/lib/ip.js'
import { writeJson } from '../src/lib/util.js'
import { getPasskeyContext, passkeyStatus } from '../src/lib/passkey-context.js'
import { hashPassword, verifyPassword, checkLockout, recordFailedAttempt } from '../src/lib/password.js'
import { createVisitorsStore } from '../src/lib/visitors.js'
import { createGate, wrapWebServer } from '../src/gate.js'
import { isAuthExcluded, shouldWrapPrefix } from '../src/lib/route-policy.js'
import { createTokenStore } from '../src/lib/tokens.js'
import { createPeersStore } from '../src/lib/peers.js'
import { installOutboundFetch } from '../src/lib/outbound-fetch.js'

test('password hash and verify', () => {
  const hash = hashPassword('secret-pass')
  assert.ok(hash.startsWith('$scrypt$'))
  assert.equal(verifyPassword('secret-pass', hash), true)
  assert.equal(verifyPassword('wrong', hash), false)
})

test('ip whitelist and blacklist evaluation', () => {
  const cfg = { ipLimitEnabled: true, allow: ['127.0.0.1'], deny: ['10.0.0.1'] }
  assert.equal(evaluateIpAccess('10.0.0.1', cfg).action, 'block')
  assert.equal(evaluateIpAccess('10.0.0.1', cfg).reason, 'ip_blacklisted')
  assert.equal(evaluateIpAccess('127.0.0.1', cfg).action, 'pass')
  assert.equal(evaluateIpAccess('203.0.113.50', cfg).action, 'block')
  assert.equal(evaluateIpAccess('203.0.113.50', { ...cfg, ipLimitEnabled: false }).action, 'pass')
})

test('cidr matching', () => {
  assert.equal(ipMatchesEntry('192.168.1.10', '192.168.1.0/24'), true)
  assert.equal(ipMatchesEntry('192.168.2.10', '192.168.1.0/24'), false)
  assert.ok(ipInList('192.168.1.5', ['192.168.0.0/16']))
})

test('ip list validation and mutual exclusion', () => {
  assert.equal(isValidIpOrCidr('203.0.113.10'), true)
  assert.equal(isValidIpOrCidr('192.168.1.0/24'), true)
  assert.equal(isValidIpOrCidr('not-an-ip'), false)
  assert.equal(isValidIpOrCidr('192.168.1.0/33'), false)
  assert.equal(normalizeIpEntry('::ffff:203.0.113.10'), '203.0.113.10')

  const cfg = { allow: ['127.0.0.1'], deny: [] }
  const toDeny = applyIpListChange(cfg, { listKey: 'deny', entry: '127.0.0.1' })
  assert.equal(toDeny.error, 'loopback')

  const toAllow = applyIpListChange({ allow: [], deny: ['10.0.0.1'] }, { listKey: 'allow', entry: '10.0.0.1' })
  assert.deepEqual(toAllow.allow, ['10.0.0.1'])
  assert.deepEqual(toAllow.deny, [])
})

test('cannot deny-list loopback addresses', () => {
  const cfg = { allow: ['127.0.0.1'], deny: [] }
  const r = applyIpListChange(cfg, { listKey: 'deny', entry: '127.0.0.1' })
  assert.equal(r.error, 'loopback')
  assert.deepEqual(r.deny, [])
})

test('store strips loopback from deny on load', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-v2-'))
  try {
    writeJson(join(dir, 'config.json'), {
      passwordHash: '',
      allow: ['127.0.0.1', '::1'],
      deny: ['127.0.0.1'],
      ipLimitEnabled: true,
      lockout: { maxAttempts: 5, lockMinutes: 30 },
      routePolicy: { mode: 'protect-all', excludePrefixes: [] },
    })
    const store = createStore({ dataDir: dir })
    assert.deepEqual(store.cfg.deny, [])
    assert.ok(store.cfg.allow.includes('127.0.0.1'))
    assert.ok(store.cfg.allow.includes('::1'))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('store enforces deny over allow on save', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-v2-'))
  try {
    const store = createStore({ dataDir: dir })
    store.updateConfig({ allow: ['1.2.3.4', '10.0.0.1'], deny: ['10.0.0.1'] })
    assert.deepEqual(store.cfg.allow, ['::1', '127.0.0.1', '1.2.3.4'])
    assert.deepEqual(store.cfg.deny, ['10.0.0.1'])
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('resolve client ip ignores forwarded headers on direct connection', () => {
  const req = {
    socket: { remoteAddress: '203.0.113.9' },
    headers: { 'x-real-ip': '127.0.0.1' },
  }
  assert.equal(resolveClientIp(req, { trustProxy: true }), '203.0.113.9')
  const proxied = {
    socket: { remoteAddress: '127.0.0.1' },
    headers: { 'x-real-ip': '203.0.113.9' },
  }
  assert.equal(resolveClientIp(proxied, { trustProxy: true }), '203.0.113.9')
})

test('visitors record blocked and login failures separately', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-v2-'))
  try {
    const visitors = createVisitorsStore(dir)
    visitors.record('1.2.3.4', 'ip_blocked')
    visitors.record('1.2.3.4', 'login_failed')
    const stats = visitors.getStats()
    assert.equal(stats.totalIllegalBlocked, 1)
    assert.equal(stats.totalLoginFailures, 1)
    assert.equal(visitors.listVisitors().length, 1)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('store persists config', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-v2-'))
  try {
    const store = createStore({ dataDir: dir })
    store.setPasswordHash(hashPassword('test-password'))
    store.updateConfig({ allow: ['127.0.0.1', '1.2.3.4'] })
    const again = createStore({ dataDir: dir })
    assert.ok(again.cfg.passwordHash)
    assert.equal(verifyPassword('test-password', again.cfg.passwordHash), true)
    assert.deepEqual(again.cfg.allow, ['::1', '127.0.0.1', '1.2.3.4'])
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('lockout after failed attempts', () => {
  const lockout = { attempts: 0, lockedUntil: 0 }
  const opts = { maxAttempts: 3, lockMinutes: 30 }
  recordFailedAttempt(lockout, '1.1.1.1', opts)
  recordFailedAttempt(lockout, '1.1.1.1', opts)
  const third = recordFailedAttempt(lockout, '1.1.1.1', opts)
  assert.equal(third.locked, true)
  const status = checkLockout(lockout, opts)
  assert.equal(status.locked, true)
})

test('gate blocks non-whitelisted ip on api path', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-v2-'))
  try {
    const store = createStore({ dataDir: dir, allow: ['127.0.0.1'] })
    const gate = createGate(store)
    let statusCode = 0
    const req = {
      url: '/api/foo',
      socket: { remoteAddress: '203.0.113.50' },
      headers: {},
    }
    const res = {
      writeHead(code) { statusCode = code },
      end() {},
    }
    const result = gate.checkIpGate(req, res)
    assert.equal(result, true)
    assert.equal(statusCode, 403)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('detect nginx misconfig when proxied without x-real-ip', () => {
  const req = {
    socket: { remoteAddress: '127.0.0.1' },
    headers: { host: 'dsh.example.com' },
  }
  const info = detectNginxMisconfig(req)
  assert.equal(info.misconfigured, true)
  assert.equal(info.code, 'nginx_missing_x_real_ip')
})

test('direct localhost access is not flagged as nginx misconfig', () => {
  const req = {
    socket: { remoteAddress: '127.0.0.1' },
    headers: { host: '127.0.0.1:3080' },
  }
  assert.equal(detectNginxMisconfig(req).misconfigured, false)
  assert.equal(requestHost(req), '127.0.0.1')
})

test('nginx proxy with x-real-ip is ok', () => {
  const req = {
    socket: { remoteAddress: '127.0.0.1' },
    headers: { host: 'dsh.example.com', 'x-real-ip': '203.0.113.50' },
  }
  assert.equal(detectNginxMisconfig(req).misconfigured, false)
  assert.equal(resolveClientIp(req, { trustProxy: true }), '203.0.113.50')
})

test('gate blocks api when nginx misconfigured', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-v2-'))
  try {
    const store = createStore({ dataDir: dir })
    const gate = createGate(store)
    let body = ''
    const req = {
      url: '/api/foo',
      socket: { remoteAddress: '127.0.0.1' },
      headers: { host: 'dsh.example.com' },
    }
    const res = {
      statusCode: 0,
      writeHead(code) { this.statusCode = code },
      end(text) { body = text },
    }
    assert.equal(gate.checkNginxGate(req, res), true)
    assert.equal(res.statusCode, 503)
    assert.match(body, /nginx_missing_x_real_ip/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('passkey available on https or localhost only', () => {
  assert.equal(getPasskeyContext({
    headers: { host: 'dsh.example.com', 'x-forwarded-proto': 'https' },
    socket: {},
  }).available, true)
  assert.equal(getPasskeyContext({
    headers: { host: '127.0.0.1:3080' },
    socket: {},
  }).available, true)
  assert.equal(getPasskeyContext({
    headers: { host: '192.168.1.10:3080' },
    socket: {},
  }).available, false)
  const status = passkeyStatus({ headers: { host: '192.168.1.10:3080' }, socket: {} })
  assert.equal(status.available, false)
  assert.ok(status.hint)
})

test('route policy excludes configured prefixes from auth skip', () => {
  const excludes = ['/pluginrepo']
  assert.equal(isAuthExcluded('/pluginrepo/api/packages', excludes), true)
  assert.equal(isAuthExcluded('/api/foo', excludes), false)
  assert.equal(shouldWrapPrefix('/pluginrepo', { mode: 'protect-all', excludePrefixes: excludes }), true)
  assert.equal(shouldWrapPrefix('/api', { mode: 'protect-all', excludePrefixes: excludes }), true)
})

test('bearer api token authenticates gate', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-v2-'))
  try {
    const store = createStore({ dataDir: dir, allow: ['203.0.113.50'] })
    const created = store.tokens.createApiToken('sync')
    const gate = createGate(store)
    let statusCode = 0
    const req = {
      url: '/api/foo',
      socket: { remoteAddress: '203.0.113.50' },
      headers: { authorization: `Bearer ${created.token}` },
    }
    const res = {
      writeHead(code) { statusCode = code },
      end() {},
      setHeader() {},
    }
    assert.equal(gate.isAuthenticated(req), true)
    const ipResult = gate.checkIpGate(req, res)
    assert.equal(ipResult.ip, '203.0.113.50')
    assert.equal(gate.wrapHttpHandler(() => { statusCode = 200 }) (req, res), undefined)
    assert.equal(statusCode, 200)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('wrapWebServer wraps all prefixes in protect-all mode', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-v2-'))
  try {
    const store = createStore({ dataDir: dir })
    const gate = createGate(store)
    const handlers = {
      api: () => {},
      pluginrepo: () => {},
    }
    const webServer = {
      fallback: undefined, prefixes: new Map([
        ['/api', { handler: handlers.api }],
        ['/pluginrepo', { handler: handlers.pluginrepo }],
      ]),
      upgrades: new Map(),
      exact: new Map(),
    }
    const unpatch = wrapWebServer(webServer, gate, store)
    assert.equal(typeof webServer.prefixes.get('/api').handler, 'function')
    assert.equal(webServer.prefixes.get('/api').__dshGateWrapped, true)
    assert.equal(webServer.prefixes.get('/pluginrepo').__dshGateWrapped, true)
    unpatch()
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('wrapWebServer wraps exact routes (dsh-host-webserver uses .exact)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-v2-'))
  try {
    const store = createStore({ dataDir: dir, allow: ['127.0.0.1'] })
    const gate = createGate(store)
    let originalCalled = false
    const webServer = {
      fallback: undefined, prefixes: new Map(),
      upgrades: new Map(),
      exact: new Map([
        ['/dsh-version-updater/status', {
          handler: () => { originalCalled = true },
        }],
      ]),
    }
    const unpatch = wrapWebServer(webServer, gate, store)
    const route = webServer.exact.get('/dsh-version-updater/status')
    assert.equal(route.__dshGateWrapped, true)

    let statusCode = 0
    const req = {
      url: '/dsh-version-updater/status',
      socket: { remoteAddress: '127.0.0.1' },
      headers: {},
    }
    const res = {
      writeHead(code) { statusCode = code },
      end() {},
      setHeader() {},
    }
    route.handler(req, res)
    assert.equal(statusCode, 401)
    assert.equal(originalCalled, false)
    unpatch()
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('outbound fetch injects peer bearer token', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-v2-'))
  try {
    const peers = createPeersStore(dir)
    peers.addOutboundPeer({
      name: 'VPS',
      baseUrl: 'https://vps.example.com',
      token: 'peer-secret-token',
    })
    const calls = []
    const original = async (url, init) => {
      calls.push({ url, init })
      return { ok: true }
    }
    globalThis.fetch = original
    const restore = installOutboundFetch(peers)
    await globalThis.fetch('https://vps.example.com/pluginrepo/api/packages')
    assert.equal(calls.length, 1)
    assert.match(String(calls[0].init.headers.get('authorization')), /Bearer peer-secret-token/)
    restore()
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('excluded prefix skips auth but keeps ip gate', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-v2-'))
  try {
    const store = createStore({
      dataDir: dir,
      allow: ['127.0.0.1'],
      routePolicy: { mode: 'protect-all', excludePrefixes: ['/pluginrepo'] },
    })
    const gate = createGate(store)
    let statusCode = 0
    const req = {
      url: '/pluginrepo/api/packages',
      socket: { remoteAddress: '203.0.113.50' },
      headers: {},
    }
    const res = {
      writeHead(code) { statusCode = code },
      end() {},
    }
    gate.wrapHttpHandler(() => { statusCode = 200 })(req, res)
    assert.equal(statusCode, 403)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('excluded prefix cannot bypass authentication', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-v2-'))
  try {
    const store = createStore({
      dataDir: dir,
      allow: ['203.0.113.50'],
      routePolicy: { mode: 'protect-all', excludePrefixes: ['/pluginrepo'] },
    })
    const gate = createGate(store)
    let statusCode = 0
    const req = {
      url: '/pluginrepo/api/packages',
      socket: { remoteAddress: '203.0.113.50' },
      headers: {},
    }
    const res = {
      writeHead(code) { statusCode = code },
      end() {},
    }
    gate.wrapHttpHandler(() => { statusCode = 200 })(req, res)
    assert.equal(statusCode, 401)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('peer pairing code can be claimed once', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-v2-'))
  try {
    const peers = createPeersStore(dir)
    const { code } = peers.createPairingCode()
    const first = peers.claimPairingCode({ code, peerName: 'Home', peerBaseUrl: 'https://home.test' })
    const second = peers.claimPairingCode({ code, peerName: 'Home', peerBaseUrl: 'https://home.test' })
    assert.equal(first.ok, true)
    assert.ok(first.token)
    assert.equal(second.ok, false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
