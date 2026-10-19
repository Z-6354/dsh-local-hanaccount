// Run against explicit installed rc2 code and a staged plugin; no production home or credentials.
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as httpRequest } from 'node:http'
import { connect } from 'node:net'
import { pathToFileURL } from 'node:url'
import { randomBytes } from 'node:crypto'
import * as Auth from '../src/index.js'
import { RC2_BUILD } from '../src/lib/dsh-adapter.js'
import { hashPassword } from '../src/lib/password.js'
const root = process.argv[2]
const auditedBuild = process.argv[3] || RC2_BUILD
assert.ok(root, 'explicit official rc2 package dependency root required')
const load = name => import(pathToFileURL(join(root, '@deepseek-ai', name, 'lib/index.js')).href)
const { Context } = await load('cordis')
const { default: WebServer } = await load('dsh-host-webserver')
const Connection = await load('dsh-client-connection')
const ctx = new Context(), dir = await mkdtemp(join(tmpdir(), 'rc2-auth-'))
let credential
ctx.provide('credentials', { async modifyRecord(_key, change) { const next = await change(credential); if (next !== undefined) credential = next; return credential } })
const password = randomBytes(20).toString('hex')
let authFiber
try {
  await ctx.plugin(WebServer, { host: '127.0.0.1', port: 0, compression: 'none' })
  await ctx.plugin(Connection, { trustedHosts: [], cookieMaxAgeDays: 1 })
  const server = ctx.webServer
  server.registerFallback((_req, res) => { res.writeHead(200); res.end('unsafe-official-fixture') })
  server.register({ kind: 'prefix', path: '/assets/', handler(_req, res) { res.writeHead(200); res.end('protected-asset') } })
  server.register({ kind: 'prefix', path: '/plugins/', handler(_req, res) { res.writeHead(200); res.end('protected-plugin') } })
  server.registerUpgrade({ path: '/assets/stream', handler(_req, socket) { socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: fixture\r\n\r\n') } })
  authFiber = await ctx.plugin(Auth, { officialBuild: auditedBuild, dataDir: dir, passwordHash: hashPassword(password), ipLimitEnabled: false })
  const port = server.port
  function request(path, cookie = '', method = 'GET', body) {
    return new Promise((resolve, reject) => {
      const req = httpRequest({ host: '127.0.0.1', port, path, method, headers: { host: 'localhost', cookie, ...(body ? { 'content-type': 'application/json' } : {}) } }, res => {
        let text = ''; res.on('data', data => { text += data }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: text }))
      }); req.on('error', reject); if (body) req.write(JSON.stringify(body)); req.end()
    })
  }
  async function upgrade(cookie) {
    return new Promise(resolve => {
      const socket = connect(port, '127.0.0.1'), timer = setTimeout(() => { socket.destroy(); resolve(false) }, 1000)
      socket.on('connect', () => socket.write(`GET /assets/stream HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: fixture\r\nCookie: ${cookie}\r\n\r\n`))
      socket.on('data', data => { clearTimeout(timer); socket.destroy(); resolve(data.toString().startsWith('HTTP/1.1 101')) })
      socket.on('close', () => { clearTimeout(timer); resolve(false) }); socket.on('error', () => { clearTimeout(timer); resolve(false) })
    })
  }
  const login = await request('/dsh-local-hanaccount/api/auth/login', '', 'POST', { password })
  assert.equal(login.status, 200)
  const cookies = login.headers['set-cookie'].map(value => value.split(';')[0])
  assert.equal(cookies.length, 2)
  const gate = cookies.find(value => value.startsWith('dsh_gate_token=')), native = cookies.find(value => value.startsWith('dsh-auth-'))
  for (const cookie of ['', gate, native, cookies.join('; ')]) {
    const both = cookie === cookies.join('; ')
    for (const path of ['/assets/test.js', '/plugins/test.js']) assert.equal((await request(path, cookie)).status, both ? 200 : 401)
    const me = JSON.parse((await request('/dsh-local-hanaccount/api/auth/me', cookie)).body)
    assert.equal(!!me.resumeScope, both)
    assert.equal(await upgrade(cookie), both)
  }
  const anonymous = await request('/')
  assert.notEqual(anonymous.body, 'unsafe-official-fixture')
  const status = JSON.parse((await request('/dsh-local-hanaccount/api/status')).body)
  assert.equal(status.security.ready, true); assert.equal(status.security.officialBuild, auditedBuild)
  const logout = await request('/dsh-local-hanaccount/api/auth/logout', cookies.join('; '), 'POST', {})
  assert.equal(logout.status, 200); assert.equal((await request('/assets/test.js', cookies.join('; '))).status, 401)
  await authFiber.dispose()
  assert.equal((await request('/assets/test.js', native)).status, 503)
  assert.equal((await request('/')).status, 503)
  console.log('PASS installed rc2 real Cordis/WebServer/Connection: dual-cookie HTTP/static/WS, scope, logout, dispose deny; no credentials emitted')
} finally { await ctx.fiber.dispose(); await rm(dir, { recursive: true, force: true }) }
