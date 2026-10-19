/**
 * Regression tests for the 2026-10-09 security audit. Every case drives the real entry point (API handler,
 * store, key-auth) rather than an isolated helper, and each one failed before its fix.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { generateKeyPairSync, sign } from 'node:crypto'
import { Readable } from 'node:stream'
import { createNativeBridge } from '../src/lib/native-bridge.js'
import { createStore } from '../src/lib/store.js'
import { hashPassword } from '../src/lib/password.js'
import { createGate } from '../src/gate.js'
import { createApiHandler } from '../src/api.js'
import { addPublicKey, keyId, loadAuthorizedKeys, parseAuthorizedKeys, saveAuthorizedKeys, verifyKeySignature } from '../src/lib/key-auth.js'

function owner() {
  return {
    requestRejection() { return undefined },
    authenticatedUrl() { return 'http://localhost/?token=internal-only' },
    authorizeIndex(req, res) { res.writeHead(303, { location: '/', 'set-cookie': 'dsh-auth-fixture=native; Path=/; HttpOnly' }); res.end(); return false },
  }
}

async function withApi(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'audit-test-'))
  const store = createStore({ dataDir: dir, ipLimitEnabled: false })
  store.setPasswordHash(hashPassword('correct-password'))
  const bridge = createNativeBridge(owner())
  const gate = createGate(store, bridge)
  try { return await fn({ store, bridge, gate, dir }) } finally { gate.dispose(); bridge.dispose(); rmSync(dir, { recursive: true, force: true }) }
}

// Body stream that stays open until released, so every request is parked at `await readOperationBody()` together.
function loginRequest(password, release) {
  const req = Readable.from((async function* () { await release; yield JSON.stringify({ password }) })())
  return Object.assign(req, {
    method: 'POST', url: '/dsh-local-hanaccount/api/auth/login',
    headers: { host: 'localhost', 'content-type': 'application/json' }, socket: { remoteAddress: '203.0.113.9' },
  })
}

test('lockout holds under a concurrent burst of wrong passwords (check happens after the body await)', async () => {
  await withApi(async ({ store, bridge, gate }) => {
    const handler = createApiHandler({ store, gate, bridge })
    let open; const release = new Promise((resolve) => { open = resolve })
    const maxAttempts = store.cfg.lockout.maxAttempts
    const burst = 20
    const outcomes = []
    const pending = Array.from({ length: burst }, () => {
      const status = {}
      return handler(loginRequest('wrong-password', release), { writeHead(s) { status.code = s }, end() {} }).then(() => outcomes.push(status.code))
    })
    open()
    await Promise.all(pending)
    const verified = outcomes.filter((code) => code === 401).length
    const limited = outcomes.filter((code) => code === 429).length
    assert.equal(verified, maxAttempts, `only ${maxAttempts} password checks may run, got ${verified} (limited=${limited})`)
    assert.equal(limited, burst - maxAttempts)
  })
})

test('lockout still blocks the correct password after the burst', async () => {
  await withApi(async ({ store, bridge, gate }) => {
    const handler = createApiHandler({ store, gate, bridge })
    let open; const release = new Promise((resolve) => { open = resolve })
    const wrong = Array.from({ length: 10 }, () => handler(loginRequest('nope', release), { writeHead() {}, end() {} }))
    open(); await Promise.all(wrong)
    const status = {}
    await handler(loginRequest('correct-password', Promise.resolve()), { writeHead(s) { status.code = s }, end() {} })
    assert.equal(status.code, 429)
  })
})

test('prototype-key session cookies are unknown sessions: no write, no security broadcast', async () => {
  await withApi(async ({ store, dir }) => {
    let broadcasts = 0
    const unsubscribe = store.onSecurityChange?.(() => { broadcasts++ })
    const stateFile = join(dir, 'state.json')
    const before = existsSync(stateFile)
    for (const token of ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf']) {
      assert.equal(store.sessionFromToken(token), null, token)
      assert.equal(store.resumeScope(token), undefined, token)
      store.logout(token)
    }
    assert.equal(existsSync(stateFile), before, 'an unauthenticated cookie must not create or rewrite state.json')
    assert.equal(broadcasts, 0)
    assert.equal(Object.getPrototypeOf(store.state.sessions), Object.prototype, 'logout must not touch the prototype')
    unsubscribe?.()
  })
})

test('a genuine session still resolves after the hasOwn change', async () => {
  await withApi(async ({ store }) => {
    const token = store.issueSession()
    assert.ok(store.sessionFromToken(token))
    store.logout(token)
    assert.equal(store.sessionFromToken(token), null)
  })
})

function sshLine(publicKey, comment = 'test') {
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)
  const type = Buffer.from('ssh-ed25519')
  const blob = Buffer.concat([Buffer.from([0, 0, 0, type.length]), type, Buffer.from([0, 0, 0, 32]), raw])
  return `ssh-ed25519 ${blob.toString('base64')} ${comment}`
}

test('ssh-ed25519 login: a valid signature verifies and a tampered one does not', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const keys = parseAuthorizedKeys(sshLine(publicKey))
  assert.equal(keys.length, 1)
  const nonce = 'a1b2c3'
  const signature = sign(null, Buffer.from(nonce), privateKey)
  assert.equal(verifyKeySignature(keys, nonce, signature)?.id, keys[0].id)
  assert.equal(verifyKeySignature(keys, nonce + 'x', signature), null, 'different message')
  const flipped = Buffer.from(signature); flipped[0] ^= 0xff
  assert.equal(verifyKeySignature(keys, nonce, flipped), null, 'tampered signature')
  const other = generateKeyPairSync('ed25519')
  assert.equal(verifyKeySignature(parseAuthorizedKeys(sshLine(other.publicKey)), nonce, signature), null, 'wrong key')
})

test('key ids are stable across reloads, so a key can actually be revoked', () => {
  const dir = mkdtempSync(join(tmpdir(), 'audit-keys-'))
  try {
    const file = join(dir, 'authorized_keys')
    const a = generateKeyPairSync('ed25519').publicKey
    const b = generateKeyPairSync('ed25519').publicKey
    saveAuthorizedKeys(file, addPublicKey(addPublicKey([], sshLine(a, 'a')), sshLine(b, 'b')))
    const first = loadAuthorizedKeys(file)
    const second = loadAuthorizedKeys(file)
    assert.deepEqual(first.map((k) => k.id), second.map((k) => k.id), 'ids must not change between loads')
    assert.equal(new Set(first.map((k) => k.id)).size, 2)
    assert.equal(first[0].id, keyId(first[0].key))
    // The exact flow of DELETE keys/:id: reload, filter by id, save.
    saveAuthorizedKeys(file, loadAuthorizedKeys(file).filter((k) => k.id !== first[0].id))
    const left = loadAuthorizedKeys(file)
    assert.equal(left.length, 1)
    assert.equal(left[0].id, first[1].id)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})
