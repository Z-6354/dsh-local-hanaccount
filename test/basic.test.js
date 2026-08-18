import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { _internals } from '../src/index.js'

test('ordinary user workspace is forced under account root', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-'))
  try {
    const store = _internals.createStore({ dataDir: dir, users: [{ username: 'u', password: 'p', role: 'user' }] })
    const user = store.findUser('u')
    const ws = store.createWorkspace(user, { name: 'Project A', path: '/tmp/evil' })
    assert.equal(ws.owner, 'u')
    assert.equal(ws.external, false)
    assert.ok(_internals.inside(ws.path, store.userWorkspaceRoot('u')))
    assert.ok(existsSync(ws.path))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('admin can add external workspace', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-'))
  const ext = mkdtempSync(join(tmpdir(), 'lha-ext-'))
  try {
    const store = _internals.createStore({ dataDir: dir, users: [{ username: 'a', password: 'p', role: 'admin' }] })
    const user = store.findUser('a')
    const ws = store.addExternalWorkspace(user, { path: ext })
    assert.equal(ws.owner, 'a')
    assert.equal(ws.external, true)
    assert.equal(ws.path, ext)
  } finally {
    rmSync(dir, { recursive: true, force: true })
    rmSync(ext, { recursive: true, force: true })
  }
})

test('sha256 password verification works', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-'))
  try {
    const hash = _internals.sha256('secret')
    const store = _internals.createStore({ dataDir: dir, users: [{ username: 'u', passwordSha256: hash, role: 'user' }] })
    const user = store.findUser('u')
    assert.equal(store.verifyPassword(user, 'secret'), true)
    assert.equal(store.verifyPassword(user, 'bad'), false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

function mockRegistry(initial = []) {
  const entities = new Map(initial.map((w) => [w.id, { ...w }]))
  return {
    list() {
      return [...entities.values()]
    },
    async create(path, title) {
      const real = resolve(path)
      for (const e of entities.values()) {
        if (resolve(e.path) === real) return e
      }
      const id = 'n_' + entities.size + '_' + Math.random().toString(16).slice(2, 8)
      const row = { id, path: real, title: title || 'ws' }
      entities.set(id, row)
      return row
    },
    async resolveByPath(path) {
      const real = resolve(path)
      for (const e of entities.values()) {
        if (resolve(e.path) === real) return e
      }
      return undefined
    },
    async delete(id) {
      return entities.delete(id)
    },
    _entities: entities,
  }
}

test('patched list uses ALS user, not state.currentUser', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-'))
  try {
    const store = _internals.createStore({
      dataDir: dir,
      users: [
        { username: 'a', password: 'p', role: 'user' },
        { username: 'b', password: 'p', role: 'user' },
      ],
    })
    const userA = store.findUser('a')
    const userB = store.findUser('b')
    const wsA = store.createWorkspace(userA, { name: 'wa' })
    const wsB = store.createWorkspace(userB, { name: 'wb' })
    store.issueSession(userB)
    assert.equal(store.activeUser()?.username, 'b')

    const registry = mockRegistry([
      { id: 'na', path: wsA.path, title: 'wa' },
      { id: 'nb', path: wsB.path, title: 'wb' },
    ])
    const unpatch = _internals.patchWorkspaceRegistry({ logger: { info() {} } }, registry, store)
    try {
      const listed = _internals.runWithUser(userA, () => registry.list())
      assert.equal(listed.length, 1)
      assert.equal(resolve(listed[0].path), resolve(wsA.path))
    } finally {
      unpatch()
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('patched list shows account-root paths even without plugin row', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-'))
  try {
    const store = _internals.createStore({
      dataDir: dir,
      users: [{ username: 'a', password: 'p', role: 'user' }],
    })
    const userA = store.findUser('a')
    const root = store.userWorkspaceRoot('a')
    const under = resolve(root, 'native-only')
    const registry = mockRegistry([
      { id: 'n1', path: under, title: 'native-only' },
      { id: 'nx', path: '/tmp/other-ws-y', title: 'x' },
    ])
    const unpatch = _internals.patchWorkspaceRegistry({ logger: { info() {} } }, registry, store)
    try {
      const listed = _internals.runWithUser(userA, () => registry.list())
      assert.equal(listed.length, 1)
      assert.equal(resolve(listed[0].path), under)
    } finally {
      unpatch()
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('patched list pass-through when ALS empty', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-'))
  try {
    const store = _internals.createStore({
      dataDir: dir,
      users: [{ username: 'a', password: 'p', role: 'user' }],
    })
    const userA = store.findUser('a')
    const wsA = store.createWorkspace(userA, { name: 'wa' })
    const registry = mockRegistry([
      { id: 'na', path: wsA.path, title: 'wa' },
      { id: 'nx', path: '/tmp/other-ws-x', title: 'x' },
    ])
    const original = registry.list()
    const unpatch = _internals.patchWorkspaceRegistry({ logger: { info() {} } }, registry, store)
    try {
      assert.equal(_internals.userFromAls(), null)
      const listed = registry.list()
      assert.equal(listed.length, original.length)
      assert.deepEqual(
        listed.map((w) => w.id).sort(),
        original.map((w) => w.id).sort(),
      )
    } finally {
      unpatch()
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('ensureNativeWorkspace sets nativeWorkspaceId via resolve then create', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-'))
  try {
    const store = _internals.createStore({
      dataDir: dir,
      users: [{ username: 'a', password: 'p', role: 'user' }],
    })
    const user = store.findUser('a')
    const ws = store.createWorkspace(user, { name: 'adopt-me' })
    assert.ok(!ws.nativeWorkspaceId)

    const registry = mockRegistry()
    const unpatch = _internals.patchWorkspaceRegistry({ logger: { info() {} } }, registry, store)
    try {
      await _internals.ensureNativeWorkspace(registry, store, user, ws)
      assert.ok(ws.nativeWorkspaceId)
      const again = store.listWorkspaces(user).find((w) => w.id === ws.id)
      assert.equal(again.nativeWorkspaceId, ws.nativeWorkspaceId)
      const resolved = await registry.resolveByPath(ws.path)
      assert.equal(String(resolved.id), String(ws.nativeWorkspaceId))
    } finally {
      unpatch()
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('deleteWorkspace returns record and API deletes native id', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-'))
  try {
    const store = _internals.createStore({
      dataDir: dir,
      users: [{ username: 'a', password: 'p', role: 'user' }],
    })
    const user = store.findUser('a')
    const ws = store.createWorkspace(user, { name: 'to-del' })
    const registry = mockRegistry()
    await _internals.ensureNativeWorkspace(registry, store, user, ws)
    const nativeId = ws.nativeWorkspaceId
    assert.ok(nativeId)
    assert.ok(registry._entities.has(nativeId))

    const removed = store.deleteWorkspace(user, ws.id)
    assert.ok(removed)
    assert.equal(removed.nativeWorkspaceId, nativeId)
    assert.equal(store.listWorkspaces(user).length, 0)

    // Simulate API delete sync path
    if (removed.nativeWorkspaceId && typeof registry.delete === 'function') {
      await registry.delete(removed.nativeWorkspaceId)
    }
    assert.equal(registry._entities.has(nativeId), false)
    assert.ok(existsSync(ws.path), 'disk directory must remain')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('patched create remaps path outside account root for role=user', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-'))
  try {
    const store = _internals.createStore({
      dataDir: dir,
      users: [{ username: 'u', password: 'p', role: 'user' }],
    })
    const user = store.findUser('u')
    const root = store.userWorkspaceRoot('u')
    const registry = mockRegistry()
    const unpatch = _internals.patchWorkspaceRegistry({ logger: { info() {} } }, registry, store)
    try {
      const native = await _internals.runWithUser(user, () => registry.create('/tmp/not-under-account', 'evil'))
      assert.ok(_internals.inside(native.path, root))
      assert.equal(resolve(native.path), resolve(root, 'not-under-account'))
    } finally {
      unpatch()
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('directory picker list is clamped to account root for role=user', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-'))
  try {
    const store = _internals.createStore({
      dataDir: dir,
      users: [{ username: 'u', password: 'p', role: 'user' }],
    })
    const user = store.findUser('u')
    const root = resolve(store.userWorkspaceRoot('u'))
    const listed = []
    const cap = {
      kind: 'browse',
      async list(path) {
        listed.push(path)
        return {
          path: resolve(path),
          home: '/home/ubuntu',
          crumbs: [
            { name: '/', path: '/' },
            { name: 'home', path: '/home' },
            { name: 'ubuntu', path: '/home/ubuntu' },
            { name: 'workspaces', path: root },
          ],
          entries: [{ name: 'peer', path: '/home/ubuntu/peer', isDirectory: true }],
          truncated: false,
        }
      },
      async createDirectory(path, name) {
        return join(path, name)
      },
    }
    const picker = { capability() { return cap } }
    const ctx = {
      get(name) { return name === 'directoryPicker' ? picker : undefined },
      logger: { info() {} },
    }
    const unpatch = _internals.patchDirectoryPicker(ctx, store)
    try {
      const out = await _internals.runWithUser(user, () => cap.list('/home/ubuntu'))
      assert.equal(out.home, root)
      assert.equal(out.path, root)
      assert.ok(listed.includes(root))
      assert.ok(out.crumbs.every((c) => _internals.inside(c.path, root)))
    } finally {
      unpatch()
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('sessionVisibleTo isolates sessions by owner cwd and sessionOwners', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-'))
  const adminDir = mkdtempSync(join(tmpdir(), 'lha-admin-ws-'))
  try {
    const store = _internals.createStore({
      dataDir: dir,
      users: [
        { username: 'admin', password: 'p', role: 'admin' },
        { username: 'u', password: 'p', role: 'user' },
      ],
    })
    const admin = store.findUser('admin')
    const user = store.findUser('u')
    const adminWs = store.addExternalWorkspace(admin, { path: adminDir })
    store.rememberSessionOwner(admin, 's-admin', adminWs.path)
    const userWs = store.createWorkspace(user, { name: 'mine' })
    store.rememberSessionOwner(user, 's-user', userWs.path)

    assert.equal(store.sessionVisibleTo(user, { id: 's-admin', header: { cwd: adminWs.path } }), false)
    assert.equal(store.sessionVisibleTo(user, { id: 's-user', header: { cwd: userWs.path } }), true)
    assert.equal(store.sessionVisibleTo(user, { sessionId: 's-user', cwd: '/tmp/other' }), true)
    assert.equal(store.sessionVisibleTo(admin, { id: 's-user', header: { cwd: userWs.path } }), false)
    assert.equal(store.sessionVisibleTo(admin, { id: 's-admin', cwd: adminWs.path }), true)
  } finally {
    rmSync(dir, { recursive: true, force: true })
    rmSync(adminDir, { recursive: true, force: true })
  }
})

test('reAdoptAll does not recreate workspaces whose directory was deleted', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-'))
  try {
    const store = _internals.createStore({
      dataDir: dir,
      users: [{ username: 'u', password: 'p', role: 'user' }],
    })
    const user = store.findUser('u')
    const ws = store.createWorkspace(user, { name: 'gone' })
    assert.ok(existsSync(ws.path))
    // 用户删掉了文件夹（文件系统层面），但 state.workspaces 记录还在。
    rmSync(ws.path, { recursive: true, force: true })
    assert.equal(existsSync(ws.path), false)

    let createCalls = 0
    const registry = {
      async resolveByPath() { return undefined },
      async create() { createCalls++ ; return { id: 'n_recreated' } },
    }

    _internals.reAdoptAll(store, registry)

    // 目录已被删除：不得重新 create（否则重启后文件夹“又加回来”）。
    assert.equal(createCalls, 0)
    assert.equal(existsSync(ws.path), false)
    // 失效记录应被清理，列表不再残留。
    assert.equal(store.listWorkspaces(user).length, 0)
    assert.equal(store.state.workspaces.some((w) => w.id === ws.id), false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('ensureNativeWorkspace skips workspaces whose directory was deleted', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lha-'))
  try {
    const store = _internals.createStore({
      dataDir: dir,
      users: [{ username: 'u', password: 'p', role: 'user' }],
    })
    const user = store.findUser('u')
    const ws = store.createWorkspace(user, { name: 'gone2' })
    rmSync(ws.path, { recursive: true, force: true })

    let createCalls = 0
    const registry = {
      async resolveByPath() { return undefined },
      async create() { createCalls++ ; return { id: 'n_recreated' } },
    }

    _internals.ensureNativeWorkspace(registry, store, user, ws)
    assert.equal(createCalls, 0)
    assert.equal(existsSync(ws.path), false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
