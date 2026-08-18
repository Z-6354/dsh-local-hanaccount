import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { AsyncLocalStorage } from 'node:async_hooks'
import { homedir } from 'node:os'
import { basename, dirname, isAbsolute, join, resolve, sep } from 'node:path'
import { randomBytes, timingSafeEqual, createHash } from 'node:crypto'

export const name = 'dsh-local-hanaccount'
export const inject = ['webServer', 'workspaceRegistry']

const COOKIE = 'dsh_lha_token'
const API_PREFIX = '/dsh-local-hanaccount/api'

const DEFAULTS = {
  enabled: true,
  rememberLogin: true,
  dataDir: '',
  users: [],
  sessionCookieDays: 180,
}

const authAls = new AsyncLocalStorage()
let loggedAlsEmptyOnce = false

function runWithUser(user, fn) {
  return authAls.run({ user, token: null }, fn)
}

function userFromAls() {
  return authAls.getStore()?.user ?? null
}

function logAlsEmptyOnce(ctx) {
  if (loggedAlsEmptyOnce) return
  loggedAlsEmptyOnce = true
  ctx?.logger?.info?.('[dsh-local-hanaccount] workspaceRegistry: no ALS user; pass-through original list/create/resolveByPath')
}

/** Browse target for non-admin: stay inside account root (outside → root). */
function accountBrowseTarget(store, user, path) {
  const root = resolve(store.userWorkspaceRoot(user.username))
  mkdirSync(root, { recursive: true })
  if (path === undefined || path === null || String(path).trim() === '') return root
  const target = resolve(String(path))
  return inside(target, root) ? target : root
}

/** Create remap for non-admin: outside picks become `<root>/<basename>`. */
function clampToAccountRoot(store, user, path) {
  const root = resolve(store.userWorkspaceRoot(user.username))
  mkdirSync(root, { recursive: true })
  if (path === undefined || path === null || String(path).trim() === '') return root
  const target = resolve(String(path))
  if (inside(target, root)) return target
  const leaf = basename(target)
  if (!leaf || leaf === '.' || leaf === '..') return root
  return resolve(root, leaf)
}

function dshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh')
}

function defaultDataDir() {
  return join(dshHome(), 'storages', 'dsh-local-hanaccount')
}

function nowIso() {
  return new Date().toISOString()
}

function id(prefix) {
  return `${prefix}_${randomBytes(12).toString('hex')}`
}

function sha256(s) {
  return createHash('sha256').update(String(s)).digest('hex')
}

function safeName(input) {
  const s = String(input ?? '').trim()
  if (!s) throw new Error('name required')
  if (s.length > 80) throw new Error('name too long')
  if (!/^[\w\-.\u4e00-\u9fff ]+$/.test(s)) throw new Error('name contains invalid characters')
  const cleaned = s.replace(/[\\/]+/g, '-').replace(/\s+/g, ' ').trim()
  if (!cleaned || cleaned === '.' || cleaned === '..') throw new Error('invalid name')
  return cleaned
}

function safeUserKey(username) {
  return encodeURIComponent(String(username)).replace(/%/g, '~')
}

function inside(child, parent) {
  const c = resolve(child)
  const p = resolve(parent)
  return c === p || c.startsWith(p.endsWith(sep) ? p : p + sep)
}

function readJson(file, fallback) {
  try {
    if (!existsSync(file)) return fallback
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    return fallback
  }
}

function writeJson(file, value) {
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(file, JSON.stringify(value, null, 2) + '\n', 'utf8')
}

function normalizeUsers(users) {
  const out = []
  const seen = new Set()
  for (const raw of Array.isArray(users) ? users : []) {
    const username = String(raw?.username ?? '').trim()
    if (!username || seen.has(username)) continue
    const role = raw?.role === 'admin' ? 'admin' : 'user'
    out.push({
      username,
      displayName: String(raw?.displayName ?? username),
      role,
      password: raw?.password == null ? '' : String(raw.password),
      passwordSha256: raw?.passwordSha256 == null ? '' : String(raw.passwordSha256),
    })
    seen.add(username)
  }
  return out
}

function publicUser(user) {
  if (!user) return null
  return { username: user.username, displayName: user.displayName || user.username, role: user.role }
}

function createStore(cfg) {
  const dataDir = resolve(cfg.dataDir || defaultDataDir())
  const stateFile = join(dataDir, 'state.json')
  const users = normalizeUsers(cfg.users)
  mkdirSync(dataDir, { recursive: true })
  const state = readJson(stateFile, { version: 1, sessions: {}, workspaces: [], sessionOwners: [] })
  if (!state.sessions || typeof state.sessions !== 'object') state.sessions = {}
  if (!Array.isArray(state.workspaces)) state.workspaces = []
  if (!Array.isArray(state.sessionOwners)) state.sessionOwners = []

  function save() {
    writeJson(stateFile, state)
  }

  function findUser(username) {
    return users.find((u) => u.username === username) || null
  }

  function verifyPassword(user, password) {
    const given = String(password ?? '')
    if (user.passwordSha256) return safeEqualHex(sha256(given), user.passwordSha256)
    return String(user.password ?? '') === given
  }

  function issueSession(user) {
    const token = randomBytes(32).toString('hex')
    state.sessions[token] = { username: user.username, role: user.role, createdAt: nowIso(), lastSeenAt: nowIso() }
    state.currentUser = user.username
    state.currentUserAt = nowIso()
    save()
    return token
  }

  function userFromToken(token) {
    const t = String(token || '')
    const s = state.sessions[t]
    if (!s) return null
    const user = findUser(s.username)
    if (!user) return null
    s.lastSeenAt = nowIso()
    return user
  }

  function logout(token) {
    const username = token && state.sessions[token]?.username
    if (token && state.sessions[token]) delete state.sessions[token]
    if (!username || state.currentUser === username) {
      state.currentUser = ''
      state.currentUserAt = nowIso()
    }
    save()
  }

  function userRoot(username) {
    return join(dataDir, 'users', safeUserKey(username))
  }

  function userWorkspaceRoot(username) {
    return join(userRoot(username), 'workspaces')
  }

  function ensureUserDirs(username) {
    mkdirSync(userWorkspaceRoot(username), { recursive: true })
  }

  function listWorkspaces(user) {
    ensureUserDirs(user.username)
    return state.workspaces.filter((w) => w.owner === user.username)
  }

  function activeUser() {
    return findUser(state.currentUser || '')
  }

  function userFromContext() {
    const fromAls = userFromAls()
    if (!fromAls) return null
    if (fromAls.username) return findUser(fromAls.username) || fromAls
    return findUser(String(fromAls))
  }

  function ownsPath(user, targetPath) {
    if (!user || !targetPath) return false
    const ws = listWorkspaces(user)
    return ws.some((w) => inside(targetPath, w.path))
  }

  function canUsePath(user, targetPath) {
    if (!user || !targetPath) return false
    if (user.role === 'admin') return true
    return inside(targetPath, userWorkspaceRoot(user.username))
  }

  function recordWorkspace(user, { name, path, external = false, nativeWorkspaceId = '' }) {
    const realPath = resolve(path)
    const existing = state.workspaces.find((w) => w.owner === user.username && resolve(w.path) === realPath)
    if (existing) {
      if (nativeWorkspaceId && existing.nativeWorkspaceId !== nativeWorkspaceId) {
        existing.nativeWorkspaceId = nativeWorkspaceId
      }
      existing.updatedAt = nowIso()
      save()
      return existing
    }
    const cleanName = name ? safeName(name) : safeName(basename(realPath) || 'workspace')
    const ws = { id: id('w'), owner: user.username, name: cleanName, title: cleanName, path: realPath, external: !!external, nativeWorkspaceId, createdBy: user.username, createdAt: nowIso(), updatedAt: nowIso() }
    state.workspaces.push(ws)
    save()
    return ws
  }

  function createWorkspace(user, body) {
    const name = safeName(body?.name)
    const requestedPath = String(body?.path ?? '').trim()
    const mode = body?.mode === 'external' || body?.external ? 'external' : 'account'
    let target
    let external = false

    if (user.role === 'admin' && requestedPath) {
      target = resolve(requestedPath)
      external = !inside(target, userWorkspaceRoot(user.username))
    } else {
      target = join(userWorkspaceRoot(user.username), name)
    }

    if (user.role !== 'admin') {
      const root = userWorkspaceRoot(user.username)
      target = join(root, name)
      if (!inside(target, root)) throw httpError(403, 'ordinary users can only create workspaces under their own account folder')
    }

    if (!isAbsolute(target)) throw httpError(400, 'workspace path must be absolute')
    if (mode === 'external' && user.role !== 'admin') throw httpError(403, 'external workspaces require admin role')

    mkdirSync(target, { recursive: true })
    const realPath = resolve(target)
    if (user.role !== 'admin' && !inside(realPath, userWorkspaceRoot(user.username))) {
      throw httpError(403, 'workspace path escapes account folder')
    }

    return recordWorkspace(user, { name, path: realPath, external })
  }

  function addExternalWorkspace(user, body) {
    if (user.role !== 'admin') throw httpError(403, 'external workspaces require admin role')
    const rawPath = String(body?.path ?? '').trim()
    if (!rawPath) throw httpError(400, 'path required')
    const target = resolve(rawPath)
    if (!existsSync(target)) throw httpError(404, 'path does not exist')
    const name = body?.name ? safeName(body.name) : safeName(basename(target) || 'workspace')
    return recordWorkspace(user, { name, path: target, external: true })
  }

  function deleteWorkspace(user, workspaceId) {
    const idx = state.workspaces.findIndex((w) => w.id === workspaceId && w.owner === user.username)
    if (idx < 0) return null
    const [removed] = state.workspaces.splice(idx, 1)
    save()
    return removed
  }

  function rememberSessionOwner(user, sessionId, workspacePath = '') {
    const sid = String(sessionId || '')
    if (!sid) return
    const existing = state.sessionOwners.find((x) => x.sessionId === sid)
    if (existing) {
      if (existing.owner !== user.username) return
      existing.workspacePath = workspacePath || existing.workspacePath || ''
      existing.updatedAt = nowIso()
    } else {
      state.sessionOwners.push({ sessionId: sid, owner: user.username, workspacePath, createdAt: nowIso(), updatedAt: nowIso() })
    }
    save()
  }

  function listSessionOwners(user) {
    return state.sessionOwners.filter((x) => x.owner === user.username)
  }

  /** Whether a session (attached entity or list/cold summary) is visible to this account. */
  function sessionVisibleTo(user, sessionLike) {
    if (!user || !sessionLike) return false
    const sid = String(sessionLike.id || sessionLike.sessionId || '')
    const cwd = String(
      sessionLike.header?.cwd
      || sessionLike.cwd
      || sessionLike.workspacePath
      || '',
    )
    if (sid && state.sessionOwners.some((x) => x.sessionId === sid && x.owner === user.username)) return true
    if (!cwd) return false
    const target = resolve(cwd)
    const root = resolve(userWorkspaceRoot(user.username))
    if (inside(target, root)) return true
    return listWorkspaces(user).some((w) => inside(target, w.path))
  }

  return {
    dataDir,
    users,
    state,
    findUser,
    verifyPassword,
    issueSession,
    userFromToken,
    logout,
    userWorkspaceRoot,
    listWorkspaces,
    createWorkspace,
    addExternalWorkspace,
    deleteWorkspace,
    rememberSessionOwner,
    listSessionOwners,
    sessionVisibleTo,
    activeUser,
    userFromContext,
    ownsPath,
    canUsePath,
    recordWorkspace,
  }
}

function safeEqualHex(a, b) {
  try {
    const aa = Buffer.from(String(a), 'hex')
    const bb = Buffer.from(String(b), 'hex')
    return aa.length === bb.length && timingSafeEqual(aa, bb)
  } catch {
    return false
  }
}

function httpError(status, message) {
  const e = new Error(message)
  e.status = status
  return e
}

function parseCookies(req) {
  const header = req.headers?.cookie || ''
  const out = {}
  for (const part of header.split(';')) {
    const i = part.indexOf('=')
    if (i < 0) continue
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim())
  }
  return out
}

async function readBody(req) {
  let body = ''
  for await (const chunk of req) body += chunk
  if (!body) return {}
  try { return JSON.parse(body) } catch { throw httpError(400, 'bad json') }
}

function sendJson(res, status, value, headers = {}) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers })
  res.end(JSON.stringify(value))
}

function setCookieHeader(token, cfg) {
  const maxAge = Math.max(1, Number(cfg.sessionCookieDays) || 180) * 24 * 60 * 60
  return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`
}

function clearCookieHeader() {
  return `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
}

function authUser(req, store) {
  const token = parseCookies(req)[COOKIE]
  const user = store.userFromToken(token)
  return { token, user }
}

export function createApiHandler({ cfg, store, workspaceRegistry }) {
  return async (req, res) => {
    const auth = authUser(req, store)
    return authAls.run({ user: auth.user, token: auth.token }, async () => {
      try {
        const url = new URL(req.url ?? '/', 'http://x')
        const sub = url.pathname.slice(API_PREFIX.length).replace(/^\/+/, '')

        if (req.method === 'GET' && sub === 'auth/me') {
          sendJson(res, 200, {
            authenticated: !!auth.user,
            user: publicUser(auth.user),
            configured: store.users.length > 0,
            dataDir: store.dataDir,
          })
          return
        }

        if (req.method === 'POST' && sub === 'auth/login') {
          const body = await readBody(req)
          const user = store.findUser(String(body.username ?? '').trim())
          if (!user || !store.verifyPassword(user, body.password)) {
            sendJson(res, 401, { error: 'invalid username or password' })
            return
          }
          const token = store.issueSession(user)
          sendJson(res, 200, { ok: true, user: publicUser(user) }, { 'set-cookie': setCookieHeader(token, cfg) })
          return
        }

        if (req.method === 'POST' && sub === 'auth/logout') {
          store.logout(auth.token)
          sendJson(res, 200, { ok: true }, { 'set-cookie': clearCookieHeader() })
          return
        }

        const user = auth.user
        if (!user) {
          sendJson(res, 401, { error: 'login required' })
          return
        }

        if (req.method === 'GET' && sub === 'workspaces') {
          sendJson(res, 200, {
            user: publicUser(user),
            accountWorkspaceRoot: store.userWorkspaceRoot(user.username),
            workspaces: store.listWorkspaces(user),
            sessionOwners: store.listSessionOwners(user),
          })
          return
        }

        if (req.method === 'POST' && sub === 'workspaces/create') {
          const ws = store.createWorkspace(user, await readBody(req))
          await ensureNativeWorkspace(workspaceRegistry, store, user, ws)
          sendJson(res, 200, { ok: true, workspace: ws })
          return
        }

        if (req.method === 'POST' && sub === 'workspaces/add-external') {
          const ws = store.addExternalWorkspace(user, await readBody(req))
          await ensureNativeWorkspace(workspaceRegistry, store, user, ws)
          sendJson(res, 200, { ok: true, workspace: ws })
          return
        }

        if (req.method === 'POST' && sub === 'sessions/claim') {
          const body = await readBody(req)
          store.rememberSessionOwner(user, body.sessionId, body.workspacePath || '')
          sendJson(res, 200, { ok: true })
          return
        }

        const m = sub.match(/^workspaces\/([^/]+)$/)
        if (req.method === 'DELETE' && m) {
          const removed = store.deleteWorkspace(user, decodeURIComponent(m[1]))
          if (!removed) {
            sendJson(res, 404, { error: 'workspace not found' })
            return
          }
          let nativeUnlinked = false
          if (removed.nativeWorkspaceId && typeof workspaceRegistry?.delete === 'function') {
            try {
              await workspaceRegistry.delete(removed.nativeWorkspaceId)
              nativeUnlinked = true
            } catch {
              // registry unlink is best-effort; plugin row is already gone
            }
          }
          sendJson(res, 200, { ok: true, nativeUnlinked, workspace: removed })
          return
        }

        sendJson(res, 404, { error: 'not found' })
      } catch (err) {
        sendJson(res, err?.status || 500, { error: String(err?.message || err) })
      }
    })
  }
}

async function ensureNativeWorkspace(workspaceRegistry, store, user, ws) {
  if (!workspaceRegistry) return
  // 目录已被用户删除：不再收养/重建（否则服务重启后 reAdoptAll 会把它重新 create 出来）。
  if (!existsSync(ws.path)) return
  return runWithUser(user, async () => {
    try {
      let native
      if (typeof workspaceRegistry.resolveByPath === 'function') {
        try {
          native = await workspaceRegistry.resolveByPath(ws.path)
        } catch {
          native = undefined
        }
      }
      if (!native && typeof workspaceRegistry.create === 'function') {
        native = await workspaceRegistry.create(ws.path, ws.title || ws.name)
      }
      const nativeId = native?.id ? String(native.id) : ''
      if (nativeId && ws.nativeWorkspaceId !== nativeId) {
        const updated = store.recordWorkspace(user, {
          name: ws.name,
          path: ws.path,
          external: ws.external,
          nativeWorkspaceId: nativeId,
        })
        ws.nativeWorkspaceId = updated.nativeWorkspaceId || nativeId
      }
    } catch {
      // The plugin record remains useful even if the native registry is temporarily unavailable.
    }
  })
}

async function reAdoptAll(store, workspaceRegistry) {
  if (!workspaceRegistry || !store?.users?.length) return
  for (const user of store.users) {
    const list = store.listWorkspaces(user)
    for (const ws of list) {
      // 目录已被用户删除：清掉残留记录，避免重启后列表/文件系统里“又加回来”。
      if (!existsSync(ws.path)) {
        store.deleteWorkspace(user, ws.id)
        continue
      }
      await ensureNativeWorkspace(workspaceRegistry, store, user, ws)
    }
  }
}

function wrapApiPrefixAuth(webServer, store) {
  const restored = []
  let stopped = false
  let timer = null

  function wrapHttp() {
    const route = webServer?.prefixes?.get?.('/api')
    if (!route || typeof route.handler !== 'function' || route.__dshLocalHanaccountApiWrapped) return !!route?.__dshLocalHanaccountApiWrapped
    const originalHandler = route.handler
    route.handler = function wrappedApiHandler(req, res) {
      const { user, token } = authUser(req, store)
      return authAls.run({ user, token }, () => originalHandler(req, res))
    }
    route.__dshLocalHanaccountApiWrapped = true
    restored.push(() => {
      route.handler = originalHandler
      delete route.__dshLocalHanaccountApiWrapped
    })
    return true
  }

  function wrapUpgrade(path) {
    const route = webServer?.upgrades?.get?.(path)
    if (!route || typeof route.handler !== 'function' || route.__dshLocalHanaccountApiWrapped) {
      return !!route?.__dshLocalHanaccountApiWrapped
    }
    const originalHandler = route.handler
    route.handler = function wrappedUpgradeHandler(req, socket, head) {
      const { user, token } = authUser(req, store)
      return authAls.run({ user, token }, () => originalHandler(req, socket, head))
    }
    route.__dshLocalHanaccountApiWrapped = true
    restored.push(() => {
      route.handler = originalHandler
      delete route.__dshLocalHanaccountApiWrapped
    })
    return true
  }

  function attachAll() {
    const httpOk = wrapHttp()
    const hostOk = wrapUpgrade('/api/events.host')
    const muxOk = wrapUpgrade('/api/events.mux')
    return httpOk && hostOk && muxOk
  }

  if (!attachAll()) {
    let tries = 0
    timer = setInterval(() => {
      if (stopped) return
      if (attachAll() || ++tries >= 50) {
        clearInterval(timer)
        timer = null
      }
    }, 100)
  }

  return () => {
    stopped = true
    if (timer) clearInterval(timer)
    for (const undo of restored.splice(0)) {
      try { undo() } catch {}
    }
  }
}

function patchWorkspaceRegistry(ctx, workspaceRegistry, store) {
  if (!workspaceRegistry || workspaceRegistry.__dshLocalHanaccountPatched) return () => {}
  const original = {
    list: workspaceRegistry.list?.bind(workspaceRegistry),
    create: workspaceRegistry.create?.bind(workspaceRegistry),
    resolveByPath: workspaceRegistry.resolveByPath?.bind(workspaceRegistry),
  }
  workspaceRegistry.__dshLocalHanaccountPatched = true

  if (original.list) {
    workspaceRegistry.list = function patchedList(...args) {
      const all = original.list(...args)
      const user = store.userFromContext()
      if (!user) {
        logAlsEmptyOnce(ctx)
        return all
      }
      // Only this account's root + its recorded rows (admin externals). Never other accounts.
      const root = resolve(store.userWorkspaceRoot(user.username))
      const allowed = store.listWorkspaces(user).map((w) => resolve(w.path))
      return all.filter((w) => {
        const p = resolve(w.path)
        if (p === root || inside(p, root)) return true
        return allowed.some((a) => p === a || inside(p, a))
      })
    }
  }

  if (original.create) {
    workspaceRegistry.create = async function patchedCreate(path, title, ...rest) {
      const user = store.userFromContext()
      if (!user) {
        logAlsEmptyOnce(ctx)
        return original.create(path, title, ...rest)
      }
      let target = resolve(String(path || ''))
      if (user.role !== 'admin') {
        // Ordinary users: always land under account root (remap outside picks).
        target = clampToAccountRoot(store, user, target)
        mkdirSync(target, { recursive: true })
      } else if (!store.canUsePath(user, target)) {
        throw httpError(403, 'workspace path is outside current account')
      }
      const native = await original.create(target, title, ...rest)
      store.recordWorkspace(user, {
        name: title || basename(target) || 'workspace',
        path: native?.path || target,
        external: !inside(native?.path || target, store.userWorkspaceRoot(user.username)),
        nativeWorkspaceId: native?.id ? String(native.id) : '',
      })
      return native
    }
  }

  if (original.resolveByPath) {
    workspaceRegistry.resolveByPath = async function patchedResolveByPath(path, ...rest) {
      const user = store.userFromContext()
      if (!user) {
        logAlsEmptyOnce(ctx)
        return original.resolveByPath(path, ...rest)
      }
      const target = resolve(String(path || ''))
      if (!store.canUsePath(user, target) && !store.ownsPath(user, target)) return undefined
      const ws = await original.resolveByPath(target, ...rest)
      if (!ws) return undefined
      return store.ownsPath(user, ws.path) || store.canUsePath(user, ws.path) ? ws : undefined
    }
  }

  ctx?.logger?.info?.('[dsh-local-hanaccount] workspaceRegistry patched: native workspace list/create are account-scoped via ALS')
  return () => {
    if (original.list) workspaceRegistry.list = original.list
    if (original.create) workspaceRegistry.create = original.create
    if (original.resolveByPath) workspaceRegistry.resolveByPath = original.resolveByPath
    delete workspaceRegistry.__dshLocalHanaccountPatched
  }
}

/**
 * Scope the in-app directory browser so non-admin users only see/create under
 * their account workspace root (home crumb rewritten to that root).
 */
function patchDirectoryPicker(ctx, store) {
  const restored = []
  let stopped = false
  let timer = null

  function attach() {
    const picker = ctx.get?.('directoryPicker')
    if (!picker || picker.__dshLocalHanaccountPatched) return !!picker?.__dshLocalHanaccountPatched
    const cap = picker.capability?.()
    if (!cap || cap.kind !== 'browse' || typeof cap.list !== 'function') return false

    const origList = cap.list.bind(cap)
    const origCreate = typeof cap.createDirectory === 'function' ? cap.createDirectory.bind(cap) : null

    cap.list = async function scopedList(path, signal) {
      const user = store.userFromContext()
      if (!user || user.role === 'admin') return origList(path, signal)
      const root = resolve(store.userWorkspaceRoot(user.username))
      mkdirSync(root, { recursive: true })
      const target = accountBrowseTarget(store, user, path)
      const listing = await origList(target, signal)
      const crumbs = (listing.crumbs || []).filter((c) => inside(c.path, root))
      if (!crumbs.some((c) => resolve(c.path) === root)) {
        crumbs.unshift({ name: basename(root) || root, path: root })
      }
      return {
        ...listing,
        home: root,
        path: inside(listing.path, root) ? listing.path : root,
        crumbs,
        entries: listing.entries || [],
      }
    }

    if (origCreate) {
      cap.createDirectory = async function scopedCreateDirectory(path, name) {
        const user = store.userFromContext()
        if (!user || user.role === 'admin') return origCreate(path, name)
        const root = resolve(store.userWorkspaceRoot(user.username))
        mkdirSync(root, { recursive: true })
        const parent = accountBrowseTarget(store, user, path)
        if (!inside(parent, root)) {
          const err = new Error(`cannot create under "${parent}": outside account workspace root ${root}`)
          err.code = 'directory-create-failed'
          err.path = parent
          throw err
        }
        return origCreate(parent, name)
      }
    }

    picker.__dshLocalHanaccountPatched = true
    restored.push(() => {
      cap.list = origList
      if (origCreate) cap.createDirectory = origCreate
      delete picker.__dshLocalHanaccountPatched
    })
    ctx?.logger?.info?.('[dsh-local-hanaccount] directoryPicker browse scoped to account workspace root for non-admin users')
    return true
  }

  if (!attach()) {
    let tries = 0
    timer = setInterval(() => {
      if (stopped) return
      if (attach() || ++tries >= 50) {
        clearInterval(timer)
        timer = null
      }
    }, 100)
  }

  return () => {
    stopped = true
    if (timer) clearInterval(timer)
    for (const undo of restored.splice(0)) {
      try { undo() } catch {}
    }
  }
}

/**
 * Filter attached + cold session listings so other accounts' sessions do not
 * leak into session.list (which the sidebar would otherwise show under 未分组
 * once the owning workspace row is hidden).
 */
function patchSessionListing(ctx, store) {
  const restored = []
  let stopped = false
  let timer = null

  function attach() {
    const sessions = ctx.get?.('sessions')
    const persistence = ctx.get?.('sessionPersistence')
    let did = false

    if (sessions && typeof sessions.list === 'function' && !sessions.__dshLocalHanaccountPatched) {
      const originalList = sessions.list.bind(sessions)
      sessions.list = function patchedSessionsList(...args) {
        const all = originalList(...args)
        const user = store.userFromContext()
        if (!user) {
          logAlsEmptyOnce(ctx)
          return all
        }
        return all.filter((s) => store.sessionVisibleTo(user, s))
      }
      sessions.__dshLocalHanaccountPatched = true
      restored.push(() => {
        sessions.list = originalList
        delete sessions.__dshLocalHanaccountPatched
      })
      did = true
    }

    if (persistence && typeof persistence.list === 'function' && !persistence.__dshLocalHanaccountPatched) {
      const originalList = persistence.list.bind(persistence)
      persistence.list = async function patchedPersistenceList(...args) {
        const all = await originalList(...args)
        const user = store.userFromContext()
        if (!user) {
          logAlsEmptyOnce(ctx)
          return all
        }
        return (all || []).filter((meta) => store.sessionVisibleTo(user, meta))
      }
      persistence.__dshLocalHanaccountPatched = true
      restored.push(() => {
        persistence.list = originalList
        delete persistence.__dshLocalHanaccountPatched
      })
      did = true
    }

    if (did) {
      ctx?.logger?.info?.('[dsh-local-hanaccount] sessions.list / sessionPersistence.list scoped per account via ALS')
    }
    // Prefer both when present; accept sessions-only if persistence mounts later.
    return !!(sessions?.__dshLocalHanaccountPatched)
  }

  if (!attach()) {
    let tries = 0
    timer = setInterval(() => {
      if (stopped) return
      if (attach() || ++tries >= 50) {
        clearInterval(timer)
        timer = null
      }
    }, 100)
  }

  return () => {
    stopped = true
    if (timer) clearInterval(timer)
    for (const undo of restored.splice(0)) {
      try { undo() } catch {}
    }
  }
}

export async function apply(ctx, config = {}) {
  const cfg = { ...DEFAULTS, ...config }
  if (cfg.enabled === false) return
  const webServer = ctx.get('webServer')
  const workspaceRegistry = ctx.get('workspaceRegistry')
  if (!webServer) {
    ctx.logger?.warn?.('[dsh-local-hanaccount] webServer unavailable; not mounting')
    return
  }
  const store = createStore(cfg)
  const unpatchApi = wrapApiPrefixAuth(webServer, store)
  const unpatchRegistry = workspaceRegistry
    ? patchWorkspaceRegistry(ctx, workspaceRegistry, store)
    : () => {}
  const unpatchPicker = patchDirectoryPicker(ctx, store)
  const unpatchSessions = patchSessionListing(ctx, store)
  const disposer = webServer.register({
    kind: 'prefix',
    path: API_PREFIX,
    handler: createApiHandler({ cfg, store, workspaceRegistry }),
  })

  await reAdoptAll(store, workspaceRegistry)

  // Prefer ALS identity on create; fall back to cwd→workspace owner matching.
  ctx.on?.('session/created', (session) => {
    try {
      const cwd = session?.header?.cwd || session?.header?.request?.cwd || ''
      const alsUser = store.userFromContext()
      if (alsUser) {
        store.rememberSessionOwner(alsUser, String(session.id), cwd)
        return
      }
      if (!cwd) return
      const ws = store.users
        .flatMap((u) => store.listWorkspaces(u))
        .find((w) => inside(cwd, w.path))
      if (!ws) return
      const user = store.findUser(ws.owner)
      if (user) store.rememberSessionOwner(user, String(session.id), cwd)
    } catch {}
  })

  ctx.provide?.('dshLocalHanaccount', {
    dataDir: store.dataDir,
    users: () => store.users.map(publicUser),
  })

  ctx.on('dispose', () => {
    try { disposer() } catch {}
    try { unpatchRegistry() } catch {}
    try { unpatchPicker() } catch {}
    try { unpatchSessions() } catch {}
    try { unpatchApi() } catch {}
  })
}

export const _internals = {
  createStore,
  safeName,
  inside,
  sha256,
  API_PREFIX,
  COOKIE,
  authAls,
  runWithUser,
  userFromAls,
  clampToAccountRoot,
  accountBrowseTarget,
  patchWorkspaceRegistry,
  patchDirectoryPicker,
  patchSessionListing,
  ensureNativeWorkspace,
  wrapApiPrefixAuth,
  reAdoptAll,
  createApiHandler,
}
