import { mkdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { randomBytes, createHash } from 'node:crypto'
import { readJson, writeJson, nowIso, normalizeStringList, defaultDataDir } from './util.js'
import { normalizeRoutePolicy } from './route-policy.js'
import { createVisitorsStore } from './visitors.js'
import { createPasskeyStore } from './passkey-store.js'
import { createTokenStore } from './tokens.js'
import { createPeersStore } from './peers.js'
import { isValidIpOrCidr, normalizeIpEntry, LOOPBACK_ENTRIES, isLoopbackIp } from './ip.js'

function sanitizeIpList(list) {
  const out = []
  const seen = new Set()
  for (const raw of normalizeStringList(list)) {
    const entry = normalizeIpEntry(raw)
    if (!entry || !isValidIpOrCidr(entry) || seen.has(entry)) continue
    seen.add(entry)
    out.push(entry)
  }
  return out
}

function sanitizeDenyList(list) {
  return sanitizeIpList(list).filter((x) => !isLoopbackIp(x))
}

function ensureLoopbackAllow(allow, deny) {
  const denySet = new Set(deny)
  const out = allow.filter((x) => !denySet.has(x))
  for (const lb of LOOPBACK_ENTRIES) {
    if (!denySet.has(lb) && !out.includes(lb)) out.unshift(lb)
  }
  return out
}

export function createStore(initialConfig = {}, {onStorageFailure} = {}) {
  let active = true
  function assertActive() {
    if (!active) throw Object.assign(new Error('auth_unavailable'), {status:503, code:'auth_unavailable'})
  }
  function storageFailure() { active = false; onStorageFailure?.() }
  function guarded(method) { return (...args) => { assertActive(); return method(...args) } }
  function guardedStore(child) {
    return Object.fromEntries(Object.entries(child).map(([key,value]) => [key, typeof value === 'function' ? guarded(value) : value]))
  }
  const dataDir = resolve(initialConfig.dataDir || defaultDataDir())
  mkdirSync(dataDir, { recursive: true })
  const configFile = join(dataDir, 'config.json')
  const stateFile = join(dataDir, 'state.json')

  const defaults = {
    enabled: true,
    passwordHash: '',
    allow: ['127.0.0.1', '::1'],
    deny: [],
    ipLimitEnabled: true,
    trustProxy: true,
    nginxBasicAutoLogin: false,
    keyAuthEnabled: true,
    sessionMaxAgeDays: 7,
    lockout: { maxAttempts: 5, lockMinutes: 30 },
    routePolicy: { mode: 'protect-all', excludePrefixes: [] },
  }

  const saved = readJson(configFile, {})
  let cfg = { ...defaults, ...initialConfig, ...saved }
  cfg.allow = sanitizeIpList(cfg.allow)
  cfg.deny = sanitizeDenyList(cfg.deny)
  // Mutual exclusion: deny wins; loopback never stays in deny after sanitize.
  const denySet = new Set(cfg.deny)
  cfg.allow = ensureLoopbackAllow(cfg.allow.filter((x) => !denySet.has(x)), cfg.deny)
  cfg.routePolicy = normalizeRoutePolicy({ ...defaults.routePolicy, ...cfg.routePolicy, ...saved.routePolicy })

  const needsConfigRepair = (saved.deny || []).some((x) => isLoopbackIp(x))
    || (saved.allow || []).some((x) => sanitizeDenyList(saved.deny || []).includes(normalizeIpEntry(x)))

  let state = readJson(stateFile, { version: 2, sessions: {}, lockouts: {} })
  if (!state.sessions) state.sessions = {}
  if (!state.lockouts) state.lockouts = {}

  const visitors = guardedStore(createVisitorsStore(dataDir))
  const securityListeners = new Set()
  const securityChanged = () => { for (const listener of securityListeners) listener() }
  const passkeys = createPasskeyStore(dataDir, securityChanged, {assertActive,onStorageFailure:storageFailure})
  const tokens = createTokenStore(dataDir, securityChanged, {assertActive,onStorageFailure:storageFailure})
  const peers = createPeersStore(dataDir, securityChanged, {assertActive,onStorageFailure:storageFailure})
  const keysFile = join(dataDir, 'authorized_keys')

  function saveConfig() {
    assertActive()
    try { writeJson(configFile, {
      passwordHash: cfg.passwordHash,
      allow: cfg.allow,
      deny: cfg.deny,
      ipLimitEnabled: cfg.ipLimitEnabled,
      nginxBasicAutoLogin: cfg.nginxBasicAutoLogin,
      keyAuthEnabled: cfg.keyAuthEnabled,
      sessionMaxAgeDays: cfg.sessionMaxAgeDays,
      lockout: cfg.lockout,
      routePolicy: { ...cfg.routePolicy, excludePrefixes: [...cfg.routePolicy.excludePrefixes] },
    }) } catch { storageFailure(); throw Object.assign(new Error('storage_unavailable'), {status:503, code:'storage_unavailable'}) }
  }

  if (needsConfigRepair) saveConfig()

  function saveState() {
    assertActive()
    try { writeJson(stateFile, state) }
    catch { storageFailure(); throw Object.assign(new Error('storage_unavailable'), {status:503, code:'storage_unavailable'}) }
  }

  function publicConfig() {
    return {
      enabled: cfg.enabled,
      passwordConfigured: !!cfg.passwordHash,
      allow: [...cfg.allow],
      deny: [...cfg.deny],
      ipLimitEnabled: cfg.ipLimitEnabled,
      nginxBasicAutoLogin: cfg.nginxBasicAutoLogin,
      keyAuthEnabled: cfg.keyAuthEnabled,
      sessionMaxAgeDays: cfg.sessionMaxAgeDays,
      lockout: { ...cfg.lockout },
      routePolicy: { ...cfg.routePolicy, excludePrefixes: [...cfg.routePolicy.excludePrefixes] },
      dataDir,
    }
  }

  function updateConfig(patch) {
    if (patch.allow != null || patch.deny != null) {
      const nextAllow = patch.allow != null ? sanitizeIpList(patch.allow) : [...cfg.allow]
      const nextDeny = patch.deny != null ? sanitizeDenyList(patch.deny) : [...cfg.deny]
      const denySet = new Set(nextDeny)
      cfg.allow = ensureLoopbackAllow(nextAllow.filter((x) => !denySet.has(x)), nextDeny)
      cfg.deny = nextDeny
    }
    if (patch.ipLimitEnabled != null) cfg.ipLimitEnabled = !!patch.ipLimitEnabled
    if (patch.nginxBasicAutoLogin != null) cfg.nginxBasicAutoLogin = !!patch.nginxBasicAutoLogin
    if (patch.keyAuthEnabled != null) cfg.keyAuthEnabled = !!patch.keyAuthEnabled
    if (patch.sessionMaxAgeDays != null) cfg.sessionMaxAgeDays = Number(patch.sessionMaxAgeDays) || 7
    if (patch.lockout) cfg.lockout = { ...cfg.lockout, ...patch.lockout }
    if (patch.routePolicy) {
      cfg.routePolicy = normalizeRoutePolicy({ ...cfg.routePolicy, ...patch.routePolicy })
    }
    saveConfig()
    securityChanged()
  }

  function setPasswordHash(hash) {
    cfg.passwordHash = hash
    saveConfig()
    state.sessions = {}
    try { saveState() } finally { securityChanged() }
  }

  function authVersion() { return createHash('sha256').update(cfg.passwordHash).digest('hex') }

  function issueSession() {
    const token = randomBytes(32).toString('hex')
    state.sessions[token] = { createdAt: nowIso(), lastSeenAt: nowIso(), authVersion: authVersion() }
    saveState()
    return token
  }

  function sessionFromToken(token, { touch = true } = {}) {
    const t = String(token || '')
    const s = state.sessions[t]
    if (!s) return null
    const ttl = Math.max(1, Number(cfg.sessionMaxAgeDays) || 7) * 86400000
    const created = Date.parse(s.createdAt)
    const seen = Date.parse(s.lastSeenAt)
    if (s.authVersion !== authVersion() || !Number.isFinite(created) || !Number.isFinite(seen) || Date.now() - created >= ttl || Date.now() - seen >= ttl) {
      delete state.sessions[t]
      try { saveState() } finally { securityChanged() }
      return null
    }
    if (touch) s.lastSeenAt = nowIso()
    return s
  }

  function logout(token) {
    if (token && state.sessions[token]) {
      delete state.sessions[token]
      try { saveState() } finally { securityChanged() }
    }
  }

  function getLockout(ip) {
    if (!state.lockouts[ip]) state.lockouts[ip] = { attempts: 0, lockedUntil: 0 }
    return state.lockouts[ip]
  }

  return {
    dataDir,
    cfg,
    state,
    keysFile,
    visitors,
    passkeys,
    tokens,
    peers,
    publicConfig,
    updateConfig: guarded(updateConfig),
    setPasswordHash: guarded(setPasswordHash),
    issueSession: guarded(issueSession),
    sessionFromToken: guarded(sessionFromToken),
    logout: guarded(logout),
    getLockout: guarded(getLockout),
    saveState: guarded(saveState),
    assertActive,
    retire() { active = false },
    onSecurityChange(listener) { securityListeners.add(listener); return () => securityListeners.delete(listener) },
  }
}
