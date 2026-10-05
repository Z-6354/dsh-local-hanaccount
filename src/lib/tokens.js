import { createHash, randomBytes } from 'node:crypto'
import { join } from 'node:path'
import { id, nowIso, readJson, writeJson } from './util.js'

export function hashToken(raw) {
  return createHash('sha256').update(String(raw), 'utf8').digest('hex')
}

export function issueToken() {
  return randomBytes(32).toString('hex')
}

export function createTokenStore(dataDir, securityChanged = () => {}, {assertActive = () => {}, onStorageFailure = () => {}} = {}) {
  let failed = false
  function assertUsable() {
    if (failed) throw Object.assign(new Error('storage_unavailable'), {status:503, code:'storage_unavailable'})
    assertActive()
  }
  const guarded = method => (...args) => {assertUsable(); return method(...args)}
  const apiTokensFile = join(dataDir, 'api-tokens.json')

  let apiState = readJson(apiTokensFile, { version: 1, tokens: [] })
  if (!Array.isArray(apiState.tokens)) apiState.tokens = []

  function saveApiTokens() {
    assertUsable()
    try { writeJson(apiTokensFile, apiState) }
    catch {
      failed = true
      try { onStorageFailure() } finally { securityChanged() }
      throw Object.assign(new Error('storage_unavailable'), {status:503, code:'storage_unavailable'})
    }
  }

  function listApiTokensPublic() {
    return apiState.tokens.map((row) => ({
      id: row.id,
      name: row.name,
      createdAt: row.createdAt,
      lastUsedAt: row.lastUsedAt || null,
    }))
  }

  function createApiToken(name) {
    const raw = issueToken()
    const row = {
      id: id('tok'),
      name: String(name || 'API token').trim() || 'API token',
      tokenHash: hashToken(raw),
      createdAt: nowIso(),
      lastUsedAt: null,
    }
    apiState.tokens.push(row)
    saveApiTokens()
    return { id: row.id, name: row.name, token: raw }
  }

  function revokeApiToken(tokenId) {
    const before = apiState.tokens.length
    apiState.tokens = apiState.tokens.filter((row) => row.id !== tokenId)
    if (apiState.tokens.length === before) return false
    try { saveApiTokens() } finally { securityChanged() }
    return true
  }

  function verifyApiToken(raw) {
    const hash = hashToken(raw)
    const row = apiState.tokens.find((t) => t.tokenHash === hash)
    if (!row) return null
    if (!row.lastUsedAt || Date.now() - Date.parse(row.lastUsedAt) >= 60000) {
      row.lastUsedAt = nowIso()
      saveApiTokens()
    }
    return { kind: 'api', id: row.id, name: row.name }
  }

  function verifyAny(raw, extraHashes = []) {
    const api = verifyApiToken(raw)
    if (api) return api
    const hash = hashToken(raw)
    for (const entry of extraHashes) {
      if (entry.hash === hash) {
        if (entry.onUse) entry.onUse()
        return { kind: entry.kind || 'peer', id: entry.id, name: entry.name }
      }
    }
    return null
  }

  return {
    listApiTokensPublic: guarded(listApiTokensPublic),
    createApiToken: guarded(createApiToken),
    revokeApiToken: guarded(revokeApiToken),
    verifyApiToken: guarded(verifyApiToken),
    verifyAny: guarded(verifyAny),
    hashToken,
    issueToken,
  }
}
