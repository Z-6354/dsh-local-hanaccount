import { join } from 'node:path'
import { readJson, writeJson, nowIso, id } from './util.js'

const CHALLENGE_TTL_MS = 5 * 60 * 1000

function emptyFile() {
  return { version: 1, credentials: [], challenges: {} }
}

export function createPasskeyStore(dataDir, securityChanged = () => {}, {assertActive = () => {}, onStorageFailure = () => {}} = {}) {
  let failed = false
  function assertUsable() {
    if (failed) throw Object.assign(new Error('storage_unavailable'), {status:503, code:'storage_unavailable'})
    assertActive()
  }
  const guarded = method => (...args) => {assertUsable(); return method(...args)}
  const file = join(dataDir, 'passkeys.json')
  let data = readJson(file, emptyFile())
  if (!Array.isArray(data.credentials)) data.credentials = []
  if (!data.challenges || typeof data.challenges !== 'object') data.challenges = {}

  function save() {
    assertUsable()
    try { writeJson(file, data) }
    catch {
      failed = true
      try { onStorageFailure() } finally { securityChanged() }
      throw Object.assign(new Error('storage_unavailable'), {status:503, code:'storage_unavailable'})
    }
  }

  function purgeChallenges() {
    const now = Date.now()
    for (const [k, row] of Object.entries(data.challenges)) {
      if (!row?.expiresAt || row.expiresAt < now) delete data.challenges[k]
    }
  }

  function setChallenge(kind, challenge) {
    purgeChallenges()
    data.challenges[kind] = { challenge, expiresAt: Date.now() + CHALLENGE_TTL_MS }
    save()
  }

  function takeChallenge(kind) {
    purgeChallenges()
    const row = data.challenges[kind]
    delete data.challenges[kind]
    if (!row || row.expiresAt < Date.now()) return null
    return row.challenge
  }

  function listPublic() {
    return data.credentials.map((c) => ({
      id: c.id,
      name: c.name || 'Passkey',
      createdAt: c.createdAt,
      backedUp: !!c.backedUp,
    }))
  }

  function listForAuth() {
    return data.credentials.map((c) => ({
      id: c.credentialId,
      transports: c.transports || [],
    }))
  }

  function findByCredentialId(credentialId) {
    const needle = String(credentialId || '')
    return data.credentials.find((c) => c.credentialId === needle) || null
  }

  function addCredential(row) {
    const entry = {
      id: id('pk'),
      credentialId: row.credentialId,
      publicKey: row.publicKey,
      counter: row.counter ?? 0,
      deviceType: row.deviceType || 'singleDevice',
      backedUp: !!row.backedUp,
      transports: row.transports || [],
      name: row.name || 'Passkey',
      createdAt: nowIso(),
    }
    data.credentials.push(entry)
    save()
    return entry
  }

  function removeCredential(entryId) {
    const before = data.credentials.length
    data.credentials = data.credentials.filter((c) => c.id !== entryId)
    if (data.credentials.length !== before) {
      try { save() } finally { securityChanged() }
    }
    return before !== data.credentials.length
  }

  function updateCounter(credentialId, counter) {
    const row = findByCredentialId(credentialId)
    if (!row) return false
    row.counter = counter
    save()
    return true
  }

  return {
    file,
    listPublic: guarded(listPublic),
    listForAuth: guarded(listForAuth),
    findByCredentialId: guarded(findByCredentialId),
    addCredential: guarded(addCredential),
    removeCredential: guarded(removeCredential),
    updateCounter: guarded(updateCounter),
    setChallenge: guarded(setChallenge),
    takeChallenge: guarded(takeChallenge),
    count: guarded(() => data.credentials.length),
  }
}
