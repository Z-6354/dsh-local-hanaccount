import { join } from 'node:path'
import { readJson, writeJson, nowIso, id } from './util.js'

const CHALLENGE_TTL_MS = 5 * 60 * 1000

function emptyFile() {
  return { version: 1, credentials: [], challenges: {} }
}

export function createPasskeyStore(dataDir) {
  const file = join(dataDir, 'passkeys.json')
  let data = readJson(file, emptyFile())
  if (!Array.isArray(data.credentials)) data.credentials = []
  if (!data.challenges || typeof data.challenges !== 'object') data.challenges = {}

  function save() {
    writeJson(file, data)
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
    if (data.credentials.length !== before) save()
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
    listPublic,
    listForAuth,
    findByCredentialId,
    addCredential,
    removeCredential,
    updateCounter,
    setChallenge,
    takeChallenge,
    count: () => data.credentials.length,
  }
}
