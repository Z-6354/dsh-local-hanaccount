import { join } from 'node:path'
import { randomInt } from 'node:crypto'
import { id, nowIso, readJson, writeJson, httpError } from './util.js'
import { hashToken, issueToken } from './tokens.js'

const PAIRING_TTL_MS = 10 * 60 * 1000

function normalizeBaseUrl(raw) {
  const text = String(raw ?? '').trim()
  if (!text) return ''
  const url = new URL(text.includes('://') ? text : `http://${text}`)
  url.pathname = ''
  url.search = ''
  url.hash = ''
  return url.toString().replace(/\/$/, '')
}

export function createPeersStore(dataDir, securityChanged = () => {}, {assertActive = () => {}, onStorageFailure = () => {}} = {}) {
  let failed = false
  function assertUsable() {
    if (failed) throw Object.assign(new Error('storage_unavailable'), {status:503, code:'storage_unavailable'})
    assertActive()
  }
  const guarded = method => (...args) => {assertUsable(); return method(...args)}
  function persist(file, state) {
    assertUsable()
    try { writeJson(file, state) }
    catch {
      failed = true
      try { onStorageFailure() } finally { securityChanged() }
      throw Object.assign(new Error('storage_unavailable'), {status:503, code:'storage_unavailable'})
    }
  }
  const peersFile = join(dataDir, 'peers.json')
  const pairingFile = join(dataDir, 'pairing-codes.json')

  let state = readJson(peersFile, { version: 1, peers: [] })
  if (!Array.isArray(state.peers)) state.peers = []

  let pairingState = readJson(pairingFile, { version: 1, codes: [] })
  if (!Array.isArray(pairingState.codes)) pairingState.codes = []

  function savePeers() {
    persist(peersFile, state)
  }

  function savePairing() {
    persist(pairingFile, pairingState)
  }

  function prunePairingCodes() {
    const now = Date.now()
    const before = pairingState.codes.length
    pairingState.codes = pairingState.codes.filter((row) => Date.parse(row.expiresAt) > now)
    if (before !== pairingState.codes.length) savePairing()
  }

  function listPeersPublic() {
    return state.peers.map((row) => ({
      id: row.id,
      name: row.name,
      baseUrl: row.baseUrl,
      direction: row.direction,
      createdAt: row.createdAt,
      lastUsedAt: row.lastUsedAt || null,
    }))
  }

  function getPeer(peerId) {
    return state.peers.find((row) => row.id === peerId) || null
  }

  function addOutboundPeer({ name, baseUrl, token }) {
    const row = {
      id: id('peer'),
      name: String(name || 'Peer').trim() || 'Peer',
      baseUrl: normalizeBaseUrl(baseUrl),
      direction: 'outbound',
      outboundToken: String(token),
      inboundTokenHash: '',
      createdAt: nowIso(),
      lastUsedAt: null,
    }
    state.peers.push(row)
    savePeers()
    return row
  }

  function addInboundPeer({ name, baseUrl, tokenHash }) {
    const row = {
      id: id('peer'),
      name: String(name || 'Peer').trim() || 'Peer',
      baseUrl: normalizeBaseUrl(baseUrl),
      direction: 'inbound',
      outboundToken: '',
      inboundTokenHash: tokenHash,
      createdAt: nowIso(),
      lastUsedAt: null,
    }
    state.peers.push(row)
    savePeers()
    return row
  }

  function removePeer(peerId) {
    const before = state.peers.length
    state.peers = state.peers.filter((row) => row.id !== peerId)
    if (state.peers.length === before) return false
    try { savePeers() } finally { securityChanged() }
    return true
  }

  function createPairingCode() {
    prunePairingCodes()
    if (pairingState.codes.length >= 8) throw httpError(429, 'pairing code limit reached')
    let code
    do { code = String(randomInt(100000, 1000000)) } while (pairingState.codes.some(row => row.code === code))
    const token = issueToken()
    const row = {
      code,
      token,
      tokenHash: hashToken(token),
      expiresAt: new Date(Date.now() + PAIRING_TTL_MS).toISOString(),
      createdAt: nowIso(),
    }
    pairingState.codes.push(row)
    savePairing()
    return { code, expiresAt: row.expiresAt }
  }

  function claimPairingCode({ code, peerName, peerBaseUrl }) {
    prunePairingCodes()
    const now = Date.now()
    if (!pairingState.attempts || pairingState.attempts.resetAt <= now) pairingState.attempts = {count:0, resetAt:now + PAIRING_TTL_MS}
    if (pairingState.attempts.count >= 30) return {ok:false,error:'pairing attempt limit reached'}
    const wanted = String(code ?? '').trim()
    const idx = pairingState.codes.findIndex((row) => row.code === wanted)
    if (idx < 0) {
      pairingState.attempts.count += 1
      savePairing()
      return { ok: false, error: 'invalid or expired pairing code' }
    }
    const pending = pairingState.codes.splice(idx, 1)[0]
    savePairing()
    if (Date.parse(pending.expiresAt) <= Date.now()) {
      return { ok: false, error: 'invalid or expired pairing code' }
    }
    const inbound = addInboundPeer({
      name: peerName,
      baseUrl: peerBaseUrl,
      tokenHash: pending.tokenHash,
    })
    return { ok: true, peerId: inbound.id, token: pending.token }
  }

  function inboundVerifierEntries() {
    return state.peers
      .filter((row) => row.inboundTokenHash)
      .map((row) => ({
        kind: 'peer',
        id: row.id,
        name: row.name,
        hash: row.inboundTokenHash,
        onUse: () => {
          assertUsable()
          if (row.lastUsedAt && Date.now() - Date.parse(row.lastUsedAt) < 60000) return
          row.lastUsedAt = nowIso()
          savePeers()
        },
      }))
  }

  function matchUrl(rawUrl) {
    let parsed
    try {
      parsed = new URL(String(rawUrl))
    } catch {
      return null
    }
    const target = `${parsed.protocol}//${parsed.host}`
    for (const row of state.peers) {
      if (!row.outboundToken || !row.baseUrl) continue
      try {
        const base = new URL(row.baseUrl.includes('://') ? row.baseUrl : `http://${row.baseUrl}`)
        const baseOrigin = `${base.protocol}//${base.host}`
        if (baseOrigin === target) return row
      } catch {
        continue
      }
    }
    return null
  }

  return {
    listPeersPublic: guarded(listPeersPublic),
    getPeer: guarded(getPeer),
    addOutboundPeer: guarded(addOutboundPeer),
    addInboundPeer: guarded(addInboundPeer),
    removePeer: guarded(removePeer),
    createPairingCode: guarded(createPairingCode),
    claimPairingCode: guarded(claimPairingCode),
    inboundVerifierEntries: guarded(inboundVerifierEntries),
    matchUrl: guarded(matchUrl),
    normalizeBaseUrl,
  }
}
