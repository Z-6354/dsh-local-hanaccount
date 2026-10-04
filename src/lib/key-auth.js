import { createPublicKey, createVerify, randomBytes } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { id, nowIso } from './util.js'

function parseSshEd25519(line) {
  const parts = String(line).trim().split(/\s+/)
  if (parts.length < 2 || parts[0] !== 'ssh-ed25519') return null
  const blob = Buffer.from(parts[1], 'base64')
  if (blob.length < 32) return null
  const key = blob.subarray(blob.length - 32)
  const comment = parts.slice(2).join(' ') || ''
  return { key, comment, line: line.trim() }
}

export function parseAuthorizedKeys(text) {
  const keys = []
  for (const line of String(text || '').split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const parsed = parseSshEd25519(trimmed)
    if (parsed) keys.push({ id: id('key'), ...parsed })
  }
  return keys
}

export function loadAuthorizedKeys(file) {
  if (!existsSync(file)) return []
  return parseAuthorizedKeys(readFileSync(file, 'utf8'))
}

export function saveAuthorizedKeys(file, keys) {
  mkdirSync(dirname(file), { recursive: true })
  const lines = keys.map((k) => k.line || `ssh-ed25519 ${Buffer.from(k.key).toString('base64')} ${k.comment || ''}`.trim())
  writeFileSync(file, lines.join('\n') + (lines.length ? '\n' : ''), 'utf8')
}

export function createChallengeStore() {
  const pending = new Map()
  return {
    issue() {
      const challengeId = id('ch')
      const nonce = randomBytes(32).toString('hex')
      const expiresAt = Date.now() + 60_000
      pending.set(challengeId, { nonce, expiresAt })
      return { challengeId, nonce, expiresIn: 60 }
    },
    consume(challengeId, signatureB64) {
      const row = pending.get(challengeId)
      pending.delete(challengeId)
      if (!row || row.expiresAt < Date.now()) return { ok: false, error: 'challenge expired' }
      return { ok: true, nonce: row.nonce, signature: Buffer.from(signatureB64, 'base64') }
    },
    purge() {
      const now = Date.now()
      for (const [k, v] of pending) {
        if (v.expiresAt < now) pending.delete(k)
      }
    },
  }
}

export function verifyEd25519Signature(publicKey32, message, signature) {
  try {
    const der = Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      publicKey32,
    ])
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' })
    return createVerify('ed25519').update(message).verify(key, signature)
  } catch {
    return false
  }
}

export function verifyKeySignature(keys, nonce, signature) {
  const msg = Buffer.from(String(nonce), 'utf8')
  for (const k of keys) {
    if (verifyEd25519Signature(k.key, msg, signature)) return k
  }
  return null
}

export function addPublicKey(keys, line) {
  const parsed = parseSshEd25519(line)
  if (!parsed) throw new Error('invalid ssh-ed25519 public key')
  if (keys.some((k) => k.line === parsed.line)) return keys
  return [...keys, { id: id('key'), ...parsed, addedAt: nowIso() }]
}
