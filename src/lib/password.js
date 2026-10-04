import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }

export function hashPassword(password) {
  const salt = randomBytes(16)
  const hash = scryptSync(String(password), salt, 32, SCRYPT_PARAMS)
  return `$scrypt$${salt.toString('base64')}$${hash.toString('base64')}`
}

export function verifyPassword(password, encoded) {
  const s = String(encoded || '')
  if (!s.startsWith('$scrypt$')) return false
  const parts = s.split('$')
  if (parts.length !== 4) return false
  const salt = Buffer.from(parts[2], 'base64')
  const expected = Buffer.from(parts[3], 'base64')
  const actual = scryptSync(String(password), salt, expected.length, SCRYPT_PARAMS)
  return expected.length === actual.length && timingSafeEqual(expected, actual)
}

export function createLockoutState() {
  return { attempts: 0, lockedUntil: 0 }
}

export function checkLockout(lockout, { maxAttempts = 5, lockMinutes = 30 } = {}) {
  const now = Date.now()
  if (lockout.lockedUntil && lockout.lockedUntil > now) {
    return { locked: true, retryAfterSec: Math.ceil((lockout.lockedUntil - now) / 1000) }
  }
  if (lockout.lockedUntil && lockout.lockedUntil <= now) {
    lockout.attempts = 0
    lockout.lockedUntil = 0
  }
  return { locked: false, attemptsLeft: Math.max(0, maxAttempts - (lockout.attempts || 0)) }
}

export function recordFailedAttempt(lockout, ip, { maxAttempts = 5, lockMinutes = 30 } = {}) {
  lockout.attempts = (lockout.attempts || 0) + 1
  if (lockout.attempts >= maxAttempts) {
    lockout.lockedUntil = Date.now() + lockMinutes * 60 * 1000
    return { locked: true, reason: 'lockout' }
  }
  return { locked: false, reason: 'login_failed', ip }
}

export function resetLockout(lockout) {
  lockout.attempts = 0
  lockout.lockedUntil = 0
}
