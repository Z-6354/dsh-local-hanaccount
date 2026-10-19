import { readFileSync } from 'node:fs'
import { hashPassword } from './password.js'

export const MIN_PASSWORD_LENGTH = 8
export const PASSWORD_ENV = 'DSH_HANACCOUNT_PASSWORD'
export const PASSWORD_FILE_ENV = 'DSH_HANACCOUNT_PASSWORD_FILE'

/**
 * Operator-supplied initial password: `DSH_HANACCOUNT_PASSWORD_FILE` (preferred, nothing secret stays in the
 * environment) or `DSH_HANACCOUNT_PASSWORD`. Returns '' when neither is set. A file that cannot be read is an error
 * rather than silent: the operator asked for a password and would otherwise find the instance without one.
 */
export function readInitialPassword(env = process.env, readFile = (path) => readFileSync(path, 'utf8')) {
  const file = String(env[PASSWORD_FILE_ENV] || '').trim()
  if (file) return readFile(file).replace(/\r?\n$/, '')
  return String(env[PASSWORD_ENV] || '')
}

/**
 * Browser setup is closed (`auth/setup` answers 403): an unauthenticated first visitor must never be able to claim the
 * instance, and a tunnel into loopback is indistinguishable from the local browser. The initial password therefore
 * comes from someone who controls the process environment or the data directory. It is applied only while no password
 * exists and never overwrites one.
 *
 * @returns {{ applied: boolean, reason?: string }}
 */
export function applyInitialPassword(store, { env = process.env, logger, readFile } = {}) {
  if (store.cfg.passwordHash) return { applied: false, reason: 'already_configured' }
  let password
  try { password = readInitialPassword(env, readFile) }
  catch { logger?.warn?.(`[dsh-local-hanaccount] ${PASSWORD_FILE_ENV} could not be read; no password was set`); return { applied: false, reason: 'unreadable' } }
  if (!password) return { applied: false, reason: 'not_provided' }
  if (password.length < MIN_PASSWORD_LENGTH) {
    logger?.warn?.(`[dsh-local-hanaccount] the initial password must be at least ${MIN_PASSWORD_LENGTH} characters; no password was set`)
    return { applied: false, reason: 'too_short' }
  }
  store.setPasswordHash(hashPassword(password))
  logger?.info?.('[dsh-local-hanaccount] access password set from the environment; remove it from the environment now')
  return { applied: true }
}
