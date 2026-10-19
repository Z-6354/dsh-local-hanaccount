import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { migrateLegacySessions } from '../src/lib/legacy-session-migration.js'
test('offline migration proves post-config TTL-valid rows, preserves times and existing versions', () => {
  const now = Date.parse('2026-10-07T08:00:00Z'), stamp = ms => new Date(ms).toISOString()
  const good = { createdAt: stamp(now-1000), lastSeenAt: stamp(now-500), ip: 'fixture' }
  const state = { sessions: { good, oldPassword: { ...good, createdAt: stamp(now-4000) }, expired: { ...good, createdAt: stamp(now-86400000) }, future: { ...good, lastSeenAt: stamp(now+1) }, invalid: {}, versioned: { ...good, authVersion: 'different', resumeScope: 'keep' } } }
  const config = { passwordHash: ' exact hash ', sessionMaxAgeDays: 1 }
  const result = migrateLegacySessions(state, config, { nowMs: now, configMtimeMs: now-2000, scope: () => 'a'.repeat(48) })
  assert.deepEqual(result.counts, { total: 6, migrated: 1, unprovenOrExpired: 4, versioned: 1 })
  assert.deepEqual(result.state.sessions.good, { ...good, authVersion: createHash('sha256').update(config.passwordHash).digest('hex'), resumeScope: 'a'.repeat(48) })
  for (const name of ['oldPassword', 'expired', 'future', 'invalid', 'versioned']) assert.deepEqual(result.state.sessions[name], state.sessions[name])
  assert.equal(state.sessions.good.authVersion, undefined)
  assert.equal(migrateLegacySessions(result.state, config, { nowMs: now, configMtimeMs: now-2000 }).counts.migrated, 0)
})
