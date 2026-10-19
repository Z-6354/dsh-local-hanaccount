/** Offline migration only; runtime continues rejecting unversioned sessions. */
import { createHash, randomBytes } from 'node:crypto'
export function migrateLegacySessions(state, config, { configMtimeMs, nowMs = Date.now(), scope = () => randomBytes(24).toString('hex') }) {
  const counts = { total: 0, migrated: 0, unprovenOrExpired: 0, versioned: 0 }
  const result = structuredClone(state), ttl = Math.max(1, Number(config.sessionMaxAgeDays) || 7) * 86400000
  const version = typeof config.passwordHash === 'string' && config.passwordHash ? createHash('sha256').update(config.passwordHash).digest('hex') : null
  for (const row of Object.values(result.sessions || {})) {
    counts.total++
    if (row.authVersion != null) { counts.versioned++; continue }
    const created = Date.parse(row.createdAt), seen = Date.parse(row.lastSeenAt)
    if (!version || !Number.isFinite(configMtimeMs) || !Number.isFinite(created) || !Number.isFinite(seen)
      || created < configMtimeMs || created > nowMs || seen > nowMs || seen < created
      || nowMs - created >= ttl || nowMs - seen >= ttl) { counts.unprovenOrExpired++; continue }
    row.authVersion = version
    row.resumeScope = scope()
    counts.migrated++
  }
  return { state: result, counts }
}
