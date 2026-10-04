import { join } from 'node:path'
import { readJson, writeJson, nowIso } from './util.js'

const MAX_VISITORS = 300

function emptyVisitorsFile() {
  return {
    version: 1,
    stats: {
      totalIllegalBlocked: 0,
      totalBlacklistedHits: 0,
      totalStrictBlocked: 0,
      totalLoginFailures: 0,
      totalUnauthenticated: 0,
      since: nowIso(),
    },
    visitors: {},
  }
}

export function createVisitorsStore(dataDir) {
  const file = join(dataDir, 'security-visitors.json')
  let data = readJson(file, emptyVisitorsFile())
  if (!data.stats) data.stats = emptyVisitorsFile().stats
  if (!data.visitors || typeof data.visitors !== 'object') data.visitors = {}

  function save() {
    writeJson(file, data)
  }

  function trimVisitors() {
    const entries = Object.values(data.visitors)
    if (entries.length <= MAX_VISITORS) return
    entries.sort((a, b) => String(a.lastSeenAt).localeCompare(String(b.lastSeenAt)))
    for (const v of entries.slice(0, entries.length - MAX_VISITORS)) delete data.visitors[v.ip]
  }

  function record(ip, reason, meta = {}) {
    if (!ip) return
    const stats = data.stats
    if (reason === 'ip_blacklisted') {
      stats.totalIllegalBlocked++
      stats.totalBlacklistedHits++
    } else if (reason === 'ip_blocked') {
      stats.totalIllegalBlocked++
      stats.totalStrictBlocked++
    } else if (reason === 'unauthenticated') {
      stats.totalIllegalBlocked++
      stats.totalUnauthenticated++
    } else if (reason === 'login_failed') {
      stats.totalLoginFailures++
    }

    const row = data.visitors[ip] || {
      ip,
      firstSeenAt: nowIso(),
      lastSeenAt: nowIso(),
      eventCount: 0,
      reasons: {},
      lastReason: reason,
      lastPath: meta.path || '',
      userAgent: meta.userAgent || '',
      status: 'suspicious',
      whitelisted: false,
    }
    row.lastSeenAt = nowIso()
    row.eventCount++
    row.reasons[reason] = (row.reasons[reason] || 0) + 1
    row.lastReason = reason
    if (meta.path) row.lastPath = meta.path
    if (meta.userAgent) row.userAgent = meta.userAgent
    data.visitors[ip] = row
    trimVisitors()
    save()
  }

  return {
    file,
    getStats() { return { ...data.stats } },
    listVisitors() {
      return Object.values(data.visitors).sort((a, b) => String(b.lastSeenAt).localeCompare(String(a.lastSeenAt)))
    },
    record,
    dismiss(ip) {
      delete data.visitors[ip]
      save()
    },
    resetStats() {
      data.stats = emptyVisitorsFile().stats
      save()
    },
  }
}
