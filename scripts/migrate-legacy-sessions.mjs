// Run only with the service stopped and an original state/config backup available.
import { readFileSync, statSync, openSync, writeFileSync, fsyncSync, closeSync, renameSync, fchmodSync, fchownSync } from 'node:fs'
import { join } from 'node:path'
import { migrateLegacySessions } from '../src/lib/legacy-session-migration.js'
const directory = process.argv[2]
if (!directory) throw new Error('explicit data directory required')
const statePath = join(directory, 'state.json'), configPath = join(directory, 'config.json')
const original = statSync(statePath)
const { state, counts } = migrateLegacySessions(JSON.parse(readFileSync(statePath, 'utf8')), JSON.parse(readFileSync(configPath, 'utf8')), { configMtimeMs: statSync(configPath).mtimeMs })
if (counts.migrated) {
  const temporary = join(directory, `.state-migration-${process.pid}.tmp`)
  const fd = openSync(temporary, 'wx', 0o600)
  try { fchownSync(fd, original.uid, original.gid); fchmodSync(fd, 0o600); writeFileSync(fd, JSON.stringify(state, null, 2)+'\n'); fsyncSync(fd) } finally { closeSync(fd) }
  renameSync(temporary, statePath)
  const dirfd = openSync(directory, 'r'); try { fsyncSync(dirfd) } finally { closeSync(dirfd) }
}
console.log(JSON.stringify(counts))
