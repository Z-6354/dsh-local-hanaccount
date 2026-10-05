// Source-only contract launcher. The former full CLI probe depended on stale
// built packages and is retired; this never starts the official CLI or a model.
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { createRequire } from 'node:module'
const source = resolve(process.argv[2] || '')
if (!process.argv[2] || !existsSync(join(source, 'packages/host/webserver/src/index.ts'))) throw Error('explicit official source checkout required')
if (process.argv.includes('--serve-for-qa')) throw Error('serve-for-qa is unsupported; source contract fixture closes all temporary listeners')
const requireSource = createRequire(join(source, 'package.json'))
const fixture = fileURLToPath(new URL('./official-auth-fixture.mjs', import.meta.url))
const result = spawnSync(process.execPath, ['--import', pathToFileURL(requireSource.resolve('tsx/esm')).href, fixture], {
  cwd: source, env: {...process.env, TSX_TSCONFIG_PATH: join(source, 'tsconfig.json')}, windowsHide:true, stdio:'inherit',
})
if (result.error) throw result.error
process.exitCode = result.status ?? 1
