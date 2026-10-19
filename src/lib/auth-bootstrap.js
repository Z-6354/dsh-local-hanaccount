import { AUTH_BOOTSTRAP_SCRIPT } from './auth-bootstrap.generated.js'

const INJECTION_EVENT = 'webserver/index-inject'

/** Register immutable code in the official document head; no request data is embedded. */
export function installAuthBootstrap(ctx) {
  if (typeof ctx?.on !== 'function') return () => {}
  let active = true
  const inject = rows => {
    if (!active || !Array.isArray(rows) || rows.some(row => row?.kind === 'script' && row?.text === AUTH_BOOTSTRAP_SCRIPT)) return
    rows.push({ kind: 'script', placement: 'head', text: AUTH_BOOTSTRAP_SCRIPT })
  }
  const registration = ctx.on(INJECTION_EVENT, inject)
  let disposed = false
  return () => {
    if (disposed) return
    disposed = true; active = false
    if (typeof registration === 'function') registration()
    else ctx.off?.(INJECTION_EVENT, inject)
  }
}

export { AUTH_BOOTSTRAP_SCRIPT }
