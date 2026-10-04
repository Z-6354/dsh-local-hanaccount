import { requestHost } from './ip.js'

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1'])

export const PASSKEY_INSECURE_HINT =
  'Passkey 需要 HTTPS 或本机 http://127.0.0.1 / localhost 访问。'

function forwardedProto(req) {
  const raw = String(req.headers?.['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase()
  if (raw === 'https' || raw === 'http') return raw
  return req.socket?.encrypted ? 'https' : 'http'
}

/** WebAuthn rpId / origin from the incoming request (not a config flag). */
export function getPasskeyContext(req) {
  const hostHeader = String(req.headers?.host || '').trim()
  const hostname = requestHost(req)
  const proto = forwardedProto(req)
  const https = proto === 'https'
  const local = LOCAL_HOSTS.has(hostname)
  const available = https || local
  const origin = hostHeader ? `${proto}://${hostHeader}` : `${proto}://${hostname}`
  return {
    available,
    secure: https || local,
    rpId: hostname,
    origin,
    hostname,
    hint: available ? null : PASSKEY_INSECURE_HINT,
  }
}

export function passkeyStatus(req) {
  const ctx = getPasskeyContext(req)
  return {
    available: ctx.available,
    rpId: ctx.rpId,
    origin: ctx.origin,
    hint: ctx.hint,
  }
}
