import { isIP } from 'node:net'

const TRUSTED_PROXIES = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1'])

/** Loopback — must never be deny-listed or local DSH becomes unreachable. */
export const LOOPBACK_ENTRIES = ['127.0.0.1', '::1']

export function isLoopbackIp(entry) {
  const n = normalizeIpEntry(entry)
  return LOOPBACK_ENTRIES.includes(n)
}

function normalizeIp(ip) {
  const s = String(ip || '').trim()
  if (s.startsWith('::ffff:')) return s.slice(7)
  return s
}

function ipv4ToInt(ip) {
  const parts = ip.split('.').map((x) => Number(x))
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
}

function matchCidr(ip, cidr) {
  const [base, bitsRaw] = cidr.split('/')
  const bits = bitsRaw == null ? 32 : Number(bitsRaw)
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false
  const ipInt = ipv4ToInt(ip)
  const baseInt = ipv4ToInt(base)
  if (ipInt == null || baseInt == null) return false
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
  return (ipInt & mask) === (baseInt & mask)
}

export function ipMatchesEntry(ip, entry) {
  const target = String(entry || '').trim()
  if (!target) return false
  const normalized = normalizeIp(ip)
  if (target.includes('/')) return matchCidr(normalized, target)
  return normalizeIp(target) === normalized
}

export function ipInList(ip, list) {
  for (const entry of list || []) {
    if (ipMatchesEntry(ip, entry)) return true
  }
  return false
}

/** Normalize a single allow/deny entry (trim + strip IPv4-mapped prefix on hosts). */
export function normalizeIpEntry(entry) {
  const raw = String(entry || '').trim()
  if (!raw) return ''
  if (raw.includes('/')) {
    const [base, bits] = raw.split('/')
    const host = normalizeIp(base)
    return bits == null || bits === '' ? host : `${host}/${bits}`
  }
  return normalizeIp(raw)
}

/**
 * Validate IPv4 / IPv6 / IPv4 CIDR entry for allow/deny lists.
 * IPv6 CIDR is rejected (matcher is IPv4-only).
 */
export function isValidIpOrCidr(entry) {
  const raw = normalizeIpEntry(entry)
  if (!raw) return false
  if (raw.includes('/')) {
    const [base, bitsRaw] = raw.split('/')
    if (!isIP(base) || isIP(base) !== 4) return false
    const bits = Number(bitsRaw)
    return Number.isInteger(bits) && bits >= 0 && bits <= 32
  }
  return !!isIP(raw)
}

/**
 * Merge into allow or deny with mutual exclusion and validation.
 * @returns {{ allow: string[], deny: string[], added: string|null, error?: string }}
 */
export function applyIpListChange(cfg, { listKey, entry, remove = false } = {}) {
  const allow = [...(cfg.allow || [])]
  const deny = [...(cfg.deny || [])]
  const key = listKey === 'deny' ? 'deny' : 'allow'
  const normalized = normalizeIpEntry(entry)
  if (!normalized) return { allow, deny, added: null, error: 'empty' }
  if (!isValidIpOrCidr(normalized)) {
    return { allow, deny, added: null, error: 'invalid' }
  }
  if (key === 'deny' && isLoopbackIp(normalized)) {
    return { allow, deny, added: null, error: 'loopback' }
  }
  if (remove) {
    if (key === 'allow') {
      return { allow: allow.filter((x) => normalizeIpEntry(x) !== normalized), deny, added: null }
    }
    return { allow, deny: deny.filter((x) => normalizeIpEntry(x) !== normalized), added: null }
  }
  const nextAllow = allow.filter((x) => normalizeIpEntry(x) !== normalized)
  const nextDeny = deny.filter((x) => normalizeIpEntry(x) !== normalized)
  if (key === 'allow') {
    if (!nextAllow.some((x) => normalizeIpEntry(x) === normalized)) nextAllow.push(normalized)
    return { allow: nextAllow, deny: nextDeny, added: normalized }
  }
  if (!nextDeny.some((x) => normalizeIpEntry(x) === normalized)) nextDeny.push(normalized)
  return { allow: nextAllow, deny: nextDeny, added: normalized }
}

function headerIp(req, name) {
  const raw = req.headers?.[name]
  if (!raw) return ''
  const first = String(raw).split(',')[0].trim()
  return normalizeIp(first)
}

export function resolveClientIp(req, { trustProxy = true } = {}) {
  const remote = normalizeIp(req.socket?.remoteAddress || '')
  if (!remote) return ''
  if (!trustProxy || !TRUSTED_PROXIES.has(remote)) return remote
  const real = headerIp(req, 'x-real-ip')
  if (real && isIP(real)) return real
  const forwarded = headerIp(req, 'x-forwarded-for')
  if (forwarded && isIP(forwarded)) return forwarded
  return remote
}

/**
 * @returns {{ action: 'pass'|'block', reason?: string, whitelisted?: boolean, blacklisted?: boolean }}
 */
export function evaluateIpAccess(ip, cfg) {
  const allow = cfg.allow || []
  const deny = cfg.deny || []
  if (ipInList(ip, deny)) return { action: 'block', reason: 'ip_blacklisted', blacklisted: true }
  if (!cfg.ipLimitEnabled) return { action: 'pass' }
  if (ipInList(ip, allow)) return { action: 'pass', whitelisted: true }
  return { action: 'block', reason: 'ip_blocked', whitelisted: false }
}

export function nginxSnippet({ port = 3080 } = {}) {
  return `# DSH access lock — put inside your server { } block
location / {
    proxy_pass http://127.0.0.1:${port};
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}

# Recommended: DSH listens on 127.0.0.1 only; expose only via Nginx + TLS.`
}

export function detectProxy(req) {
  const remote = normalizeIp(req.socket?.remoteAddress || '')
  const viaTrusted = TRUSTED_PROXIES.has(remote)
  const hasForwarded = !!(req.headers?.['x-real-ip'] || req.headers?.['x-forwarded-for'])
  return { viaTrustedProxy: viaTrusted, hasForwardedHeaders: hasForwarded, remoteAddress: remote }
}

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1'])

export const NGINX_MISCONFIG_MESSAGE =
  '检测到 Nginx 反代，但未配置 X-Real-IP。所有外网请求会被识别为 127.0.0.1，白名单将失效。请在 Nginx 的 location 中添加：proxy_set_header X-Real-IP $remote_addr;'

function hasClientIpHeader(req) {
  const real = headerIp(req, 'x-real-ip')
  if (real && isIP(real)) return true
  const forwarded = headerIp(req, 'x-forwarded-for')
  return !!(forwarded && isIP(forwarded))
}

/** Hostname from Host header (no port). */
export function requestHost(req) {
  const raw = String(req.headers?.host || '').trim().toLowerCase()
  if (!raw) return ''
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']')
    return end >= 0 ? raw.slice(1, end) : raw
  }
  const colon = raw.lastIndexOf(':')
  if (colon > 0 && /^\d+$/.test(raw.slice(colon + 1))) return raw.slice(0, colon)
  return raw
}

/**
 * Nginx proxies to 127.0.0.1 but forgot X-Real-IP while Host is an external name.
 * Direct local access (Host: localhost / 127.0.0.1) is not flagged.
 */
export function detectNginxMisconfig(req) {
  const remote = normalizeIp(req.socket?.remoteAddress || '')
  if (!TRUSTED_PROXIES.has(remote)) return { misconfigured: false }
  if (hasClientIpHeader(req)) return { misconfigured: false }
  const host = requestHost(req)
  if (!host || LOCAL_HOSTS.has(host)) return { misconfigured: false }
  return {
    misconfigured: true,
    code: 'nginx_missing_x_real_ip',
    message: NGINX_MISCONFIG_MESSAGE,
    host,
    remoteAddress: remote,
  }
}

export { TRUSTED_PROXIES }
