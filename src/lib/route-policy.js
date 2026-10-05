import { normalizeStringList } from './util.js'

export const ROUTE_MODE_PROTECT_ALL = 'protect-all'

/** Prefix names do not establish static ownership. Login runs without bundles. */
export const BUILTIN_AUTH_EXCLUDE_PREFIXES = []

export function normalizeRoutePath(path) {
  const raw = String(path ?? '').trim()
  if (!raw) return '/'
  const withSlash = raw.startsWith('/') ? raw : `/${raw}`
  return withSlash.replace(/\/+$/, '') || '/'
}

export function normalizeRoutePolicy(policy = {}) {
  const mode = policy.mode === ROUTE_MODE_PROTECT_ALL ? ROUTE_MODE_PROTECT_ALL : ROUTE_MODE_PROTECT_ALL
  return {
    mode,
    excludePrefixes: normalizeStringList(policy.excludePrefixes).map(normalizeRoutePath),
  }
}

export function isAuthExcluded(pathname, excludePrefixes = []) {
  const path = normalizeRoutePath(pathname)
  for (const prefix of excludePrefixes) {
    const ex = normalizeRoutePath(prefix)
    if (path === ex || path.startsWith(`${ex}/`)) return true
  }
  return false
}

export function shouldWrapPrefix(prefixPath, routePolicy) {
  const policy = normalizeRoutePolicy(routePolicy)
  if (policy.mode !== ROUTE_MODE_PROTECT_ALL) return normalizeRoutePath(prefixPath) === '/api'
  void prefixPath
  return true
}
