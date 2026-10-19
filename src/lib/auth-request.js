/** Same-origin JSON request shared by the early bootstrap and client bundle. */
export function createAuthRequest({ fetchImpl = globalThis.fetch, base = '/dsh-local-hanaccount/api', origin = globalThis.location?.origin } = {}) {
  if (typeof fetchImpl !== 'function') throw new TypeError('fetch unavailable')
  const baseUrl = new URL(base, origin)
  if (!origin || baseUrl.origin !== origin || baseUrl.pathname.endsWith('/')) throw new TypeError('same-origin API required')
  const prefix = baseUrl.pathname.replace(/\/$/, '')
  return async function request(path, options = {}) {
    const endpoint = new URL(`${prefix}${path}`, origin)
    if (endpoint.origin !== origin || !endpoint.pathname.startsWith(`${prefix}/`)) throw new TypeError('same-origin API path required')
    const controller = typeof AbortController === 'function' ? new AbortController() : null
    const timeoutMs = Number.isFinite(options.timeoutMs) ? Math.max(1, options.timeoutMs) : 5000
    const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null
    const onAbort = () => controller?.abort()
    const externalSignal = options.signal
    if (externalSignal?.aborted) controller?.abort()
    else externalSignal?.addEventListener?.('abort', onAbort, { once: true })
    try {
      const { signal: _signal, timeoutMs: _timeout, ...requestOptions } = options
      const response = await fetchImpl(endpoint.href, {
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers: { 'content-type': 'application/json', ...(requestOptions.headers || {}) },
        ...requestOptions,
        signal: controller?.signal ?? externalSignal,
      })
      if (response.redirected) throw Object.assign(new Error('cross_origin_redirect'), { status: response.status })
      let body = {}
      const text = await response.text()
      try { body = text ? JSON.parse(text) : {} } catch {
        throw Object.assign(new Error('invalid_json'), { status: response.status })
      }
      if (!response.ok) throw Object.assign(new Error(body.error || `HTTP ${response.status}`), { status: response.status, code: body.code })
      return body
    } catch (error) {
      if (error?.name === 'AbortError') throw Object.assign(new Error('timeout'), { name: 'TimeoutError' })
      throw error
    } finally {
      if (timer) clearTimeout(timer)
      externalSignal?.removeEventListener?.('abort', onAbort)
    }
  }
}
