export function installOutboundFetch(peersStore) {
  if (globalThis.__dshHcFetchPatched) {
    return globalThis.__dshHcFetchRestore || (() => {})
  }

  const original = globalThis.fetch?.bind(globalThis)
  if (typeof original !== 'function') {
    return () => {}
  }

  async function patchedFetch(input, init = {}) {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input?.url
    const peer = url ? peersStore.matchUrl(url) : null
    if (!peer?.outboundToken) {
      return original(input, init)
    }

    const headers = new Headers(
      init.headers || (typeof Request !== 'undefined' && input instanceof Request ? input.headers : undefined),
    )
    if (!headers.has('authorization')) {
      headers.set('authorization', `Bearer ${peer.outboundToken}`)
    }

    if (typeof Request !== 'undefined' && input instanceof Request) {
      const next = new Request(input, { ...init, headers })
      return original(next)
    }

    return original(input, { ...init, headers })
  }

  globalThis.fetch = patchedFetch
  globalThis.__dshHcFetchPatched = true

  const restore = () => {
    if (!globalThis.__dshHcFetchPatched) return
    globalThis.fetch = original
    delete globalThis.__dshHcFetchPatched
    delete globalThis.__dshHcFetchRestore
  }
  globalThis.__dshHcFetchRestore = restore
  return restore
}
