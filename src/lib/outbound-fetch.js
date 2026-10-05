let installation
export function installOutboundFetch(peersStore) {
  if (installation) throw new Error('outbound enhancement already installed')

  const original = globalThis.fetch
  if (typeof original !== 'function') {
    return () => {}
  }

  let active = true
  async function patchedFetch(input, init = {}) {
    if (!active) return original.call(globalThis, input, init)
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input?.url
    const peer = url ? peersStore.matchUrl(url) : null
    if (!peer?.outboundToken) {
      return original.call(globalThis, input, init)
    }

    const headers = new Headers(
      init.headers || (typeof Request !== 'undefined' && input instanceof Request ? input.headers : undefined),
    )
    if (!headers.has('authorization')) {
      headers.set('authorization', `Bearer ${peer.outboundToken}`)
    }

    if (typeof Request !== 'undefined' && input instanceof Request) {
      const next = new Request(input, { ...init, headers })
      return original.call(globalThis, next)
    }

    return original.call(globalThis, input, { ...init, headers })
  }

  globalThis.fetch = patchedFetch
  installation = patchedFetch

  const restore = () => {
    if (!active) return
    active = false
    if (globalThis.fetch === patchedFetch) globalThis.fetch = original
    if (installation === patchedFetch) installation = undefined
  }
  return restore
}
