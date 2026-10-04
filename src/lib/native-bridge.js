export const AUTH_PROTOCOL = 'password-native-v1'

function failure(code = 'native_bridge_unavailable', status = 503) {
  return Object.assign(new Error(code), { code, status })
}

// Only the public connection owner can mint and verify its native cookie.
export function createNativeBridge(connection) {
  for (const method of ['requestRejection', 'authenticatedUrl', 'authorizeIndex']) {
    if (typeof connection?.[method] !== 'function') throw failure()
  }
  let disposed = false
  function fence(req) {
    if (disposed) throw failure()
    const rejection = connection.requestRejection(req)
    if (rejection === 403) throw failure('access_denied', 403)
    if (rejection !== undefined && rejection !== 401) throw failure()
    return rejection
  }
  function mint(req, secure = false) {
    fence(req)
    let status, headers, ended = false
    try {
      const internal = new URL(connection.authenticatedUrl(`http://${req.headers.host}`))
      const request = Object.create(req)
      Object.defineProperties(request, {
        method: { value: 'GET' }, url: { value: internal.pathname + internal.search },
      })
      const allowed = connection.authorizeIndex(request, {
        writeHead(code, values) { status = code; headers = values },
        end() { ended = true },
      })
      const cookie = headers?.['set-cookie']
      if (allowed !== false || !ended || status !== 303 || headers?.location !== '/'
        || typeof cookie !== 'string' || !/^dsh-auth-[^=;\s]+=/.test(cookie)
        || cookie.includes('\r') || cookie.includes('\n')) throw failure()
      const check = Object.create(req)
      Object.defineProperty(check, 'headers', { value: { ...req.headers, cookie: cookie.split(';')[0] } })
      if (connection.requestRejection(check) !== undefined) throw failure()
      return secure && !/;\s*Secure(?:;|$)/i.test(cookie) ? `${cookie}; Secure` : cookie
    } catch (err) {
      if (err?.code === 'access_denied') throw err
      throw failure()
    }
  }
  return {
    fence, mint,
    authenticated(req) { return fence(req) === undefined },
    clear(req, secure = false) {
      const name = mint(req, secure).split('=')[0]
      return `${name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? '; Secure' : ''}`
    },
    dispose() { disposed = true },
  }
}
