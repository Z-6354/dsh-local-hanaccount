// A deploy-owned static stylesheet, not a plugin module or an auth capability.
export function loginStyle(config = {}) {
  try {
    if (!config.loginStylesheetUrl) return null
    const origin = new URL(config.canonicalOrigin)
    if (origin.protocol !== 'https:' || origin.href !== `${origin.origin}/` || origin.username || origin.password) return null
    const url = new URL(config.loginStylesheetUrl)
    if (url.origin !== origin.origin || url.username || url.password || url.search || url.hash
      || url.pathname !== '/hanui-assets/login.css' || url.href !== config.loginStylesheetUrl) return null
    return Object.freeze({ url: url.href, origin: origin.origin, host: origin.host, path: url.pathname })
  } catch { return null }
}
