window.__ModuleLoader__.load({
  id: 'dsh-local-hanaccount',
  factory: (require) => {
    const module = { exports: {} }
    const exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' })

    const React = require('react')
    const { jsx, jsxs } = require('react/jsx-runtime')

    const API = '/dsh-local-hanaccount/api'
    const STYLE_ID = 'dsh-local-hanaccount-css-v4'

    const listeners = new Set()
    const state = { me: null, loading: true }
    function emit() { for (const fn of listeners) fn({ ...state }) }
    function setState(patch) { Object.assign(state, patch); emit() }

    async function api(path, options) {
      const res = await fetch(API + path, {
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', ...(options?.headers || {}) },
        ...options,
      })
      const text = await res.text()
      let data = {}
      try { data = text ? JSON.parse(text) : {} } catch { data = { error: text } }
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
      return data
    }

    async function refreshMe() {
      setState({ loading: true })
      try {
        const me = await api('/auth/me')
        setState({ me, loading: false })
      } catch (err) {
        setState({ me: { authenticated: false, error: String(err.message || err) }, loading: false })
      }
    }

    function clientPasskeyReady() {
      return typeof window !== 'undefined'
        && window.isSecureContext
        && typeof window.PublicKeyCredential !== 'undefined'
    }

    function base64URLToBuffer(base64URLString) {
      const base64 = String(base64URLString).replace(/-/g, '+').replace(/_/g, '/')
      const pad = base64.length % 4
      const padded = pad ? base64 + '='.repeat(4 - pad) : base64
      const str = atob(padded)
      const buffer = new ArrayBuffer(str.length)
      const view = new Uint8Array(buffer)
      for (let i = 0; i < str.length; i++) view[i] = str.charCodeAt(i)
      return buffer
    }

    function bufferToBase64URL(buffer) {
      const bytes = new Uint8Array(buffer)
      let str = ''
      for (const b of bytes) str += String.fromCharCode(b)
      return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
    }

    function prepRegOptions(options) {
      return {
        ...options,
        challenge: base64URLToBuffer(options.challenge),
        user: { ...options.user, id: base64URLToBuffer(options.user.id) },
        excludeCredentials: (options.excludeCredentials || []).map((c) => ({
          ...c,
          id: base64URLToBuffer(c.id),
        })),
      }
    }

    function prepAuthOptions(options) {
      return {
        ...options,
        challenge: base64URLToBuffer(options.challenge),
        allowCredentials: (options.allowCredentials || []).map((c) => ({
          ...c,
          id: base64URLToBuffer(c.id),
        })),
      }
    }

    function credToJSON(cred) {
      if (!cred) return null
      const res = cred.response
      const out = {
        id: cred.id,
        rawId: bufferToBase64URL(cred.rawId),
        type: cred.type,
        response: {
          clientDataJSON: bufferToBase64URL(res.clientDataJSON),
        },
        clientExtensionResults: cred.getClientExtensionResults?.() || {},
      }
      if (res.attestationObject) out.response.attestationObject = bufferToBase64URL(res.attestationObject)
      if (res.authenticatorData) out.response.authenticatorData = bufferToBase64URL(res.authenticatorData)
      if (res.signature) out.response.signature = bufferToBase64URL(res.signature)
      if (res.userHandle) out.response.userHandle = bufferToBase64URL(res.userHandle)
      return out
    }

    async function passkeyLogin() {
      const options = await api('/auth/passkey/login/options', { method: 'POST', body: '{}' })
      const cred = await navigator.credentials.get({ publicKey: prepAuthOptions(options) })
      if (!cred) throw new Error('passkey cancelled')
      await api('/auth/passkey/login/verify', {
        method: 'POST',
        body: JSON.stringify(credToJSON(cred)),
      })
      await refreshMe()
    }

    async function passkeyRegister(name) {
      const options = await api('/auth/passkey/register/options', { method: 'POST', body: '{}' })
      const cred = await navigator.credentials.create({ publicKey: prepRegOptions(options) })
      if (!cred) throw new Error('passkey cancelled')
      const body = credToJSON(cred)
      if (name) body.name = name
      return api('/auth/passkey/register/verify', { method: 'POST', body: JSON.stringify(body) })
    }

    function useSharedState() {
      const [snap, setSnap] = React.useState({ ...state })
      React.useEffect(() => {
        listeners.add(setSnap)
        if (state.loading && !state.me) refreshMe()
        return () => listeners.delete(setSnap)
      }, [])
      return snap
    }

    function ensureStyle() {
      if (document.getElementById(STYLE_ID)) return
      const style = document.createElement('style')
      style.id = STYLE_ID
      style.textContent = `
[data-lha-overlay]{position:fixed;inset:0;z-index:120000;display:flex;align-items:center;justify-content:center;padding:24px;font-family:var(--dsw-font-family,-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif);color:var(--dsw-alias-label-primary,#0f1115)}
[data-lha-mask]{position:absolute;inset:0;background:var(--dsw-alias-bg-mask-1,rgba(0,0,0,.24));backdrop-filter:var(--dsw-mask-blur,blur(2px))}
[data-lha-dialog]{position:relative;z-index:1;display:flex;flex-direction:column;width:min(380px,100%);padding-bottom:24px;border:1px solid var(--dsw-alias-border-inverted);border-radius:24px;background:var(--dsw-alias-bg-layer-2);box-shadow:var(--dsw-shadow-lv3);overflow:hidden;animation:lha-rise .28s cubic-bezier(.22,1,.36,1)}
[data-lha-dialog][data-lha-setup]{width:min(420px,100%)}
@keyframes lha-rise{from{opacity:0;transform:translateY(10px) scale(.98)}to{opacity:1;transform:none}}
[data-lha-content]{padding:28px 24px 0;box-sizing:border-box}
[data-lha-wordmark]{font-size:12px;line-height:18px;font-weight:600;letter-spacing:.08em;color:var(--dsw-alias-label-tertiary);margin:0 0 16px}
[data-lha-title]{margin:0;font-size:20px;line-height:28px;font-weight:500;color:var(--dsw-alias-label-primary)}
[data-lha-desc]{margin:8px 0 0;font-size:14px;line-height:22px;color:var(--dsw-alias-label-secondary)}
[data-lha-body]{display:grid;gap:16px;margin-top:20px;padding:0 24px;box-sizing:border-box}
[data-lha-footer]{padding:0 24px;margin-top:20px}
[data-lha-field]{display:grid;gap:6px}
[data-lha-field] span{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary)}
[data-lha-field] input{box-sizing:border-box;width:100%;height:36px;border:1px solid var(--dsw-alias-border-l2);border-radius:12px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);padding:0 12px;font-size:14px;line-height:22px;font-family:inherit;transition:border-color .15s}
[data-lha-field] input:focus{outline:none;border-color:var(--dsw-alias-state-business-primary,var(--dsw-alias-button-primary-fill,#0f1115))}
[data-lha-btn]{display:inline-flex;align-items:center;justify-content:center;gap:4px;height:36px;padding:0 14px;border:none;border-radius:18px;font-size:14px;line-height:22px;font-weight:400;font-family:inherit;cursor:pointer;color:var(--dsw-alias-label-primary);background:transparent;transition:background .12s}
[data-lha-btn].primary{width:100%;background:var(--dsw-alias-button-primary-fill);color:var(--dsw-alias-label-primary-foreground)}
[data-lha-btn].primary:hover:not(:disabled){background:var(--dsw-alias-button-primary-hover)}
[data-lha-btn].outline{border:1px solid var(--dsw-alias-border-l2);background:transparent}
[data-lha-btn].outline:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover)}
[data-lha-btn].passkey{background:var(--dsw-alias-button-info-fill,var(--dsw-alias-button-primary-fill));color:var(--dsw-alias-label-primary-foreground)}
[data-lha-btn]:disabled{opacity:.4;cursor:not-allowed}
[data-lha-tabs]{display:flex;gap:4px;padding:4px;border-radius:12px;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-base)}
[data-lha-tabs] button{flex:1;border:0;background:transparent;border-radius:8px;padding:8px 10px;font-size:13px;line-height:18px;cursor:pointer;color:var(--dsw-alias-label-secondary);font-family:inherit}
[data-lha-tabs] button.active{background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary);font-weight:500;box-shadow:0 1px 2px rgba(0,0,0,.08)}
[data-lha-error]{padding:10px 12px;border-radius:12px;font-size:13px;line-height:20px;color:var(--dsw-alias-state-error-primary);background:color-mix(in srgb,var(--dsw-alias-state-error-primary) 10%,transparent);border:1px solid color-mix(in srgb,var(--dsw-alias-state-error-primary) 24%,transparent)}
[data-lha-warn]{padding:10px 12px;border-radius:12px;font-size:13px;line-height:20px;color:var(--dsw-alias-label-primary);background:var(--dsw-alias-interactive-bg-hover);border:1px solid var(--dsw-alias-border-l2)}
[data-lha-hint]{font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}
[data-lha-loading]{display:flex;align-items:center;gap:10px;font-size:14px;line-height:22px;color:var(--dsw-alias-label-secondary)}
[data-lha-spinner]{position:relative;width:20px;height:20px;border-radius:50%;border:2px solid var(--dsw-alias-border-l2);animation:lha-spin .8s linear infinite}
[data-lha-spinner]::after{content:'';position:absolute;inset:-2px;border-radius:inherit;background:conic-gradient(var(--dsw-alias-brand-primary,var(--dsw-alias-label-primary)) 72deg,transparent 0);-webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 2px),#000 0);mask:radial-gradient(farthest-side,transparent calc(100% - 2px),#000 0)}
@keyframes lha-spin{to{transform:rotate(360deg)}}
[data-lha-settings]{display:grid;gap:14px;padding:4px 0;max-width:720px}
[data-lha-settings] h3{margin:0;font-size:16px;font-weight:600}
[data-lha-settings] .lha-stat{font-size:28px;font-weight:700;color:var(--dsw-alias-state-business-primary)}
[data-lha-settings] .lha-section{border:1px solid var(--dsw-alias-border-l2);border-radius:12px;padding:14px;display:grid;gap:10px}
[data-lha-settings] .lha-row{display:flex;gap:8px;align-items:center;justify-content:space-between;font-size:13px}
[data-lha-settings] .lha-mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}
[data-lha-settings] details summary{cursor:pointer;font-weight:600;font-size:13px}
[data-lha-settings] .lha-list{display:grid;gap:6px}
[data-lha-settings] input,[data-lha-settings] textarea{box-sizing:border-box;width:100%;border:1px solid var(--dsw-alias-border-l2);border-radius:12px;background:var(--dsw-alias-bg-base);color:inherit;padding:8px 10px;font-size:13px;font-family:inherit}
[data-lha-settings] button{border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-base);color:inherit;border-radius:18px;padding:8px 14px;font-size:13px;cursor:pointer;font-family:inherit}
[data-lha-settings] button.primary{border-color:transparent;background:var(--dsw-alias-button-primary-fill);color:var(--dsw-alias-label-primary-foreground)}
[data-lha-chip]{display:inline-flex;gap:6px;align-items:center;padding:5px 9px;font-size:12px;border:1px solid var(--dsw-alias-border-l2);border-radius:14px;background:var(--dsw-alias-bg-layer-2);cursor:pointer;font-family:inherit;color:var(--dsw-alias-label-primary)}
`
      document.head.appendChild(style)
    }

    function AuthOverlay({ setup, children }) {
      return jsxs('div', { 'data-lha-overlay': '', children: [
        jsx('div', { 'data-lha-mask': '' }),
        jsx('div', { 'data-lha-dialog': '', 'data-lha-setup': setup ? '' : undefined, children }),
      ] })
    }

    function NginxMisconfigCard({ info }) {
      const [snippet, setSnippet] = React.useState('')
      React.useEffect(() => {
        fetch(API + '/nginx/snippet', { credentials: 'same-origin' })
          .then((r) => r.json())
          .then((d) => setSnippet(d.snippet || ''))
          .catch(() => {})
      }, [])
      return jsxs('div', { 'data-lha-content': '', children: [
        jsx('p', { 'data-lha-wordmark': '', children: 'DEEPSEEK HARNESS' }),
        jsx('h2', { 'data-lha-title': '', children: 'Nginx 配置错误' }),
        jsx('p', { 'data-lha-desc': '', children: `Host: ${info.host || '—'}` }),
        jsxs('div', { 'data-lha-body': '', children: [
          jsx('div', { 'data-lha-error': '', children: info.message }),
          jsx('p', { 'data-lha-desc': '', children: '在修复前，DSH 无法正常使用（API 与 WebSocket 已阻断），以避免白名单被绕过。' }),
          snippet ? jsx('pre', { className: 'lha-mono', style: { whiteSpace: 'pre-wrap', margin: 0, fontSize: 12 }, children: snippet }) : null,
          jsx('p', { 'data-lha-desc': '', children: '修复后 reload Nginx，然后刷新此页面。' }),
        ] }),
      ] })
    }

    function LoginGate() {
      const snap = useSharedState()
      React.useEffect(ensureStyle, [])
      if (snap.loading) {
        return jsx(AuthOverlay, { children: jsxs('div', { 'data-lha-content': '', children: [
          jsxs('div', { 'data-lha-loading': '', children: [
            jsx('span', { 'data-lha-spinner': '' }),
            '正在检查访问控制…',
          ] }),
        ] }) })
      }
      if (snap.me?.nginxMisconfig?.misconfigured) {
        return jsx(AuthOverlay, { children: jsx(NginxMisconfigCard, { info: snap.me.nginxMisconfig }) })
      }
      if (!snap.me?.passwordConfigured) {
        return jsx(AuthOverlay, { setup: true, children: jsx(SetupCard, {}) })
      }
      if (!snap.me?.authenticated) {
        return jsx(AuthOverlay, { children: jsx(LoginCard, { me: snap.me }) })
      }
      return null
    }

    function SetupCard() {
      const [password, setPassword] = React.useState('')
      const [confirm, setConfirm] = React.useState('')
      const [busy, setBusy] = React.useState(false)
      const [err, setErr] = React.useState('')
      const pwdOk = password.length >= 8
      const confirmOk = confirm.length > 0 && password === confirm

      async function submit(ev) {
        ev.preventDefault()
        setBusy(true); setErr('')
        try {
          if (password.length < 8) throw new Error('密码至少 8 位')
          if (password !== confirm) throw new Error('两次密码不一致')
          await api('/auth/setup', { method: 'POST', body: JSON.stringify({ password }) })
          await refreshMe()
        } catch (e) { setErr(String(e.message || e)) }
        finally { setBusy(false) }
      }

      return jsxs('div', { 'data-lha-content': '', children: [
        jsx('p', { 'data-lha-wordmark': '', children: 'DEEPSEEK HARNESS' }),
        jsx('h2', { 'data-lha-title': '', children: '设置访问密码' }),
        jsx('p', { 'data-lha-desc': '', children: '首次使用需为本机 DSH 设置访问密码，用于保护 Web 界面与插件 API。' }),
        jsxs('form', { onSubmit: submit, children: [
          jsxs('div', { 'data-lha-body': '', children: [
            err ? jsx('div', { 'data-lha-error': '', children: err }) : null,
            jsxs('div', { 'data-lha-field': '', children: [
              jsx('span', { children: '密码' }),
              jsx('input', { type: 'password', value: password, autoFocus: true, onChange: (e) => setPassword(e.target.value), autoComplete: 'new-password', placeholder: '至少 8 位' }),
            ] }),
            jsxs('div', { 'data-lha-field': '', children: [
              jsx('span', { children: '确认密码' }),
              jsx('input', { type: 'password', value: confirm, onChange: (e) => setConfirm(e.target.value), autoComplete: 'new-password', placeholder: '再次输入' }),
            ] }),
            jsx('p', { 'data-lha-hint': '', children: pwdOk ? (confirmOk ? '密码符合要求，可以提交' : '请确认两次密码一致') : '密码至少 8 位' }),
          ] }),
          jsx('div', { 'data-lha-footer': '', children: jsx('button', { type: 'submit', 'data-lha-btn': '', className: 'primary', disabled: busy || !pwdOk || !confirmOk, children: busy ? '设置中…' : '设置密码并继续' }) }),
        ] }),
      ] })
    }

    function LoginCard({ me }) {
      const [mode, setMode] = React.useState('password')
      const [password, setPassword] = React.useState('')
      const [busy, setBusy] = React.useState(false)
      const [err, setErr] = React.useState('')
      const passkey = me?.passkey || {}
      const canPasskey = clientPasskeyReady() && passkey.available
      const hasPasskeys = (passkey.count || 0) > 0

      React.useEffect(() => {
        if (canPasskey && hasPasskeys) setMode('passkey')
      }, [canPasskey, hasPasskeys])

      async function submitPassword(ev) {
        ev.preventDefault()
        setBusy(true); setErr('')
        try {
          await api('/auth/login', { method: 'POST', body: JSON.stringify({ password }) })
          await refreshMe()
        } catch (e) { setErr(String(e.message || e)) }
        finally { setBusy(false) }
      }

      async function submitPasskey(ev) {
        ev?.preventDefault?.()
        setBusy(true); setErr('')
        try {
          await passkeyLogin()
        } catch (e) { setErr(String(e.message || e)) }
        finally { setBusy(false) }
      }

      return jsxs('div', { 'data-lha-content': '', children: [
        jsx('p', { 'data-lha-wordmark': '', children: 'DEEPSEEK HARNESS' }),
        jsx('h2', { 'data-lha-title': '', children: '登录' }),
        jsx('p', { 'data-lha-desc': '', children: '输入访问密码以继续使用 DSH。' }),
        jsxs('div', { 'data-lha-body': '', children: [
          me?.ip ? jsx('p', { 'data-lha-hint': '', children: `当前 IP：${me.ip}${me.whitelisted ? '（白名单）' : ''}` }) : null,
          !me?.whitelisted && me?.ip ? jsx('div', { 'data-lha-warn': '', children: '您的 IP 不在白名单，登录后请在设置中添加。' }) : null,
          !canPasskey && passkey.hint ? jsx('p', { 'data-lha-hint': '', children: passkey.hint }) : null,
          err ? jsx('div', { 'data-lha-error': '', children: err }) : null,
          canPasskey && hasPasskeys ? jsxs('div', { 'data-lha-tabs': '', children: [
            jsx('button', { type: 'button', className: mode === 'passkey' ? 'active' : '', onClick: () => setMode('passkey'), children: 'Passkey' }),
            jsx('button', { type: 'button', className: mode === 'password' ? 'active' : '', onClick: () => setMode('password'), children: '密码' }),
          ] }) : null,
          mode === 'passkey' && canPasskey && hasPasskeys ? jsxs(React.Fragment, { children: [
            jsx('p', { 'data-lha-desc': '', style: { marginTop: 0 }, children: '使用本机指纹、面容或安全密钥登录。' }),
            jsx('button', { type: 'button', 'data-lha-btn': '', className: 'passkey', disabled: busy, onClick: submitPasskey, children: busy ? '验证中…' : '使用 Passkey 登录' }),
          ] }) : null,
          mode === 'password' || !hasPasskeys ? jsxs('form', { onSubmit: submitPassword, children: [
            jsxs('div', { 'data-lha-field': '', children: [
              jsx('span', { children: '密码' }),
              jsx('input', { type: 'password', value: password, autoFocus: mode === 'password' || !hasPasskeys, onChange: (e) => setPassword(e.target.value), autoComplete: 'current-password' }),
            ] }),
            jsx('div', { 'data-lha-footer': '', style: { padding: 0, marginTop: 16 }, children: jsx('button', { type: 'submit', 'data-lha-btn': '', className: 'primary', disabled: busy || !password, children: busy ? '登录中…' : '继续' }) }),
          ] }) : null,
        ] }),
      ] })
    }

    function GateSettingsSection() {
      const [config, setConfig] = React.useState(null)
      const [stats, setStats] = React.useState(null)
      const [visitors, setVisitors] = React.useState([])
      const [status, setStatus] = React.useState(null)
      const [nginx, setNginx] = React.useState('')
      const [keys, setKeys] = React.useState([])
      const [passkeys, setPasskeys] = React.useState([])
      const [passkeyInfo, setPasskeyInfo] = React.useState(null)
      const [newKey, setNewKey] = React.useState('')
      const [newPassword, setNewPassword] = React.useState('')
      const [excludeInput, setExcludeInput] = React.useState('')
      const [peers, setPeers] = React.useState([])
      const [apiTokens, setApiTokens] = React.useState([])
      const [pairingCode, setPairingCode] = React.useState('')
      const [pairExpires, setPairExpires] = React.useState('')
      const [connectUrl, setConnectUrl] = React.useState('')
      const [connectCode, setConnectCode] = React.useState('')
      const [connectName, setConnectName] = React.useState('')
      const [newTokenName, setNewTokenName] = React.useState('')
      const [issuedToken, setIssuedToken] = React.useState('')
      const [msg, setMsg] = React.useState('')
      const [err, setErr] = React.useState('')
      const [busy, setBusy] = React.useState(false)

      async function load() {
        setErr('')
        try {
          const stat = await api('/status')
          setStatus(stat)
          if (stat.nginxMisconfig?.misconfigured) return
          const [cfg, st, vis, pk, peerRes, tokenRes] = await Promise.all([
            api('/config'),
            api('/security-visitors/stats'),
            api('/security-visitors'),
            api('/passkeys'),
            api('/peers'),
            api('/api-tokens'),
          ])
          setConfig(cfg)
          setStats(st)
          setVisitors(vis.visitors || [])
          setPasskeys(pk.passkeys || [])
          setPasskeyInfo(pk.passkey || null)
          setPeers(peerRes.peers || [])
          setApiTokens(tokenRes.tokens || [])
          if (!keys.length) {
            try {
              const k = await api('/keys')
              setKeys(k.keys || [])
            } catch { /* optional */ }
          }
        } catch (e) { setErr(String(e.message || e)) }
      }

      React.useEffect(() => { ensureStyle(); load() }, [])

      async function save(patch) {
        setBusy(true); setMsg(''); setErr('')
        try {
          const body = { ...patch }
          if (newPassword) body.password = newPassword
          const res = await api('/config', { method: 'PUT', body: JSON.stringify(body) })
          setConfig(res.config)
          setNewPassword('')
          setMsg('已保存')
          await load()
        } catch (e) { setErr(String(e.message || e)) }
        finally { setBusy(false) }
      }

      async function addIp(listKey, ip) {
        const list = [...(config[listKey] || [])]
        if (!list.includes(ip)) list.push(ip)
        await save({ [listKey]: list })
      }

      async function removeIp(listKey, ip) {
        await save({ [listKey]: (config[listKey] || []).filter((x) => x !== ip) })
      }

      async function visitorAction(ip, action) {
        await api(`/security-visitors/${encodeURIComponent(ip)}/${action}`, { method: 'POST', body: '{}' })
        await load()
      }

      async function loadNginx() {
        const res = await api('/nginx/snippet')
        setNginx(res.snippet || '')
      }

      async function addPasskey() {
        setBusy(true); setErr('')
        try {
          await passkeyRegister('本机 Passkey')
          setMsg('Passkey 已添加')
          await load()
        } catch (e) { setErr(String(e.message || e)) }
        finally { setBusy(false) }
      }

      async function removePasskey(id) {
        await api(`/passkeys/${encodeURIComponent(id)}`, { method: 'DELETE' })
        await load()
      }

      async function addExclude() {
        const path = String(excludeInput || '').trim()
        if (!path) return
        if (!window.confirm(`将 ${path} 设为显式暴露（跳过登录门禁，公网有风险）。继续？`)) return
        const next = [...(config?.routePolicy?.excludePrefixes || [])]
        if (!next.includes(path)) next.push(path)
        await save({ routePolicy: { excludePrefixes: next } })
        setExcludeInput('')
      }

      async function removeExclude(path) {
        const next = (config?.routePolicy?.excludePrefixes || []).filter((p) => p !== path)
        await save({ routePolicy: { excludePrefixes: next } })
      }

      async function createPairingCode() {
        setBusy(true); setErr('')
        try {
          const res = await api('/peers/pairing-code', { method: 'POST', body: '{}' })
          setPairingCode(res.code || '')
          setPairExpires(res.expiresAt || '')
          setMsg('配对码已生成（10 分钟内有效）')
        } catch (e) { setErr(String(e.message || e)) }
        finally { setBusy(false) }
      }

      async function connectPeer() {
        setBusy(true); setErr('')
        try {
          await api('/peers/connect', {
            method: 'POST',
            body: JSON.stringify({
              remoteBaseUrl: connectUrl,
              code: connectCode,
              name: connectName || connectUrl,
            }),
          })
          setConnectCode('')
          setMsg('对等设备已连接')
          await load()
        } catch (e) { setErr(String(e.message || e)) }
        finally { setBusy(false) }
      }

      async function removePeer(id) {
        await api(`/peers/${encodeURIComponent(id)}`, { method: 'DELETE' })
        await load()
      }

      async function createApiToken() {
        setBusy(true); setErr(''); setIssuedToken('')
        try {
          const res = await api('/api-tokens', { method: 'POST', body: JSON.stringify({ name: newTokenName || 'API Token' }) })
          setIssuedToken(res.token?.token || '')
          setNewTokenName('')
          setMsg('API 密钥已创建（仅显示一次）')
          await load()
        } catch (e) { setErr(String(e.message || e)) }
        finally { setBusy(false) }
      }

      async function revokeApiToken(id) {
        await api(`/api-tokens/${encodeURIComponent(id)}`, { method: 'DELETE' })
        await load()
      }

      async function addKey() {
        await api('/keys', { method: 'POST', body: JSON.stringify({ publicKey: newKey }) })
        setNewKey('')
        const res = await api('/keys')
        setKeys(res.keys || [])
      }

      if (!config) {
        if (status?.nginxMisconfig?.misconfigured) {
          return jsxs('div', { 'data-lha-settings': '', children: [
            jsx('h3', { children: '访问控制' }),
            jsx(NginxMisconfigCard, { info: status.nginxMisconfig }),
          ] })
        }
        return jsx('div', { 'data-lha-settings': '', children: err || '加载中…' })
      }

      const currentIp = status?.ip || '—'

      return jsxs('div', { 'data-lha-settings': '', children: [
        jsx('h3', { children: '访问控制' }),
        status?.nginxMisconfig?.misconfigured ? jsx('div', { className: 'lha-error', children: status.nginxMisconfig.message }) : null,
        msg ? jsx('div', { style: { color: '#166534', fontSize: 13 }, children: msg }) : null,
        err ? jsx('div', { className: 'lha-error', children: err }) : null,
        jsxs('div', { className: 'lha-section', children: [
          jsx('div', { children: '已阻挡非法访问' }),
          jsx('div', { className: 'lha-stat', children: stats?.totalIllegalBlocked ?? 0 }),
          jsxs('div', { className: 'lha-row', children: [
            jsx('span', { children: `您当前 IP：${currentIp}` }),
            jsxs('div', { className: 'lha-actions', children: [
              jsx('button', { type: 'button', disabled: busy, onClick: () => addIp('allow', currentIp), children: '加白名单' }),
              jsx('button', { type: 'button', disabled: busy, onClick: () => addIp('deny', currentIp), children: '加黑名单' }),
            ] }),
          ] }),
        ] }),
        jsxs('div', { className: 'lha-section', children: [
          jsx('strong', { children: 'Passkey' }),
          passkeyInfo && !passkeyInfo.available ? jsx('div', { className: 'lha-sub', children: passkeyInfo.hint }) : null,
          clientPasskeyReady() && passkeyInfo?.available ? jsx('button', { type: 'button', className: 'passkey', disabled: busy, onClick: addPasskey, children: '添加本机 Passkey' }) : null,
          jsx('div', { className: 'lha-list', children: passkeys.map((p) => jsxs('div', { className: 'lha-row', key: p.id, children: [
            jsx('span', { children: `${p.name} · ${new Date(p.createdAt).toLocaleDateString()}` }),
            jsx('button', { type: 'button', onClick: () => removePasskey(p.id), children: '删除' }),
          ] }) ) }),
          jsx('div', { className: 'lha-sub', children: 'Passkey 用于浏览器一键登录（需 HTTPS 或 localhost）。' }),
        ] }),
        jsxs('div', { className: 'lha-section', children: [
          jsx('strong', { children: '访问密码' }),
          jsxs('label', { children: ['新密码（留空不改）', jsx('input', { type: 'password', value: newPassword, onChange: (e) => setNewPassword(e.target.value) })] }),
          jsx('button', { type: 'button', className: 'primary', disabled: busy, onClick: () => save({}), children: '保存密码' }),
        ] }),
        jsxs('div', { className: 'lha-section', children: [
          jsxs('div', { className: 'lha-row', children: [
            jsx('strong', { children: 'IP 白名单' }),
            jsx('button', { type: 'button', disabled: busy, onClick: () => addIp('allow', currentIp), children: '+ 当前 IP' }),
          ] }),
          jsx('div', { className: 'lha-list', children: (config.allow || []).map((ip) => jsxs('div', { className: 'lha-row', key: ip, children: [
            jsx('span', { className: 'lha-mono', children: ip }),
            jsx('button', { type: 'button', onClick: () => removeIp('allow', ip), children: '删除' }),
          ] }) ) }),
        ] }),
        jsxs('div', { className: 'lha-section', children: [
          jsx('strong', { children: 'IP 黑名单' }),
          jsx('div', { className: 'lha-list', children: (config.deny || []).map((ip) => jsxs('div', { className: 'lha-row', key: ip, children: [
            jsx('span', { className: 'lha-mono', children: ip }),
            jsx('button', { type: 'button', onClick: () => removeIp('deny', ip), children: '删除' }),
          ] }) ) }),
        ] }),
        jsxs('div', { className: 'lha-section', children: [
          jsx('strong', { children: '最近可疑 IP' }),
          jsx('div', { className: 'lha-list', children: visitors.slice(0, 20).map((v) => jsxs('div', { className: 'lha-row', key: v.ip, children: [
            jsxs('span', { className: 'lha-mono', children: [`${v.ip} · ${v.eventCount}次 · ${v.lastReason}`] }),
            jsxs('div', { children: [
              jsx('button', { type: 'button', onClick: () => visitorAction(v.ip, 'allow'), children: '加白' }),
              ' ',
              jsx('button', { type: 'button', onClick: () => visitorAction(v.ip, 'deny'), children: '加黑' }),
              ' ',
              jsx('button', { type: 'button', onClick: () => visitorAction(v.ip, 'dismiss'), children: '忽略' }),
            ] }),
          ] }) ) }),
        ] }),
        jsxs('details', { children: [
          jsx('summary', { children: '第二台设备（SSH 密钥）' }),
          jsxs('div', { className: 'lha-section', style: { marginTop: 10 }, children: [
            jsx('div', { className: 'lha-sub', children: '粘贴 ssh-ed25519 公钥，登录页可用密钥 challenge 验签。' }),
            jsxs('label', { children: ['公钥', jsx('textarea', { rows: 3, value: newKey, onChange: (e) => setNewKey(e.target.value) })] }),
            jsx('button', { type: 'button', onClick: addKey, children: '添加公钥' }),
            jsx('div', { className: 'lha-list', children: keys.map((k) => jsx('div', { className: 'lha-mono', key: k.id, children: `${k.comment || k.id} (${k.fingerprint}…)` }) ) }),
          ] }),
        ] }),
        jsxs('details', { onToggle: (e) => { if (e.target.open && !nginx) loadNginx() }, children: [
          jsx('summary', { children: 'Nginx' }),
          jsxs('div', { className: 'lha-section', style: { marginTop: 10 }, children: [
            status?.proxy ? jsx('div', { className: 'lha-sub', children: `反代检测：${status.proxy.viaTrustedProxy ? '经信任代理' : '直连'}${status.proxy.hasForwardedHeaders ? '，有转发头' : ''}` }) : null,
            jsx('label', { children: [
              jsx('input', { type: 'checkbox', checked: !!config.nginxBasicAutoLogin, onChange: (e) => save({ nginxBasicAutoLogin: e.target.checked }) }),
              ' Nginx 已设 Basic 密码 → 免二次登录',
            ] }),
            nginx ? jsx('pre', { className: 'lha-mono', style: { whiteSpace: 'pre-wrap', margin: 0 }, children: nginx }) : jsx('button', { type: 'button', onClick: loadNginx, children: '加载配置片段' }),
          ] }),
        ] }),
        jsxs('details', { children: [
          jsx('summary', { children: '路由保护（默认全包）' }),
          jsxs('div', { className: 'lha-section', style: { marginTop: 10 }, children: [
            jsx('div', { className: 'lha-sub', children: '所有插件 API 默认需要登录。下方路径将跳过登录门禁（IP 限制仍生效）。' }),
            jsx('div', { className: 'lha-list', children: (config.routePolicy?.excludePrefixes || []).map((p) => jsxs('div', { className: 'lha-row', key: p, children: [
              jsx('span', { className: 'lha-mono', style: { color: '#b45309' }, children: p }),
              jsx('button', { type: 'button', onClick: () => removeExclude(p), children: '移除' }),
            ] }) ) }),
            jsxs('div', { className: 'lha-row', children: [
              jsx('input', { type: 'text', placeholder: '/pluginrepo', value: excludeInput, onChange: (e) => setExcludeInput(e.target.value) }),
              jsx('button', { type: 'button', disabled: busy, onClick: addExclude, children: '显式暴露' }),
            ] }),
          ] }),
        ] }),
        jsxs('details', { children: [
          jsx('summary', { children: '对等设备（跨机 Token）' }),
          jsxs('div', { className: 'lha-section', style: { marginTop: 10 }, children: [
            jsx('div', { className: 'lha-sub', children: '本机与其他 DSH 配对后，插件 fetch 将自动带 Token，无需各插件适配。' }),
            jsx('div', { className: 'lha-list', children: peers.map((p) => jsxs('div', { className: 'lha-row', key: p.id, children: [
              jsx('span', { children: `${p.name} · ${p.baseUrl}` }),
              jsx('button', { type: 'button', onClick: () => removePeer(p.id), children: '撤销' }),
            ] }) ) }),
            jsxs('div', { className: 'lha-sub', children: ['在本机生成配对码（给对方填写）：', jsx('button', { type: 'button', disabled: busy, onClick: createPairingCode, children: '生成配对码' })] }),
            pairingCode ? jsx('div', { className: 'lha-mono', children: `配对码：${pairingCode}（至 ${pairExpires ? new Date(pairExpires).toLocaleTimeString() : '—'}）` }) : null,
            jsx('div', { className: 'lha-sub', children: '连接对方设备：' }),
            jsx('input', { type: 'text', placeholder: '对方地址 https://vps.example.com', value: connectUrl, onChange: (e) => setConnectUrl(e.target.value) }),
            jsx('input', { type: 'text', placeholder: '对方配对码', value: connectCode, onChange: (e) => setConnectCode(e.target.value) }),
            jsx('input', { type: 'text', placeholder: '备注名（可选）', value: connectName, onChange: (e) => setConnectName(e.target.value) }),
            jsx('button', { type: 'button', disabled: busy, onClick: connectPeer, children: '连接' }),
          ] }),
        ] }),
        jsxs('details', { children: [
          jsx('summary', { children: 'API 密钥（脚本）' }),
          jsxs('div', { className: 'lha-section', style: { marginTop: 10 }, children: [
            jsx('div', { className: 'lha-list', children: apiTokens.map((t) => jsxs('div', { className: 'lha-row', key: t.id, children: [
              jsx('span', { children: `${t.name} · ${new Date(t.createdAt).toLocaleDateString()}` }),
              jsx('button', { type: 'button', onClick: () => revokeApiToken(t.id), children: '撤销' }),
            ] }) ) }),
            jsx('input', { type: 'text', placeholder: '密钥名称', value: newTokenName, onChange: (e) => setNewTokenName(e.target.value) }),
            jsx('button', { type: 'button', disabled: busy, onClick: createApiToken, children: '生成密钥' }),
            issuedToken ? jsx('div', { className: 'lha-mono', children: `密钥（仅显示一次）：${issuedToken}` }) : null,
          ] }),
        ] }),
        jsxs('details', { children: [
          jsx('summary', { children: '仅内网使用' }),
          jsxs('div', { className: 'lha-section', style: { marginTop: 10 }, children: [
            jsx('label', { children: [
              jsx('input', { type: 'checkbox', checked: !config.ipLimitEnabled, onChange: (e) => save({ ipLimitEnabled: !e.target.checked }) }),
              ' 关闭 IP 限制（仍要密码）',
            ] }),
          ] }),
        ] }),
      ] })
    }

    function HeaderChip() {
      const snap = useSharedState()
      React.useEffect(ensureStyle, [])
      if (!snap.me?.authenticated) return null
      return jsx('button', { 'data-lha-chip': '', type: 'button', onClick: async () => {
        await api('/auth/logout', { method: 'POST', body: '{}' })
        await refreshMe()
      }, children: '退出访问控制' })
    }

    function apply(ctx) {
      ensureStyle()
      ctx.effect(() => ctx.slots.inject('shell.overlay', () => ctx.slots.register({ name: 'shell.overlay', id: 'dsh-local-hanaccount-gate', order: -1000 }, LoginGate)), 'dsh-local-hanaccount: gate')
      ctx.effect(() => ctx.slots.inject('settings.section', () => ctx.slots.register({ name: 'settings.section', id: 'dsh-local-hanaccount-settings', order: 15, label: '访问控制' }, GateSettingsSection)), 'dsh-local-hanaccount: settings')
      ctx.effect(() => ctx.slots.inject('conversation.session.header.actions', () => ctx.slots.register({ name: 'conversation.session.header.actions', id: 'dsh-local-hanaccount-chip', order: -10 }, HeaderChip)), 'dsh-local-hanaccount: chip')
      refreshMe()
    }

    exports.apply = apply
    exports.inject = ['slots']
    return module.exports
  },
})
