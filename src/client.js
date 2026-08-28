window.__ModuleLoader__.load({
  id: 'dsh-local-hanaccount',
  factory: (require) => {
    const module = { exports: {} }
    const exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' })

    const React = require('react')
    const { jsx, jsxs } = require('react/jsx-runtime')

    const API = '/dsh-local-hanaccount/api'
    const STYLE_ID = 'dsh-local-hanaccount-css-v12'

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

    async function refreshMe(opts) {
      const quiet = !!(opts && opts.quiet) || !!(state.me && state.me.authenticated)
      if (!quiet) setState({ loading: true })
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
      if (typeof document === 'undefined') return
      let el = document.getElementById(STYLE_ID)
      if (!el) {
        el = document.createElement('style')
        el.id = STYLE_ID
        document.head.appendChild(el)
      }
      el.textContent = `
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
[data-lha-field] input:focus{outline:none;border-color:var(--dsw-alias-brand-primary,var(--dsw-alias-button-primary-fill))}
[data-lha-btn]{display:inline-flex;align-items:center;justify-content:center;gap:4px;height:36px;padding:0 14px;border:none;border-radius:18px;font-size:14px;line-height:22px;font-weight:400;font-family:inherit;cursor:pointer;color:var(--dsw-alias-label-primary);background:transparent;transition:background .12s}
[data-lha-btn].primary{width:100%;background:var(--dsw-alias-button-primary-fill);color:var(--dsw-alias-label-primary-foreground)}
[data-lha-btn].primary:hover:not(:disabled){background:var(--dsw-alias-button-primary-hover)}
[data-lha-btn].outline{border:1px solid var(--dsw-alias-border-l2);background:transparent}
[data-lha-btn].outline:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover)}
[data-lha-btn].passkey{background:var(--dsw-alias-button-info-fill,var(--dsw-alias-button-primary-fill));color:var(--dsw-alias-label-primary-foreground)}
[data-lha-btn]:disabled{opacity:.4;cursor:default}
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
.dsh-lha-root{overscroll-behavior:contain;contain:layout style;display:flex;flex-direction:column;gap:14px;max-width:720px;color:var(--dsw-alias-label-primary);font-family:var(--dsw-font-family,inherit);font-size:14px;line-height:22px}
.dsh-lha-heading{margin:0;font-size:18px;line-height:26px;font-weight:600;color:var(--dsw-alias-label-primary)}
.dsh-lha-banner{display:flex;align-items:flex-start;gap:8px;padding:8px 10px;border-radius:8px;font-size:13px;line-height:20px;border:1px solid transparent}
.dsh-lha-banner--ok{color:var(--dsw-alias-state-success-primary);background:color-mix(in srgb,var(--dsw-alias-state-success-primary) 8%,transparent);border-color:color-mix(in srgb,var(--dsw-alias-state-success-primary) 25%,transparent)}
.dsh-lha-banner--error{color:var(--dsw-alias-state-error-primary);background:color-mix(in srgb,var(--dsw-alias-state-error-primary) 8%,transparent);border-color:color-mix(in srgb,var(--dsw-alias-state-error-primary) 25%,transparent)}
.dsh-lha-panel{padding:12px 14px;border:1px solid var(--dsw-alias-border-l2);border-radius:12px;background:var(--dsw-alias-bg-layer-2);display:flex;flex-direction:column;gap:10px}
.dsh-lha-panel__head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;flex-wrap:wrap}
.dsh-lha-block__title{margin:0;font-size:14px;line-height:22px;font-weight:500;color:var(--dsw-alias-label-primary)}
.dsh-lha-count{font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}
.dsh-lha-stat{font-size:28px;font-weight:600;line-height:1.1;color:var(--dsw-alias-label-primary)}
.dsh-lha-subcard{padding:10px 12px;border:1px solid var(--dsw-alias-border-l2);border-radius:10px;background:var(--dsw-alias-bg-layer-1);display:flex;flex-direction:column;gap:8px}
.dsh-lha-subcard__row{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}
.dsh-lha-tabs{display:flex;align-items:flex-end;gap:22px;border-bottom:1px solid var(--dsw-alias-border-l2);margin-bottom:2px}
.dsh-lha-tab-btn{position:relative;border:0;padding:7px 1px 9px;margin:0;background:transparent;color:var(--dsw-alias-label-tertiary);font:inherit;font-size:13px;line-height:20px;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
.dsh-lha-tab-btn:hover,.dsh-lha-tab-btn[data-active=true]{color:var(--dsw-alias-label-primary)}
.dsh-lha-tab-btn[data-active=true]::after{position:absolute;right:0;bottom:-1px;left:0;height:2px;border-radius:2px 2px 0 0;background:var(--dsw-alias-label-primary);content:''}
.dsh-lha-tab-pane{display:none;flex-direction:column;gap:10px}
.dsh-lha-tab-pane.is-active{display:flex}
.dsh-lha-list{display:flex;flex-direction:column;gap:6px;margin:0;padding:0;list-style:none}
.dsh-lha-row{box-sizing:border-box;display:flex;align-items:flex-start;gap:8px;padding:8px 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:10px;background:var(--dsw-alias-bg-layer-1);transition:border-color 120ms ease,background 120ms ease}
.dsh-lha-row:hover{border-color:color-mix(in srgb,var(--dsw-alias-border-l2) 60%,var(--dsw-alias-label-tertiary))}
.dsh-lha-row.is-current{border-color:color-mix(in srgb,var(--dsw-alias-brand-primary) 35%,var(--dsw-alias-border-l2))}
.dsh-lha-row__body{flex:1;min-width:0;display:flex;flex-wrap:wrap;align-items:center;gap:6px}
.dsh-lha-row__acts{display:flex;align-items:center;gap:4px;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end}
.dsh-lha-row__name{font-weight:500;font-size:14px;line-height:22px;min-width:0}
.dsh-lha-scroll{max-height:min(280px,40vh);overflow-y:auto;padding-right:2px;scrollbar-width:thin}
.dsh-lha-scroll::-webkit-scrollbar{width:6px}
.dsh-lha-scroll::-webkit-scrollbar-thumb{border-radius:999px;background:var(--dsw-alias-border-l2)}
.dsh-lha-tags{display:flex;flex-wrap:wrap;gap:4px}
.dsh-lha-tag{flex:none;display:inline-flex;align-items:center;padding:1px 6px;border:1px solid var(--dsw-alias-border-l2);border-radius:4px;font-size:11px;line-height:16px;font-weight:500;color:var(--dsw-alias-label-secondary);background:var(--dsw-alias-bg-module-platform);white-space:nowrap}
.dsh-lha-tag--success{color:var(--dsw-alias-state-success-primary);border-color:color-mix(in srgb,var(--dsw-alias-state-success-primary) 35%,transparent);background:color-mix(in srgb,var(--dsw-alias-state-success-primary) 8%,transparent)}
.dsh-lha-tag--danger{color:var(--dsw-alias-state-error-primary);border-color:color-mix(in srgb,var(--dsw-alias-state-error-primary) 35%,transparent);background:color-mix(in srgb,var(--dsw-alias-state-error-primary) 8%,transparent)}
.dsh-lha-tag--warn{color:var(--dsw-alias-state-warn-label,#d97706);border-color:color-mix(in srgb,var(--dsw-alias-state-warn-label,#d97706) 35%,transparent);background:color-mix(in srgb,var(--dsw-alias-state-warn-label,#d97706) 10%,transparent)}
.dsh-lha-tag--muted{color:var(--dsw-alias-label-tertiary);background:transparent;border-color:var(--dsw-alias-border-l2)}
.dsh-lha-btn{box-sizing:border-box;display:inline-flex;align-items:center;justify-content:center;gap:4px;height:36px;padding:0 14px;border:none;border-radius:18px;font:inherit;font-size:14px;line-height:22px;cursor:pointer;white-space:nowrap;background:transparent;color:var(--dsw-alias-label-primary)}
.dsh-lha-btn--primary{background:var(--dsw-alias-button-primary-fill);color:var(--dsw-alias-label-primary-foreground)}
.dsh-lha-btn--primary:hover:not(:disabled){background:var(--dsw-alias-button-primary-hover)}
.dsh-lha-btn--outline{border:1px solid var(--dsw-alias-border-l2)}
.dsh-lha-btn--outline:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover-solid,var(--dsw-alias-interactive-bg-hover))}
.dsh-lha-btn--sm{height:28px;padding:0 10px;border-radius:14px;font-size:12px;line-height:18px}
.dsh-lha-btn.is-danger{color:var(--dsw-alias-state-error-primary)}
.dsh-lha-btn.is-danger:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover-danger)}
.dsh-lha-btn.is-success{color:var(--dsw-alias-state-success-primary)}
.dsh-lha-btn.is-success:hover:not(:disabled){background:color-mix(in srgb,var(--dsw-alias-state-success-primary) 10%,transparent)}
.dsh-lha-btn:disabled{opacity:.4;cursor:default}
.dsh-lha-bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.dsh-lha-bar .dsh-lha-input{flex:1 1 120px}
.dsh-lha-input{box-sizing:border-box;height:32px;padding:0 10px;font:inherit;font-size:14px;line-height:22px;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);min-width:0;width:100%}
.dsh-lha-input:focus{outline:none;border-color:var(--dsw-alias-brand-primary)}
.dsh-lha-input::placeholder{color:var(--dsw-alias-label-dimmed)}
.dsh-lha-input.is-valid{border-color:color-mix(in srgb,var(--dsw-alias-state-success-primary) 45%,var(--dsw-alias-border-l2))}
.dsh-lha-input.is-invalid{border-color:color-mix(in srgb,var(--dsw-alias-state-error-primary) 45%,var(--dsw-alias-border-l2))}
.dsh-lha-textarea{box-sizing:border-box;width:100%;min-height:72px;padding:8px 10px;font:inherit;font-size:14px;line-height:22px;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);resize:vertical}
.dsh-lha-textarea:focus{outline:none;border-color:var(--dsw-alias-brand-primary)}
.dsh-lha-field{display:grid;gap:6px;font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary)}
.dsh-lha-checklbl{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:8px 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-bg-layer-1);cursor:pointer;font-size:13px;line-height:20px;color:var(--dsw-alias-label-primary)}
.dsh-lha-checklbl input{width:16px;height:16px;margin:0;accent-color:var(--dsw-alias-brand-primary);flex-shrink:0}
.dsh-lha-stack{display:flex;flex-direction:column;gap:8px}
.dsh-lha-empty{margin:0;text-align:center;padding:14px 8px;color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:20px;border:1px dashed var(--dsw-alias-border-l2);border-radius:10px}
.dsh-lha-mono{font-family:var(--dsw-font-family-code,var(--dsw-font-family,monospace));font-size:12px;line-height:18px;word-break:break-all;color:var(--dsw-alias-label-secondary)}
.dsh-lha-pre{margin:0;padding:10px 12px;border-radius:8px;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-1);font-family:var(--dsw-font-family-code,var(--dsw-font-family,monospace));font-size:11px;line-height:18px;white-space:pre-wrap;color:var(--dsw-alias-label-secondary)}
.dsh-lha-collapse{border:1px solid var(--dsw-alias-border-l2);border-radius:12px;background:var(--dsw-alias-bg-layer-2);overflow:hidden}
.dsh-lha-collapse>summary{cursor:pointer;list-style:none;padding:10px 12px;font-size:14px;line-height:22px;font-weight:500;color:var(--dsw-alias-label-primary);background:var(--dsw-alias-bg-module-platform);display:flex;align-items:center;justify-content:space-between;gap:8px}
.dsh-lha-collapse>summary::-webkit-details-marker{display:none}
.dsh-lha-collapse>summary::after{content:'▾';color:var(--dsw-alias-label-tertiary);font-weight:400;font-size:12px}
.dsh-lha-collapse[open]>summary::after{content:'▴'}
.dsh-lha-collapse__body{padding:10px 12px 12px;border-top:1px solid var(--dsw-alias-border-l2);display:flex;flex-direction:column;gap:10px}
.dsh-lha-collapse.is-guide{border-style:dashed}
.dsh-lha-guide-block{display:grid;gap:6px}
.dsh-lha-guide-block h4{margin:0;font-size:13px;line-height:20px;font-weight:500;color:var(--dsw-alias-label-primary)}
.dsh-lha-guide-block p{margin:0;font-size:12px;line-height:20px;color:var(--dsw-alias-label-secondary)}
.dsh-lha-guide-block ul{margin:0;padding-left:18px;font-size:12px;line-height:20px;color:var(--dsw-alias-label-secondary)}
.dsh-lha-guide-block li+li{margin-top:4px}
.dsh-lha-dialog-mask{position:fixed;inset:0;z-index:130000;background:var(--dsw-alias-bg-mask-1);display:flex;align-items:center;justify-content:center;padding:16px}
.dsh-lha-dialog{box-sizing:border-box;width:min(400px,100%);padding:20px 24px;border-radius:16px;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-2);box-shadow:var(--dsw-shadow-lv3);display:grid;gap:10px;color:var(--dsw-alias-label-primary)}
.dsh-lha-dialog h4{margin:0;font-size:16px;line-height:24px;font-weight:500}
.dsh-lha-dialog p{margin:0;font-size:14px;line-height:22px;color:var(--dsw-alias-label-secondary);white-space:pre-wrap}
.dsh-lha-dialog__foot{display:flex;justify-content:flex-end;gap:8px;flex-wrap:wrap}
[data-lha-chip]{display:inline-flex;gap:6px;align-items:center;padding:5px 9px;font-size:12px;border:1px solid var(--dsw-alias-border-l2);border-radius:14px;background:var(--dsw-alias-bg-layer-2);cursor:pointer;font-family:inherit;color:var(--dsw-alias-label-primary)}
`
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
          snippet ? jsx('pre', { className: 'dsh-lha-pre', children: snippet }) : null,
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
      const [allowInput, setAllowInput] = React.useState('')
      const [denyInput, setDenyInput] = React.useState('')
      const [ipPanelTab, setIpPanelTab] = React.useState('allow')
      const [msg, setMsg] = React.useState('')
      const [err, setErr] = React.useState('')
      const [busy, setBusy] = React.useState(false)
      const [confirm, setConfirm] = React.useState(null)
      // confirm: { title, body, run }

      function askConfirm(spec) { setConfirm(spec) }

      function looksLikeIpOrCidr(raw) {
        const s = String(raw || '').trim()
        if (!s || s === '—' || s === '-') return false
        if (s.includes('/')) {
          const [base, bits] = s.split('/')
          if (!base || bits === '' || bits == null) return false
          const n = Number(bits)
          if (!Number.isInteger(n) || n < 0 || n > 32) return false
          return /^\d{1,3}(\.\d{1,3}){3}$/.test(base)
        }
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return true
        if (s.includes(':')) return true
        return false
      }

      function isLoopbackEntry(entry) {
        const s = String(entry || '').trim()
        return s === '127.0.0.1' || s === '::1'
      }

      function listHasExact(list, entry) {
        const t = String(entry || '').trim()
        return (list || []).some((x) => String(x).trim() === t)
      }

      function sortIpList(list, listKey) {
        const rows = [...(list || [])]
        rows.sort((a, b) => {
          const score = (ip) => {
            if (ip === currentIp) return 0
            if (listKey === 'allow' && isLoopbackEntry(ip)) return 1
            return 2
          }
          const diff = score(a) - score(b)
          if (diff !== 0) return diff
          return String(a).localeCompare(String(b))
        })
        return rows
      }

      function inputValidClass(raw) {
        const s = String(raw || '').trim()
        if (!s) return ''
        return looksLikeIpOrCidr(s) ? 'is-valid' : 'is-invalid'
      }

      function renderIpListItem(listKey, ip) {
        const isAllow = listKey === 'allow'
        const isCurrent = ip === currentIp
        const reserved = isAllow && isLoopbackEntry(ip)
        const inOther = isAllow ? listHasExact(config.deny, ip) : listHasExact(config.allow, ip)
        return jsxs('div', {
          className: `dsh-lha-row${isCurrent ? ' is-current' : ''}${reserved ? ' is-reserved' : ''}`,
          key: ip,
          children: [
            jsxs('div', { className: 'dsh-lha-row__body', children: [
              jsx('span', { className: 'dsh-lha-mono', children: ip }),
              ip.includes('/') ? jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--muted', children: 'CIDR' }) : null,
              isCurrent ? jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--success', children: '当前' }) : null,
              reserved ? jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--muted', children: '系统保留' }) : null,
              inOther ? jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--warn', children: '冲突' }) : null,
            ] }),
            jsxs('div', { className: 'dsh-lha-row__acts', children: [
              reserved ? null : (isAllow
                ? jsx('button', {
                  type: 'button',
                  className: 'dsh-lha-btn dsh-lha-btn--outline dsh-lha-btn--sm is-danger',
                  disabled: busy || isLoopbackEntry(ip),
                  title: '移到黑名单',
                  onClick: () => addIp('deny', ip),
                  children: '加黑',
                })
                : jsx('button', {
                  type: 'button',
                  className: 'dsh-lha-btn dsh-lha-btn--outline dsh-lha-btn--sm is-success',
                  disabled: busy,
                  title: '移到白名单',
                  onClick: () => addIp('allow', ip),
                  children: '加白',
                })),
              reserved ? null : jsx('button', {
                type: 'button',
                className: 'dsh-lha-btn dsh-lha-btn--sm',
                disabled: busy,
                title: '从名单移除',
                onClick: () => removeIp(listKey, ip),
                children: '移除',
              }),
            ] }),
          ],
        })
      }

      function renderIpPanel(listKey, { active = true } = {}) {
        const isAllow = listKey === 'allow'
        const list = sortIpList(config[listKey], listKey)
        const input = isAllow ? allowInput : denyInput
        const setInput = isAllow ? setAllowInput : setDenyInput
        const clearKey = isAllow ? 'allow' : 'deny'
        const placeholder = 'IP 或 CIDR'
        const emptyText = '暂无'
        const canAddCurrent = isAllow
          ? currentIpOk && !allowExact
          : currentIpOk && !denyExact && !isLoopback
        const inputCls = inputValidClass(input)
        return jsxs('div', {
          className: `dsh-lha-tab-pane${active ? ' is-active' : ''}`,
          children: [
            jsxs('div', { className: 'dsh-lha-panel__head', children: [
              jsx('span', { className: 'dsh-lha-count', children: `${list.length} 条` }),
              jsx('button', {
                type: 'button',
                className: 'dsh-lha-btn dsh-lha-btn--outline dsh-lha-btn--sm',
                disabled: busy || !canAddCurrent,
                onClick: () => addIp(listKey, currentIp),
                children: '+ 当前 IP',
              }),
            ] }),
            list.length
              ? jsx('div', { className: 'dsh-lha-scroll', children: jsx('div', { className: 'dsh-lha-list', children: list.map((ip) => renderIpListItem(listKey, ip)) }) })
              : jsx('div', { className: 'dsh-lha-empty', children: emptyText }),
            jsxs('div', { className: 'dsh-lha-bar', children: [
              jsx('input', {
                type: 'text',
                className: `dsh-lha-input ${inputCls}`.trim(),
                placeholder,
                value: input,
                'aria-invalid': inputCls === 'is-invalid' ? 'true' : undefined,
                onChange: (e) => setInput(e.target.value),
                onKeyDown: (e) => { if (e.key === 'Enter') addIp(listKey, input, { clearInput: clearKey }) },
              }),
              jsx('button', {
                type: 'button',
                className: 'dsh-lha-btn dsh-lha-btn--primary dsh-lha-btn--sm',
                disabled: busy || !input.trim() || inputCls === 'is-invalid',
                onClick: () => addIp(listKey, input, { clearInput: clearKey }),
                children: '添加',
              }),
            ] }),
          ],
        })
      }

      async function runConfirm() {
        if (!confirm || !confirm.run) return
        setBusy(true)
        try {
          await confirm.run()
          setConfirm(null)
        } catch (e) { setErr(String(e.message || e)) }
        finally { setBusy(false) }
      }

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

      async function addIp(listKey, raw, { clearInput } = {}) {
        const entry = String(raw || '').trim()
        if (!looksLikeIpOrCidr(entry)) {
          setErr('请输入有效 IP 或 IPv4 CIDR（如 192.168.1.0/24）')
          return
        }
        if (listKey === 'deny' && (entry === '127.0.0.1' || entry === '::1')) {
          setErr('不能拉黑本机回环地址（127.0.0.1 / ::1），否则无法访问 DSH')
          return
        }
        const allow = [...(config.allow || [])]
        const deny = [...(config.deny || [])]
        const run = async () => {
          const nextAllow = allow.filter((x) => x !== entry)
          const nextDeny = deny.filter((x) => x !== entry)
          if (listKey === 'allow') {
            if (!listHasExact(nextAllow, entry)) nextAllow.push(entry)
            await save({ allow: nextAllow, deny: nextDeny })
          } else {
            if (!listHasExact(nextDeny, entry)) nextDeny.push(entry)
            await save({ allow: nextAllow, deny: nextDeny })
          }
          if (clearInput === 'allow') setAllowInput('')
          if (clearInput === 'deny') setDenyInput('')
          setMsg(listKey === 'allow' ? `已加入白名单：${entry}` : `已加入黑名单：${entry}`)
        }
        if (listKey === 'deny' && entry === String(status?.ip || '').trim()) {
          askConfirm({
            title: '把当前 IP 加入黑名单？',
            body: `将把 ${entry} 加入黑名单。若开启 IP 限制，本机会立刻无法访问。`,
            run,
          })
          return
        }
        await run()
      }

      async function removeIp(listKey, ip) {
        if (listKey === 'allow' && isLoopbackEntry(ip)) {
          setErr('本机回环地址（127.0.0.1 / ::1）为系统保留，不能从白名单移除')
          return
        }
        const label = listKey === 'allow' ? '白名单' : '黑名单'
        askConfirm({
          title: `删除 ${label} IP？`,
          body: `将从${label}移除 ${ip}。`,
          run: async () => {
            const next = (config[listKey] || []).filter((x) => x !== ip)
            await save({ [listKey]: next })
            setMsg(`已从${label}移除 ${ip}`)
          },
        })
      }

      async function visitorAction(ip, action) {
        setBusy(true); setErr(''); setMsg('')
        try {
          await api(`/security-visitors/${encodeURIComponent(ip)}/${action}`, { method: 'POST', body: '{}' })
          if (action === 'allow') setMsg(`已加白：${ip}`)
          else if (action === 'deny') setMsg(`已加黑：${ip}`)
          await load()
        } catch (e) { setErr(String(e.message || e)) }
        finally { setBusy(false) }
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
        askConfirm({
          title: '删除 Passkey？',
          body: '删除后将无法用该 Passkey 登录。',
          run: async () => {
            await api(`/passkeys/${encodeURIComponent(id)}`, { method: 'DELETE' })
            await load()
          },
        })
      }

      async function addExclude() {
        const path = String(excludeInput || '').trim()
        if (!path) return
        askConfirm({
          title: '显式暴露路径？',
          body: `将 ${path} 设为显式暴露（跳过登录门禁，公网有风险）。`,
          run: async () => {
            const next = [...(config?.routePolicy?.excludePrefixes || [])]
            if (!next.includes(path)) next.push(path)
            await save({ routePolicy: { excludePrefixes: next } })
            setExcludeInput('')
          },
        })
      }

      async function removeExclude(path) {
        askConfirm({
          title: '移除暴露路径？',
          body: `将取消 ${path} 的显式暴露，之后访问需登录。`,
          run: async () => {
            const next = (config?.routePolicy?.excludePrefixes || []).filter((p) => p !== path)
            await save({ routePolicy: { excludePrefixes: next } })
          },
        })
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
        askConfirm({
          title: '撤销对等设备？',
          body: '撤销后跨机 Token 将失效，需重新配对。',
          run: async () => {
            await api(`/peers/${encodeURIComponent(id)}`, { method: 'DELETE' })
            await load()
          },
        })
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
        askConfirm({
          title: '撤销 API 密钥？',
          body: '撤销后使用该密钥的脚本将无法访问。',
          run: async () => {
            await api(`/api-tokens/${encodeURIComponent(id)}`, { method: 'DELETE' })
            await load()
          },
        })
      }

      async function addKey() {
        await api('/keys', { method: 'POST', body: JSON.stringify({ publicKey: newKey }) })
        setNewKey('')
        const res = await api('/keys')
        setKeys(res.keys || [])
      }

      if (!config) {
        if (status?.nginxMisconfig?.misconfigured) {
          return jsxs('div', { className: 'dsh-lha-root', children: [
            jsx('h2', { className: 'dsh-lha-heading', children: '访问控制' }),
            jsx(NginxMisconfigCard, { info: status.nginxMisconfig }),
          ] })
        }
        return jsx('div', { className: 'dsh-lha-root', children: err || '加载中…' })
      }

      const currentIp = status?.ip || ''
      const currentIpOk = looksLikeIpOrCidr(currentIp)
      const isLoopback = currentIp === '127.0.0.1' || currentIp === '::1'
      const allowExact = currentIpOk && listHasExact(config.allow, currentIp)
      const denyExact = currentIpOk && listHasExact(config.deny, currentIp)
      const ipLimitOn = !!config.ipLimitEnabled
      let ipStatusTag = null
      if (!currentIpOk) {
        ipStatusTag = jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--warn', children: 'IP 未知' })
      } else if (denyExact) {
        ipStatusTag = jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--danger', children: '在黑名单' })
      } else if (allowExact) {
        ipStatusTag = jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--success', children: '在白名单' })
      } else if (ipLimitOn) {
        ipStatusTag = jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--warn', children: '未进白名单' })
      } else {
        ipStatusTag = jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--muted', children: 'IP 限制已关' })
      }

      function renderSettingsGuide() {
        const proxyText = status?.proxy
          ? (status.proxy.viaTrustedProxy ? '经信任代理' : '直连') + (status.proxy.hasForwardedHeaders ? '，有 X-Real-IP / XFF' : '，无转发头')
          : '—'
        return jsxs('details', {
          className: 'dsh-lha-collapse is-guide',
          onToggle: (e) => { if (e.target.open && !nginx) loadNginx() },
          children: [
            jsx('summary', { children: '使用说明' }),
            jsxs('div', { className: 'dsh-lha-collapse__body', children: [
              jsxs('div', { className: 'dsh-lha-guide-block', children: [
                jsx('h4', { children: '概述' }),
                jsx('p', { children: '本插件为 DSH Web 提供访问门禁：IP 名单、登录密码、Passkey，以及可选的 Nginx 反代与脚本 API 密钥。所有插件 API 默认受保护。' }),
              ] }),
              jsxs('div', { className: 'dsh-lha-guide-block', children: [
                jsx('h4', { children: 'IP 限制与白黑名单' }),
                jsx('p', { children: ipLimitOn
                  ? '当前已开启 IP 限制：仅白名单内的 IP 可通过 IP 门禁；黑名单一律 403。关闭后仍需密码/Passkey，但不按名单拦截 IP。'
                  : '当前 IP 限制已关闭：不按名单拦截，但仍需密码或 Passkey 登录。' }),
                jsx('ul', { children: [
                  jsx('li', { children: '白名单：信任 IP 或 IPv4 CIDR（如 192.168.1.0/24），命中后直接过 IP 门禁。' }),
                  jsx('li', { children: '黑名单：禁止 IP/CIDR，命中返回 403。与白名单互斥，加黑会自动移出白名单。' }),
                  jsx('li', { children: '127.0.0.1 / ::1 为系统保留，不可拉黑，不建议从白名单删除。' }),
                  isLoopback ? jsx('li', { children: '当前识别为回环地址：若经 Nginx 从外网访问，必须在反代中设置 proxy_set_header X-Real-IP $remote_addr;，否则无法识别真实客户端 IP。' }) : null,
                ] }),
              ] }),
              jsxs('div', { className: 'dsh-lha-guide-block', children: [
                jsx('h4', { children: '可疑 IP' }),
                jsx('p', { children: '记录被 IP 门禁拦截或未登录访问的 IP（白名单 IP 不记录）。可对单条快速加白、加黑或忽略。' }),
              ] }),
              jsxs('div', { className: 'dsh-lha-guide-block', children: [
                jsx('h4', { children: 'Passkey 与访问密码' }),
                jsx('p', { children: '访问密码为浏览器登录主方式。Passkey 需在 HTTPS 或 localhost 下注册，用于指纹/面容一键登录。' }),
                passkeyInfo && !passkeyInfo.available && passkeyInfo.hint
                  ? jsx('p', { children: passkeyInfo.hint })
                  : null,
              ] }),
              jsxs('div', { className: 'dsh-lha-guide-block', children: [
                jsx('h4', { children: 'Nginx 反代' }),
                jsx('p', { children: '公网访问推荐：Nginx 监听 443，转发到本机 127.0.0.1:3080，并传递真实客户端 IP。' }),
                jsx('p', { children: `反代检测：${proxyText}` }),
                jsx('p', { children: '将下列 location 放入 server { } 块，修改域名与证书后执行 nginx -t && nginx -s reload。' }),
                nginx ? jsx('pre', { className: 'dsh-lha-pre', children: nginx }) : jsx('p', { children: '展开本说明时将自动加载配置片段；也可在上方 Nginx 区点击「加载配置片段」。' }),
                jsx('p', { children: '若 Nginx 已配置 HTTP Basic 认证，可勾选「Basic 免二次登录」：请求带 Authorization: Basic 时 DSH 不再弹出登录框（IP 限制仍生效）。' }),
              ] }),
              jsxs('div', { className: 'dsh-lha-guide-block', children: [
                jsx('h4', { children: 'API 密钥（脚本）' }),
                jsx('p', { children: '供 cron、CI、本机脚本调用 DSH API，等价于已登录会话。生成后明文仅显示一次，请立即保存。' }),
                jsx('pre', { className: 'dsh-lha-pre', children: 'curl -H "Authorization: Bearer <密钥>" https://your-dsh.example.com/api/...' }),
                jsx('p', { children: '仍受 IP 白名单约束；外网脚本需将运行机 IP 加入白名单，或经 Nginx 反代且 IP 在白名单内。' }),
              ] }),
              jsxs('div', { className: 'dsh-lha-guide-block', children: [
                jsx('h4', { children: '对等设备' }),
                jsx('p', { children: '两台 DSH 配对后，跨机请求自动携带 Peer Token，无需各插件单独适配。在一台生成配对码，另一台填写对方地址与配对码即可。' }),
              ] }),
              jsxs('div', { className: 'dsh-lha-guide-block', children: [
                jsx('h4', { children: '路由暴露' }),
                jsx('p', { children: '默认所有插件 API 需登录。显式暴露的路径跳过登录门禁，但 IP 限制仍生效。跨设备同步优先使用对等设备配对，不建议长期暴露 /pluginrepo。' }),
              ] }),
              jsxs('div', { className: 'dsh-lha-guide-block', children: [
                jsx('h4', { children: 'SSH 密钥' }),
                jsx('p', { children: '粘贴 ssh-ed25519 公钥后，可通过 challenge/verify 流程在无浏览器环境下验签登录（见插件 API）。' }),
              ] }),
            ] }),
          ],
        })
      }

      return jsxs('div', { className: 'dsh-lha-root', children: [
        jsx('h2', { className: 'dsh-lha-heading', children: '访问控制' }),
        status?.nginxMisconfig?.misconfigured ? jsx('div', { className: 'dsh-lha-banner dsh-lha-banner--error', children: status.nginxMisconfig.message }) : null,
        msg ? jsx('div', { className: 'dsh-lha-banner dsh-lha-banner--ok', children: msg }) : null,
        err ? jsx('div', { className: 'dsh-lha-banner dsh-lha-banner--error', children: err }) : null,
        jsxs('div', { className: 'dsh-lha-panel', children: [
          jsxs('div', { className: 'dsh-lha-panel__head', children: [
            jsxs('div', { children: [
              jsx('p', { className: 'dsh-lha-count', children: '已阻挡' }),
              jsx('div', { className: 'dsh-lha-stat', children: stats?.totalIllegalBlocked ?? 0 }),
            ] }),
            ipStatusTag,
          ] }),
          jsxs('div', { className: 'dsh-lha-subcard', children: [
            jsxs('div', { className: 'dsh-lha-subcard__row', children: [
              jsx('span', { className: 'dsh-lha-count', children: '当前 IP' }),
              jsx('span', { className: 'dsh-lha-mono', children: currentIpOk ? currentIp : '—' }),
            ] }),
            jsxs('div', { className: 'dsh-lha-row__acts', children: [
              jsx('button', {
                type: 'button',
                className: 'dsh-lha-btn dsh-lha-btn--outline dsh-lha-btn--sm is-success',
                disabled: busy || !currentIpOk || allowExact,
                onClick: () => addIp('allow', currentIp),
                children: allowExact ? '已在白名单' : '加白',
              }),
              jsx('button', {
                type: 'button',
                className: 'dsh-lha-btn dsh-lha-btn--outline dsh-lha-btn--sm is-danger',
                disabled: busy || !currentIpOk || denyExact || isLoopback,
                onClick: () => addIp('deny', currentIp),
                children: isLoopback ? '不可拉黑' : (denyExact ? '已在黑名单' : '加黑'),
              }),
            ] }),
          ] }),
          jsx('label', { className: 'dsh-lha-checklbl', children: [
            jsx('span', { children: 'IP 白名单限制' }),
            jsx('input', {
              type: 'checkbox',
              checked: ipLimitOn,
              onChange: (e) => save({ ipLimitEnabled: e.target.checked }),
            }),
          ] }),
        ] }),
        jsxs('div', { className: 'dsh-lha-panel', children: [
          jsx('p', { className: 'dsh-lha-block__title', children: 'IP 名单' }),
          jsxs('div', { className: 'dsh-lha-tabs', role: 'tablist', 'aria-label': 'IP 名单切换', children: [
            jsxs('button', {
              type: 'button',
              role: 'tab',
              'aria-selected': ipPanelTab === 'allow' ? 'true' : 'false',
              className: 'dsh-lha-tab-btn',
              'data-active': ipPanelTab === 'allow' ? 'true' : undefined,
              onClick: () => setIpPanelTab('allow'),
              children: [
                '白名单',
                jsx('span', { className: 'dsh-lha-count', children: (config.allow || []).length }),
              ],
            }),
            jsxs('button', {
              type: 'button',
              role: 'tab',
              'aria-selected': ipPanelTab === 'deny' ? 'true' : 'false',
              className: 'dsh-lha-tab-btn',
              'data-active': ipPanelTab === 'deny' ? 'true' : undefined,
              onClick: () => setIpPanelTab('deny'),
              children: [
                '黑名单',
                jsx('span', { className: 'dsh-lha-count', children: (config.deny || []).length }),
              ],
            }),
          ] }),
          renderIpPanel('allow', { active: ipPanelTab === 'allow' }),
          renderIpPanel('deny', { active: ipPanelTab === 'deny' }),
        ] }),
        jsxs('div', { className: 'dsh-lha-panel', children: [
          jsx('p', { className: 'dsh-lha-block__title', children: '可疑 IP' }),
          visitors.length
            ? jsx('div', { className: 'dsh-lha-list', children: visitors.slice(0, 20).map((v) => jsxs('div', { className: 'dsh-lha-row', key: v.ip, children: [
              jsxs('div', { className: 'dsh-lha-row__body', children: [
                jsx('span', { className: 'dsh-lha-mono', children: v.ip }),
                jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--muted', children: `${v.eventCount} 次` }),
                jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--warn', children: v.lastReason }),
              ] }),
              jsxs('div', { className: 'dsh-lha-row__acts', children: [
                jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--outline dsh-lha-btn--sm is-success', disabled: busy, onClick: () => visitorAction(v.ip, 'allow'), children: '加白' }),
                jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--outline dsh-lha-btn--sm is-danger', disabled: busy || isLoopbackEntry(v.ip), onClick: () => visitorAction(v.ip, 'deny'), children: '加黑' }),
                jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--sm', disabled: busy, onClick: () => visitorAction(v.ip, 'dismiss'), children: '忽略' }),
              ] }),
            ] }) ) })
            : jsx('div', { className: 'dsh-lha-empty', children: '暂无可疑访客' }),
        ] }),
        jsxs('div', { className: 'dsh-lha-panel', children: [
          jsxs('div', { className: 'dsh-lha-panel__head', children: [
            jsx('p', { className: 'dsh-lha-block__title', children: 'Passkey' }),
            passkeyInfo && !passkeyInfo.available ? jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--warn', children: '不可用' }) : null,
          ] }),
          clientPasskeyReady() && passkeyInfo?.available ? jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--primary', disabled: busy, onClick: addPasskey, children: '添加' }) : null,
          jsx('div', { className: 'dsh-lha-list', children: passkeys.map((p) => jsxs('div', { className: 'dsh-lha-row', key: p.id, children: [
            jsx('span', { className: 'dsh-lha-row__name', children: `${p.name} · ${new Date(p.createdAt).toLocaleDateString()}` }),
            jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--sm is-danger', onClick: () => removePasskey(p.id), children: '删除' }),
          ] }) ) }),
        ] }),
        jsxs('div', { className: 'dsh-lha-panel', children: [
          jsx('p', { className: 'dsh-lha-block__title', children: '访问密码' }),
          jsxs('label', { className: 'dsh-lha-field', children: [
            '新密码',
            jsx('input', { type: 'password', className: 'dsh-lha-input', placeholder: '留空不改', value: newPassword, onChange: (e) => setNewPassword(e.target.value) }),
          ] }),
          jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--primary', disabled: busy, onClick: () => save({}), children: '保存' }),
        ] }),
        jsxs('details', { className: 'dsh-lha-collapse', children: [
          jsx('summary', { children: 'SSH 密钥' }),
          jsxs('div', { className: 'dsh-lha-collapse__body', children: [
            jsxs('label', { className: 'dsh-lha-field', children: [
              '公钥',
              jsx('textarea', { className: 'dsh-lha-textarea', rows: 3, placeholder: 'ssh-ed25519 AAAA...', value: newKey, onChange: (e) => setNewKey(e.target.value) }),
            ] }),
            jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--outline', onClick: addKey, children: '添加' }),
            jsx('div', { className: 'dsh-lha-list', children: keys.map((k) => jsx('div', { className: 'dsh-lha-mono', key: k.id, children: `${k.comment || k.id} (${k.fingerprint}…)` }) ) }),
          ] }),
        ] }),
        jsxs('details', { className: 'dsh-lha-collapse', onToggle: (e) => { if (e.target.open && !nginx) loadNginx() }, children: [
          jsx('summary', { children: 'Nginx' }),
          jsxs('div', { className: 'dsh-lha-collapse__body', children: [
            status?.proxy ? jsxs('div', { className: 'dsh-lha-tags', children: [
              jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--muted', children: status.proxy.viaTrustedProxy ? '信任代理' : '直连' }),
              status.proxy.hasForwardedHeaders ? jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--success', children: '有转发头' }) : jsx('span', { className: 'dsh-lha-tag dsh-lha-tag--warn', children: '无转发头' }),
            ] }) : null,
            jsx('label', { className: 'dsh-lha-checklbl', children: [
              jsx('span', { children: 'Basic 免二次登录' }),
              jsx('input', { type: 'checkbox', checked: !!config.nginxBasicAutoLogin, onChange: (e) => save({ nginxBasicAutoLogin: e.target.checked }) }),
            ] }),
            nginx ? jsx('pre', { className: 'dsh-lha-pre', children: nginx }) : jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--outline', onClick: loadNginx, children: '加载配置片段' }),
          ] }),
        ] }),
        jsxs('details', { className: 'dsh-lha-collapse', children: [
          jsx('summary', { children: '路由暴露' }),
          jsxs('div', { className: 'dsh-lha-collapse__body', children: [
            (config.routePolicy?.excludePrefixes || []).length
              ? jsx('div', { className: 'dsh-lha-list', children: (config.routePolicy?.excludePrefixes || []).map((p) => jsxs('div', { className: 'dsh-lha-row', key: p, children: [
                jsx('span', { className: 'dsh-lha-mono', children: p }),
                jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--sm is-danger', onClick: () => removeExclude(p), children: '移除' }),
              ] }) ) })
              : jsx('div', { className: 'dsh-lha-empty', children: '暂无' }),
            jsxs('div', { className: 'dsh-lha-bar', children: [
              jsx('input', {
                type: 'text',
                className: 'dsh-lha-input',
                placeholder: '/pluginrepo',
                value: excludeInput,
                onChange: (e) => setExcludeInput(e.target.value),
                onKeyDown: (e) => { if (e.key === 'Enter') addExclude() },
              }),
              jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--primary dsh-lha-btn--sm', disabled: busy, onClick: addExclude, children: '添加' }),
            ] }),
          ] }),
        ] }),
        jsxs('details', { className: 'dsh-lha-collapse', children: [
          jsx('summary', { children: '对等设备' }),
          jsxs('div', { className: 'dsh-lha-collapse__body', children: [
            peers.length
              ? jsx('div', { className: 'dsh-lha-list', children: peers.map((p) => jsxs('div', { className: 'dsh-lha-row', key: p.id, children: [
                jsx('span', { className: 'dsh-lha-row__name', children: `${p.name} · ${p.baseUrl}` }),
                jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--sm is-danger', onClick: () => removePeer(p.id), children: '撤销' }),
              ] }) ) })
              : jsx('div', { className: 'dsh-lha-empty', children: '暂无' }),
            jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--outline', disabled: busy, onClick: createPairingCode, children: '生成配对码' }),
            pairingCode ? jsx('div', { className: 'dsh-lha-mono', children: `${pairingCode}（至 ${pairExpires ? new Date(pairExpires).toLocaleTimeString() : '—'}）` }) : null,
            jsxs('div', { className: 'dsh-lha-stack', children: [
              jsx('input', { type: 'text', className: 'dsh-lha-input', placeholder: '对方地址', value: connectUrl, onChange: (e) => setConnectUrl(e.target.value) }),
              jsx('input', { type: 'text', className: 'dsh-lha-input', placeholder: '配对码', value: connectCode, onChange: (e) => setConnectCode(e.target.value) }),
              jsx('input', { type: 'text', className: 'dsh-lha-input', placeholder: '备注', value: connectName, onChange: (e) => setConnectName(e.target.value) }),
              jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--primary', disabled: busy, onClick: connectPeer, children: '连接' }),
            ] }),
          ] }),
        ] }),
        jsxs('details', { className: 'dsh-lha-collapse', children: [
          jsx('summary', { children: 'API 密钥' }),
          jsxs('div', { className: 'dsh-lha-collapse__body', children: [
            jsx('div', { className: 'dsh-lha-list', children: apiTokens.map((t) => jsxs('div', { className: 'dsh-lha-row', key: t.id, children: [
              jsx('span', { className: 'dsh-lha-row__name', children: `${t.name} · ${new Date(t.createdAt).toLocaleDateString()}` }),
              jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--sm is-danger', onClick: () => revokeApiToken(t.id), children: '撤销' }),
            ] }) ) }),
            jsxs('div', { className: 'dsh-lha-bar', children: [
              jsx('input', { type: 'text', className: 'dsh-lha-input', placeholder: '名称', value: newTokenName, onChange: (e) => setNewTokenName(e.target.value) }),
              jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--primary dsh-lha-btn--sm', disabled: busy, onClick: createApiToken, children: '生成' }),
            ] }),
            issuedToken ? jsx('div', { className: 'dsh-lha-mono', children: issuedToken }) : null,
          ] }),
        ] }),
        renderSettingsGuide(),
        confirm ? jsxs('div', {
          className: 'dsh-lha-dialog-mask',
          onClick: (e) => { if (e.target === e.currentTarget && !busy) setConfirm(null) },
          children: [
            jsxs('div', { className: 'dsh-lha-dialog', role: 'dialog', 'aria-modal': 'true', children: [
              jsx('h4', { children: confirm.title }),
              jsx('p', { children: confirm.body }),
              jsxs('div', { className: 'dsh-lha-dialog__foot', children: [
                jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--outline', disabled: busy, onClick: () => setConfirm(null), children: '取消' }),
                jsx('button', { type: 'button', className: 'dsh-lha-btn dsh-lha-btn--primary', disabled: busy, onClick: runConfirm, children: busy ? '处理中…' : '确认' }),
              ] }),
            ] }),
          ],
        }) : null,
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
