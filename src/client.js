window.__ModuleLoader__.load({
  id: 'dsh-local-hanaccount',
  factory: (require) => {
    const module = { exports: {} }
    const exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' })

    const React = require('react')
    const { jsx, jsxs } = require('react/jsx-runtime')

    const API = '/dsh-local-hanaccount/api'
    const STYLE_ID = 'dsh-local-hanaccount-css-v2'

    const listeners = new Set()
    const state = { me: null, loading: true, panelOpen: false }
    function emit() { for (const fn of listeners) fn({ ...state }) }
    function setState(patch) { Object.assign(state, patch); emit() }
    function openPanel(open) { setState({ panelOpen: !!open }) }

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
      if (typeof document !== 'undefined') {
        for (const old of document.querySelectorAll('style[id^="dsh-local-hanaccount-css"]')) {
          if (old.id !== STYLE_ID) old.remove()
        }
      }
      if (document.getElementById(STYLE_ID)) return
      const style = document.createElement('style')
      style.id = STYLE_ID
      style.textContent = `
[data-lha-overlay] { position: fixed; inset: 0; z-index: 9999; display: flex; align-items: center; justify-content: center; padding: 20px; box-sizing: border-box; background: rgba(9, 12, 20, .48); backdrop-filter: blur(8px); font-family: var(--dsw-font-family, ui-sans-serif, system-ui); color: var(--dsw-alias-label-primary, #111827); }
[data-lha-card] { width: min(760px, 100%); max-height: min(760px, calc(100vh - 40px)); overflow: auto; border-radius: 18px; background: var(--dsw-alias-bg-base, #fff); box-shadow: 0 24px 80px rgba(0,0,0,.28); border: 1px solid var(--dsw-alias-border-l2, rgba(0,0,0,.08)); }
[data-lha-card] .lha-head { display: flex; align-items: center; gap: 12px; padding: 16px 18px; border-bottom: 1px solid var(--dsw-alias-border-l2, rgba(0,0,0,.08)); }
[data-lha-card] .lha-title { font-weight: 700; font-size: 16px; }
[data-lha-card] .lha-sub { font-size: 12px; color: var(--dsw-alias-label-secondary, #6b7280); margin-top: 2px; }
[data-lha-card] .lha-spacer { flex: 1; }
[data-lha-card] .lha-body { padding: 18px; display: grid; gap: 16px; }
[data-lha-card] .lha-grid { display: grid; gap: 10px; }
[data-lha-card] label { display: grid; gap: 6px; font-size: 13px; color: var(--dsw-alias-label-secondary, #4b5563); }
[data-lha-card] input { box-sizing: border-box; width: 100%; border: 1px solid var(--dsw-alias-border-l2, #d1d5db); background: var(--dsw-alias-bg-layer-1, #fff); color: inherit; border-radius: 10px; padding: 9px 11px; font-size: 14px; outline: none; }
[data-lha-card] input:focus { border-color: var(--dsw-alias-interactive-primary, #2563eb); box-shadow: 0 0 0 3px rgba(37,99,235,.14); }
[data-lha-card] button, [data-lha-chip] { border: 1px solid var(--dsw-alias-border-l2, #d1d5db); background: var(--dsw-alias-bg-layer-1, #fff); color: inherit; border-radius: 10px; padding: 8px 12px; font-size: 13px; cursor: pointer; }
[data-lha-card] button.primary { border-color: var(--dsw-alias-interactive-primary, #2563eb); background: var(--dsw-alias-interactive-primary, #2563eb); color: white; }
[data-lha-card] button.danger { color: var(--dsw-alias-state-error-primary, #dc2626); }
[data-lha-card] button:disabled { opacity: .55; cursor: not-allowed; }
[data-lha-card] .lha-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
[data-lha-card] .lha-error { padding: 10px 12px; border-radius: 10px; color: #991b1b; background: #fee2e2; font-size: 13px; }
[data-lha-card] .lha-ok { padding: 10px 12px; border-radius: 10px; color: #166534; background: #dcfce7; font-size: 13px; }
[data-lha-card] .lha-section { border: 1px solid var(--dsw-alias-border-l2, rgba(0,0,0,.08)); border-radius: 14px; padding: 14px; display: grid; gap: 12px; }
[data-lha-card] .lha-section h3 { margin: 0; font-size: 14px; }
[data-lha-card] .lha-row { display: grid; grid-template-columns: 120px 1fr; gap: 8px; font-size: 13px; }
[data-lha-card] .lha-k { color: var(--dsw-alias-label-secondary, #6b7280); }
[data-lha-card] .lha-ws { display: grid; gap: 8px; }
[data-lha-card] .lha-ws-item { display: grid; gap: 4px; padding: 10px; border: 1px solid var(--dsw-alias-border-l2, rgba(0,0,0,.08)); border-radius: 12px; }
[data-lha-card] .lha-path { color: var(--dsw-alias-label-secondary, #6b7280); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; word-break: break-all; }
[data-lha-entry] { width: 100%; display: flex; align-items: center; gap: 8px; border: 0; background: transparent; color: inherit; padding: 8px 10px; border-radius: 10px; cursor: pointer; font-size: 13px; }
[data-lha-entry]:hover { background: var(--dsw-alias-interactive-bg-hover, rgba(0,0,0,.05)); }
[data-lha-chip] { display: inline-flex; gap: 6px; align-items: center; padding: 5px 9px; font-size: 12px; }
[data-lha-settings] { display: grid; gap: 10px; padding: 4px 0; }

@media (max-width: 720px) { [data-lha-card] .lha-row { grid-template-columns: 1fr; gap: 3px; } [data-lha-card] { border-radius: 14px; } }
`
      document.head.appendChild(style)
    }

    function LoginGate() {
      const snap = useSharedState()
      React.useEffect(ensureStyle, [])
      const authed = !!snap.me?.authenticated
      if (snap.loading) return jsx('div', { 'data-lha-overlay': '', children: jsx('div', { 'data-lha-card': '', children: jsx('div', { className: 'lha-body', children: '正在检查本地账户登录状态…' }) }) })
      if (!authed) return jsx('div', { 'data-lha-overlay': '', children: jsx(LoginCard, { me: snap.me }) })
      if (snap.panelOpen) {
        return jsx('div', {
          'data-lha-overlay': '',
          onClick: () => openPanel(false),
          children: jsx(AccountPanel, {}),
        })
      }
      return null
    }

    function LoginCard({ me }) {
      const [username, setUsername] = React.useState('')
      const [password, setPassword] = React.useState('')
      const [busy, setBusy] = React.useState(false)
      const [err, setErr] = React.useState('')
      async function submit(ev) {
        ev.preventDefault()
        setBusy(true); setErr('')
        try {
          await api('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) })
          await refreshMe()
        } catch (e) { setErr(String(e.message || e)) }
        finally { setBusy(false) }
      }
      return jsxs('form', { 'data-lha-card': '', onSubmit: submit, children: [
        jsx('div', { className: 'lha-head', children: jsxs('div', { children: [jsx('div', { className: 'lha-title', children: '登录本地账户' }), jsx('div', { className: 'lha-sub', children: 'dsh-local-hanaccount：账户来自本机配置文件，不提供网页注册。' })] }) }),
        jsxs('div', { className: 'lha-body', children: [
          me && me.configured === false ? jsx('div', { className: 'lha-error', children: '尚未配置 users。请在 profile/home 的 cordis.patch.yml 中配置本地用户后重启 DSH。' }) : null,
          err ? jsx('div', { className: 'lha-error', children: err }) : null,
          jsxs('div', { className: 'lha-grid', children: [
            jsxs('label', { children: ['用户名', jsx('input', { value: username, autoFocus: true, onChange: (e) => setUsername(e.target.value), autoComplete: 'username' })] }),
            jsxs('label', { children: ['密码', jsx('input', { type: 'password', value: password, onChange: (e) => setPassword(e.target.value), autoComplete: 'current-password' })] }),
          ] }),
          jsx('div', { className: 'lha-actions', children: jsx('button', { className: 'primary', disabled: busy || !username, children: busy ? '登录中…' : '登录' }) }),
        ] }),
      ] })
    }

    function AccountPanel() {
      const snap = useSharedState()
      const user = snap.me?.user
      const [data, setData] = React.useState(null)
      const [err, setErr] = React.useState('')
      async function load() { try { setData(await api('/workspaces')) } catch (e) { setErr(String(e.message || e)) } }
      React.useEffect(() => { load() }, [])
      async function logout() {
        await api('/auth/logout', { method: 'POST', body: '{}' })
        openPanel(false); await refreshMe()
      }
      return jsxs('div', {
        'data-lha-card': '',
        onClick: (e) => e.stopPropagation(),
        children: [
          jsx('div', { className: 'lha-head', children: jsxs('div', { children: [jsx('div', { className: 'lha-title', children: '本地账户' }), jsx('div', { className: 'lha-sub', children: '工作区请在左侧侧栏创建与管理；普通用户请选择账户根目录下的路径。' })] }) }),
          jsxs('div', { className: 'lha-body', children: [
            err ? jsx('div', { className: 'lha-error', children: err }) : null,
            jsxs('div', { className: 'lha-section', children: [
              jsx('h3', { children: '当前账户' }),
              jsx(Row, { k: '用户名', v: user?.username || '-' }),
              jsx(Row, { k: '角色', v: user?.role || '-' }),
              jsx(Row, { k: '账户工作区根目录', v: data?.accountWorkspaceRoot || '-' }),
              jsx('div', { className: 'lha-sub', children: '在左侧「工作区」区域新建时，请把目录建在上述根路径之下。' }),
              jsx('div', { className: 'lha-actions', children: jsx('button', { className: 'danger', type: 'button', onClick: logout, children: '退出登录' }) }),
            ] }),
          ] }),
        ],
      })
    }

    function Row({ k, v }) { return jsxs('div', { className: 'lha-row', children: [jsx('div', { className: 'lha-k', children: k }), jsx('div', { className: 'lha-path', children: v })] }) }

    function SidebarEntry() {
      const snap = useSharedState()
      const u = snap.me?.user
      React.useEffect(ensureStyle, [])
      return jsx('button', { 'data-lha-entry': '', type: 'button', onClick: () => openPanel(true), children: u ? `账户：${u.username}（${u.role}）` : '本地账户' })
    }

    function HeaderChip() {
      const snap = useSharedState()
      const u = snap.me?.user
      React.useEffect(ensureStyle, [])
      if (!u) return null
      return jsx('button', { 'data-lha-chip': '', type: 'button', onClick: () => openPanel(true), children: `本地账户 · ${u.username}` })
    }

    function SettingsSection() {
      const snap = useSharedState()
      const u = snap.me?.user
      React.useEffect(ensureStyle, [])
      return jsxs('div', { 'data-lha-settings': '', children: [jsx('h3', { children: '本地账户' }), jsx('div', { children: u ? `已登录：${u.username}（${u.role}）` : '未登录' }), jsx('button', { type: 'button', onClick: () => openPanel(true), children: u ? '账户信息' : '登录' })] })
    }

    /** Drop host frames / list baselines for workspaces outside the logged-in account. */
    function installClientWorkspaceFilter(workspaces) {
      if (!workspaces?.manager || workspaces.__dshLocalHanaccountFiltered) return () => {}
      workspaces.__dshLocalHanaccountFiltered = true
      const manager = workspaces.manager
      const allow = { root: '', ids: new Set(), paths: new Set(), ready: false, authed: false }
      let refreshToken = 0

      function pathAllowed(path) {
        const p = String(path || '')
        if (!p) return false
        if (allow.root) {
          const root = allow.root.endsWith('/') ? allow.root.slice(0, -1) : allow.root
          if (p === root || p.startsWith(root + '/')) return true
        }
        for (const owned of allow.paths) {
          const base = owned.endsWith('/') ? owned.slice(0, -1) : owned
          if (p === base || p.startsWith(base + '/')) return true
        }
        return false
      }

      function viewAllowed(view) {
        if (!view) return false
        // Fail-closed until allow-list loads (avoids flashing other accounts' rows).
        if (!allow.ready) return false
        if (!allow.authed) return false
        const id = String(view.workspaceId || '')
        if (id && allow.ids.has(id)) return true
        return pathAllowed(view.path)
      }

      function pruneInstalled() {
        if (!origInstallViews) return
        const views = typeof manager.itemViews === 'function'
          ? manager.itemViews()
          : (manager.getSnapshot?.().items || [])
        // Use original installViews to avoid tombstoning via remove().
        origInstallViews((views || []).filter(viewAllowed))
      }

      async function refreshAllow() {
        const token = ++refreshToken
        try {
          const me = await api('/auth/me')
          if (token !== refreshToken) return
          if (!me?.authenticated) {
            allow.root = ''
            allow.ids = new Set()
            allow.paths = new Set()
            allow.authed = false
            allow.ready = true
            if (origInstallViews) origInstallViews([])
            return
          }
          const data = await api('/workspaces')
          if (token !== refreshToken) return
          allow.root = String(data.accountWorkspaceRoot || '')
          allow.ids = new Set((data.workspaces || []).map((w) => String(w.nativeWorkspaceId || '')).filter(Boolean))
          allow.paths = new Set((data.workspaces || []).map((w) => String(w.path || '')).filter(Boolean))
          if (allow.root) allow.paths.add(allow.root)
          allow.authed = true
          allow.ready = true
          // Re-pull host baseline under cookie ALS; installViews wrapper drops foreign rows.
          if (typeof manager.refresh === 'function') await manager.refresh()
          else pruneInstalled()
        } catch {
          if (token !== refreshToken) return
          allow.ready = true
        }
      }

      const origUpsert = manager.upsert.bind(manager)
      const origInstallViews = manager.installViews?.bind(manager)
      manager.upsert = function filteredUpsert(view, identity) {
        if (!viewAllowed(view)) return
        return origUpsert(view, identity)
      }
      if (origInstallViews) {
        manager.installViews = function filteredInstallViews(items) {
          return origInstallViews((items || []).filter(viewAllowed))
        }
      }

      refreshAllow()
      const onAuth = () => { refreshAllow() }
      listeners.add(onAuth)
      const poll = setInterval(refreshAllow, 8000)

      return () => {
        listeners.delete(onAuth)
        clearInterval(poll)
        manager.upsert = origUpsert
        if (origInstallViews) manager.installViews = origInstallViews
        delete workspaces.__dshLocalHanaccountFiltered
      }
    }

    /**
     * Drop other accounts' sessions so they do not appear under 未分组 when their
     * workspace row is already filtered out of the sidebar.
     */
    function installClientSessionFilter(sessionsRuntime) {
      const manager = sessionsRuntime?.manager
      if (!manager || sessionsRuntime.__dshLocalHanaccountFiltered) return () => {}
      sessionsRuntime.__dshLocalHanaccountFiltered = true
      const allow = { root: '', paths: new Set(), sessionIds: new Set(), ready: false, authed: false }
      let refreshToken = 0

      function pathAllowed(path) {
        const p = String(path || '')
        if (!p) return false
        if (allow.root) {
          const root = allow.root.endsWith('/') ? allow.root.slice(0, -1) : allow.root
          if (p === root || p.startsWith(root + '/')) return true
        }
        for (const owned of allow.paths) {
          const base = owned.endsWith('/') ? owned.slice(0, -1) : owned
          if (p === base || p.startsWith(base + '/')) return true
        }
        return false
      }

      function summaryAllowed(summary) {
        if (!summary) return false
        if (!allow.ready || !allow.authed) return false
        const id = String(summary.sessionId || summary.id || '')
        if (id && allow.sessionIds.has(id)) return true
        return pathAllowed(summary.cwd)
      }

      function pruneSummaries() {
        if (!Array.isArray(manager.summaries)) return
        manager.summaries = manager.summaries.filter(summaryAllowed)
        manager.notifier?.markDirty?.()
      }

      async function refreshAllow() {
        const token = ++refreshToken
        try {
          const me = await api('/auth/me')
          if (token !== refreshToken) return
          if (!me?.authenticated) {
            allow.root = ''
            allow.paths = new Set()
            allow.sessionIds = new Set()
            allow.authed = false
            allow.ready = true
            manager.summaries = []
            manager.notifier?.markDirty?.()
            return
          }
          const data = await api('/workspaces')
          if (token !== refreshToken) return
          allow.root = String(data.accountWorkspaceRoot || '')
          allow.paths = new Set((data.workspaces || []).map((w) => String(w.path || '')).filter(Boolean))
          if (allow.root) allow.paths.add(allow.root)
          allow.sessionIds = new Set((data.sessionOwners || []).map((s) => String(s.sessionId || '')).filter(Boolean))
          allow.authed = true
          allow.ready = true
          if (typeof manager.refreshList === 'function') await manager.refreshList()
          else pruneSummaries()
        } catch {
          if (token !== refreshToken) return
          allow.ready = true
        }
      }

      const sessionsApi = manager.api?.sessions
      const origList = sessionsApi?.list?.bind(sessionsApi)
      if (origList) {
        sessionsApi.list = async function filteredSessionList(...args) {
          const res = await origList(...args)
          if (res?.result?.ok && Array.isArray(res.result.value?.items)) {
            res.result.value.items = res.result.value.items.filter(summaryAllowed)
          }
          return res
        }
      }

      const origRecordMutation = manager.recordMutation?.bind(manager)
      if (origRecordMutation) {
        manager.recordMutation = function filteredRecordMutation(mutation) {
          if (mutation?.kind === 'upsert' && mutation.summary && !summaryAllowed(mutation.summary)) return
          return origRecordMutation(mutation)
        }
      }

      refreshAllow()
      const onAuth = () => { refreshAllow() }
      listeners.add(onAuth)
      const poll = setInterval(refreshAllow, 8000)

      return () => {
        listeners.delete(onAuth)
        clearInterval(poll)
        if (origList) sessionsApi.list = origList
        if (origRecordMutation) manager.recordMutation = origRecordMutation
        delete sessionsRuntime.__dshLocalHanaccountFiltered
      }
    }

    function apply(ctx) {
      ensureStyle()
      ctx.effect(() => ctx.slots.inject('shell.overlay', () => ctx.slots.register({ name: 'shell.overlay', id: 'dsh-local-hanaccount-gate', order: -1000 }, LoginGate)), 'dsh-local-hanaccount: auth gate')
      ctx.effect(() => ctx.slots.inject('sidebar.footer.action', () => ctx.slots.register({ name: 'sidebar.footer.action', id: 'dsh-local-hanaccount-entry', order: 0 }, SidebarEntry)), 'dsh-local-hanaccount: sidebar entry')
      ctx.effect(() => ctx.slots.inject('conversation.session.header.actions', () => ctx.slots.register({ name: 'conversation.session.header.actions', id: 'dsh-local-hanaccount-chip', order: -10 }, HeaderChip)), 'dsh-local-hanaccount: header chip')
      ctx.effect(() => ctx.slots.inject('settings.section', () => ctx.slots.register({ name: 'settings.section', id: 'dsh-local-hanaccount-settings', order: 10, label: '本地账户' }, SettingsSection)), 'dsh-local-hanaccount: settings section')
      // Client-side filter: host event WS can push other accounts' workspaces; drop them in the workspace manager.
      ctx.effect(() => {
        let undo = null
        let tries = 0
        const timer = setInterval(() => {
          const workspaces = ctx.get?.('workspaces')
          if (workspaces) {
            clearInterval(timer)
            undo = installClientWorkspaceFilter(workspaces)
          } else if (++tries > 80) clearInterval(timer)
        }, 50)
        return () => {
          clearInterval(timer)
          try { undo?.() } catch {}
        }
      }, 'dsh-local-hanaccount: filter native workspace list')
      ctx.effect(() => {
        let undo = null
        let tries = 0
        const timer = setInterval(() => {
          const sessions = ctx.get?.('sessions')
          if (sessions?.manager) {
            clearInterval(timer)
            undo = installClientSessionFilter(sessions)
          } else if (++tries > 80) clearInterval(timer)
        }, 50)
        return () => {
          clearInterval(timer)
          try { undo?.() } catch {}
        }
      }, 'dsh-local-hanaccount: filter native session list')
      refreshMe()
    }

    exports.apply = apply
    exports.inject = ['slots']
    return module.exports
  },
})
