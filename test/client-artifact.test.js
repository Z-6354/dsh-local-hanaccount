import vm from 'node:vm'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import assert from 'node:assert/strict'
import { createAuthSession } from '../src/lib/auth-session.js'

test('checking subscriber reentry shares exactly one request', async () => {
  let calls = 0
  const auth = createAuthSession({ request: async () => { calls++; return { authenticated: true, nativeAuthenticated: true } } })
  let nested
  auth.subscribe(s => { if (s.status === 'checking') nested = auth.refresh() })
  await auth.refresh(); await nested
  assert.equal(calls, 1)
})

test('actual generated bundle dispose/reapply creates fresh auth service', async () => {
  let module, calls = 0
  const context = vm.createContext({
    window: { location: { origin: 'https://fixture.invalid' }, __ModuleLoader__: { load: definition => { module = definition.factory(() => ({})) } } },
    Symbol, URL, AbortController, setTimeout, clearTimeout,
    fetch: async () => { calls++; return { ok: true, text: async () => JSON.stringify({ authenticated: true, nativeAuthenticated: true, resumeScope: String(calls).repeat(48) }) } },
  })
  vm.runInContext(readFileSync(new URL('../src/client.js', import.meta.url), 'utf8'), context)
  function apply() {
    const disposers = [], services = {}
    module.apply({ provide: (name, service) => { services[name] = service }, effect: fn => { const off = fn(); if (typeof off === 'function') disposers.push(off) }, slots: { inject: () => () => {} } })
    return { auth: services.hanaccountAuth, dispose: () => disposers.reverse().forEach(off => off()) }
  }
  const first = apply(); await first.auth.refresh()
  assert.equal(calls, 1)
  first.dispose()
  const second = apply(); await second.auth.refresh()
  assert.equal(calls, 2)
  assert.equal(second.auth.getSnapshot().scope, '2'.repeat(48))
  await first.auth.refresh()
  assert.equal(calls, 2)
  second.dispose()
})

test('actual auth bundle paints initial unavailable retry overlay before notifying native ready', async () => {
  let module, service, gate
  const rafs = new Map(); let seq = 0
  const notifications = [], effects = [], cleanup = []
  const React = { useState: value => [value, () => {}], useRef: value => ({ current: value }), useEffect: fn => effects.push(fn) }
  const win = {
    __ModuleLoader__: { load: definition => { module = definition.factory(name => name === 'react' ? React : { jsx: (type, props) => ({ type, props }), jsxs: (type, props) => ({ type, props }) }) } },
    location: { origin: 'https://fixture.invalid' },
    requestAnimationFrame(fn) { rafs.set(++seq, fn); return seq }, cancelAnimationFrame(id) { rafs.delete(id) },
    HanApp: { postMessage: value => notifications.push(JSON.parse(value)) },
  }
  vm.runInNewContext(readFileSync(new URL('../src/client.js', import.meta.url), 'utf8'), { window: win, Symbol, URL, AbortController, setTimeout, clearTimeout, fetch: async () => { throw new Error('offline') } })
  module.apply({ provide: (_, value) => { service = value }, effect: fn => { const off = fn(); if (typeof off === 'function') cleanup.push(off) }, slots: { inject: (_, fn) => fn(), register(options, component) { if (options.id.endsWith('-gate')) gate = component; return () => {} } } })
  await service.refresh()
  const overlay = gate()
  assert.equal(service.getSnapshot().status, 'unavailable')
  const mounted = overlay.type(overlay.props)
  mounted.props.ref.current = {}
  for (const fn of effects) { const off = fn(); if (typeof off === 'function') cleanup.push(off) }
  assert.equal(notifications.length, 0)
  for (let i = 0; i < 2; i++) { const frame = [...rafs.values()]; rafs.clear(); frame.forEach(fn => fn()) }
  assert.equal(notifications.length, 1)
  assert.equal(notifications[0].type, 'pageReady')
  cleanup.reverse().forEach(fn => fn())
  assert.equal(rafs.size, 0)
})
