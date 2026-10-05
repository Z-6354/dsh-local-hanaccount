import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { EventEmitter } from 'node:events'
import { apply } from '../src/index.js'
import { createDshAdapter, AUDITED_BUILD } from '../src/lib/dsh-adapter.js'
import { createGate } from '../src/gate.js'
import { createStore } from '../src/lib/store.js'
import { loginStyle } from '../src/lib/login-style.js'
import { renderLoginPage } from '../src/lib/login-page.js'
import { installOutboundFetch } from '../src/lib/outbound-fetch.js'

function server() {
  return {exact:new Map(), prefixes:new Map(), upgrades:new Map(), fallback:undefined,
    register(route) { const map = route.kind === 'exact' ? this.exact : this.prefixes; if (map.has(route.path)) throw Error('duplicate route'); map.set(route.path, route); return () => map.delete(route.path) },
    registerUpgrade(route) { this.upgrades.set(route.path, route); return () => this.upgrades.delete(route.path) },
    registerFallback(handler) { this.fallback = handler; return () => { this.fallback = undefined } },
  }
}
const connection = {requestRejection:() => 401, authenticatedUrl:() => 'http://localhost/?token=fixture', authorizeIndex:() => false}
const cfg = {officialBuild:AUDITED_BUILD}
const request = (url='/api/business', method='GET') => ({url, method, headers:{host:'localhost'}, socket:{remoteAddress:'127.0.0.1'}})
function response() { return {writeHead(status, headers) { this.status=status; this.headers=headers }, end(body) { this.body=body }} }

test('missing and unknown audited build refuse selection', () => {
  for (const config of [{}, {officialBuild:'future-build'}]) assert.throws(() => createDshAdapter(server(), connection, config), {code:'official_build_unsupported'})
})

test('dispose and reapply retain closed route wrappers, accept late fallback/routes and release no store reads', () => {
  const web=server(); let executed=0
  web.register({kind:'exact',path:'/business',handler:() => executed++})
  const first=createDshAdapter(web, connection, cfg)
  const policy={wrapHttpHandler:original => original, wrapUpgradeHandler:original => original,dispose() {}}
  first.activate(policy)
  assert.equal(first.state().ready,true); assert.equal(first.state().deploymentReady,false)
  web.exact.get('/business').handler(request(),response()); assert.equal(executed,1)
  first.stop(); first.stop(); const blocked=response();web.exact.get('/business').handler(request(),blocked);assert.equal(blocked.status,503)
  web.register({kind:'prefix',path:'/late',handler:() => executed++});web.registerFallback(() => executed++)
  const fallback=response();web.fallback(request('/spa/deep'),fallback);assert.equal(fallback.status,503)
  assert.throws(() => createDshAdapter(web,connection,{officialBuild:'unknown'}), {code:'official_build_unsupported'})
  const next=createDshAdapter(web,connection,cfg);next.activate(policy)
  web.prefixes.get('/late').handler(request('/late'),response());assert.equal(executed,2)
  assert.throws(() => createDshAdapter(web,connection,{officialBuild:'unknown'}), {code:'official_build_unsupported'})
  assert.equal(next.state().ready,false);const unknown=response();web.fallback(request('/deep'),unknown);assert.equal(unknown.status,503);next.stop()
})

test('bridge failure after route guard installation preserves deny-only fallback', () => {
  const web=server();web.registerFallback(() => {throw Error('must not execute')})
  assert.throws(() => createDshAdapter(web,{},cfg), {code:'native_bridge_unavailable'})
  const res=response();web.fallback(request('/'),res);assert.equal(res.status,503)
})

test('retired adapter stop, state and late activate cannot take ownership from a reapplied epoch', () => {
  const web=server();let oldDisposed=0,newDisposed=0,executed=0
  web.registerFallback(() => executed++)
  const old=createDshAdapter(web,connection,cfg)
  old.activate({wrapHttpHandler:f => f,wrapUpgradeHandler:f => f,dispose(){oldDisposed++}})
  assert.throws(() => createDshAdapter(web,connection,{officialBuild:'unknown'}),{code:'official_build_unsupported'})
  assert.equal(oldDisposed,1);assert.equal(old.state().code,'official_build_unsupported')
  const current=createDshAdapter(web,connection,cfg)
  current.activate({wrapHttpHandler:f => f,wrapUpgradeHandler:f => f,dispose(){newDisposed++}})
  assert.equal(current.state().ready,true);assert.equal(old.state().ready,false)
  assert.throws(() => old.activate({}),{code:'auth_retired'})
  old.stop();old.stop()
  assert.equal(current.state().ready,true);assert.equal(newDisposed,0)
  web.fallback(request('/'),response());assert.equal(executed,1)
  current.stop();assert.equal(newDisposed,1)
})

test('invalid late route changes readiness to unavailable, Map mutation failure preflight is atomic', () => {
  const web=server();web.registerFallback(() => {})
  const adapter=createDshAdapter(web,connection,cfg)
  adapter.activate({wrapHttpHandler:f => f, wrapUpgradeHandler:f => f, dispose(){}})
  assert.throws(() => web.register({kind:'exact',path:'/bad',handler:0}), /route handler/)
  assert.equal(adapter.state().ready,false);adapter.stop()
  const incompatible=server(), original=() => {};incompatible.fallback=original
  Object.preventExtensions(incompatible.upgrades)
  assert.throws(() => createDshAdapter(incompatible,connection,cfg), /table setter/)
  assert.equal(incompatible.fallback,original);assert.equal(Object.hasOwn(incompatible.exact,'set'),false)
})

test('apply registers readiness and keeps deny layer after disposal, disables auth without restoring routes', async () => {
  const dir=mkdtempSync(join(tmpdir(),'auth-apply-')),web=server();let dispose, provided
  const ctx={get:name => name === 'webServer' ? web : connection, effect(setup) {dispose=setup()},provide(_name,value) {provided=value}}
  try {
    await apply(ctx,{...cfg,dataDir:dir});assert.equal(provided.securityState().ready,true)
    dispose();const res=response();web.registerFallback(() => {throw Error('must not execute')});web.fallback(request('/'),res);assert.equal(res.status,503)
    await apply(ctx,{...cfg,dataDir:dir});assert.equal(provided.securityState().ready,true);dispose()
    await assert.rejects(apply(ctx,{...cfg,enabled:false,dataDir:dir}), {code:'auth_disabled'})
    const unavailable=response();web.fallback(request('/'),unavailable);assert.equal(unavailable.status,503)
  } finally {dispose?.();rmSync(dir,{recursive:true,force:true})}
})

test('all dynamic assets/plugin reads require auth; only canonical exact login stylesheet read is exempt', () => {
  const dir=mkdtempSync(join(tmpdir(),'auth-style-'))
  const config={dataDir:dir,ipLimitEnabled:false,canonicalOrigin:'https://localhost',loginStylesheetUrl:'https://localhost/hanui-assets/login.css'}
  const store=createStore(config), gate=createGate(store, {fence(){},authenticated:() => false})
  try {
    for(const path of ['/assets/business','/plugins/private','/hanui-assets/login.css?token=x','/hanui-assets/login.css/deep']) {
      const res=response();gate.wrapHttpHandler(() => {throw Error('must not execute')})(request(path),res);assert.equal(res.status,401)
    }
    for(const method of ['GET','HEAD','POST','DELETE']) {
      const req=request('/hanui-assets/login.css',method);req.socket.encrypted=true
      const res=response();gate.wrapHttpHandler((_req,r) => {r.writeHead(200);r.end()})(req,res);assert.equal(res.status,['GET','HEAD'].includes(method)?200:401)
    }
    const req=request('/');req.socket.encrypted=true
    const res=response();gate.wrapHttpHandler(() => {throw Error('must not execute')})(req,res)
    assert.match(res.body, /<link rel="stylesheet" href="https:\/\/localhost\/hanui-assets\/login.css">/)
    assert.match(res.headers['content-security-policy'], /style-src .*https:\/\/localhost\/hanui-assets\/login.css;/)
  } finally {gate.dispose();rmSync(dir,{recursive:true,force:true})}
})

test('unsafe or noncanonical CSS configuration falls back to local server-owned styling', () => {
  for(const url of ['https://evil.test/hanui-assets/login.css','javascript:alert(1)','https://user:pass@localhost/hanui-assets/login.css','https://localhost/hanui-assets/login.css?token=x','https://localhost/hanui-assets/login.css#x','https://localhost/other.css','https://localhost:443/hanui-assets/login.css']) {
    assert.equal(loginStyle({canonicalOrigin:'https://localhost',loginStylesheetUrl:url}),null)
  }
  assert.equal(loginStyle({canonicalOrigin:'http://localhost',loginStylesheetUrl:'http://localhost/hanui-assets/login.css'}),null)
  assert.doesNotMatch(renderLoginPage('nonce'), /<link/)
  assert.match(renderLoginPage('nonce'), /border-radius:24px/)
})

test('long authenticated HTTP stream closes immediately on logout without cancelling submitted work', () => {
  const dir=mkdtempSync(join(tmpdir(),'auth-stream-')),store=createStore({dataDir:dir,passwordHash:'configured',ipLimitEnabled:false})
  const gate=createGate(store, {authenticated:() => true,fence(){}}),token=store.issueSession(),res=new EventEmitter()
  res.destroy=() => {res.destroyed=true;res.emit('close')};res.writeHead=() => {};res.end=() => {}
  try {
    const req=request();req.headers.cookie=`dsh_gate_token=${token}`;let work=0
    gate.wrapHttpHandler(() => {work++})(req,res);assert.equal(work,1);store.logout(token)
    assert.equal(res.destroyed,true);assert.equal(work,1)
    gate.dispose();store.sessionFromToken=() => {throw Error('retired store used')};const blocked=response();gate.wrapHttpHandler(() => {})(req,blocked);assert.equal(blocked.status,503)
  } finally {gate.dispose();rmSync(dir,{recursive:true,force:true})}
})

test('outbound enhancer disposal cannot overwrite another owner and retained chains stop injecting credentials', async () => {
  const original=globalThis.fetch;let observed
  try {
    globalThis.fetch=async (_url,init) => {observed=init}
    const undo=installOutboundFetch({matchUrl:() => ({outboundToken:'fixture'})}),ours=globalThis.fetch
    const later=(...args) => ours(...args);globalThis.fetch=later;undo()
    assert.equal(globalThis.fetch,later);await later('https://fixture.test');assert.equal(observed.headers,undefined)
  } finally {globalThis.fetch=original}
})

test('failed logout persistence emits security revocation and fails the core state without reopening a session', () => {
  const dir=mkdtempSync(join(tmpdir(),'auth-storage-'));let unavailable=0
  const store=createStore({dataDir:dir,passwordHash:'configured',ipLimitEnabled:false,...cfg}, {onStorageFailure:() => unavailable++})
  const token=store.issueSession(),gate=createGate(store,{authenticated:() => true,fence(){}})
  let destroyed=false
  try {
    const req=request();req.headers.cookie=`dsh_gate_token=${token}`
    gate.wrapUpgradeHandler(() => {})(req,{destroy(){destroyed=true},once(){}})
    store.updateConfig({officialBuild:'unknown',loginStylesheetUrl:'https://evil.test/hanui-assets/login.css'})
    assert.equal(store.cfg.officialBuild,AUDITED_BUILD);assert.equal(store.cfg.loginStylesheetUrl,undefined)
    rmSync(join(dir,'state.json'));mkdirSync(join(dir,'state.json'))
    assert.throws(() => store.logout(token), {code:'storage_unavailable'})
    assert.equal(unavailable,1);assert.equal(destroyed,true);assert.throws(() => store.sessionFromToken(token), {code:'auth_unavailable'})
  } finally {gate.dispose();rmSync(dir,{recursive:true,force:true})}
})
