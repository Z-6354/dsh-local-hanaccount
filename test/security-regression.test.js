import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync, writeFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { createStore } from '../src/lib/store.js'
import { createGate, wrapWebServer } from '../src/gate.js'
import { evaluateIpAccess } from '../src/lib/ip.js'
import { readBody, readJson, writeJson } from '../src/lib/util.js'
import { createApiHandler } from '../src/api.js'
const withStore = fn => { const dir = mkdtempSync(join(tmpdir(), 'han-security-')); try { return fn(createStore({ dataDir: dir, passwordHash: 'configured' })) } finally { rmSync(dir, { recursive: true, force: true }) } }
test('deny remains enforced when allowlist disabled', () => assert.equal(evaluateIpAccess('203.0.113.4', {ipLimitEnabled:false, deny:['203.0.113.4']}).action, 'block'))
test('expired server session is rejected', () => withStore(s => { const token = s.issueSession(); s.state.sessions[token].createdAt = '2000-01-01T00:00:00Z'; assert.equal(s.sessionFromToken(token), null) }))
test('password change invalidates sessions', () => withStore(s => { const token = s.issueSession(); s.setPasswordHash('new'); assert.equal(s.sessionFromToken(token), null) }))
test('old sessions fail after password config commits before state cleanup', () => withStore(s => { const token=s.issueSession();s.cfg.passwordHash='changed-in-config';assert.equal(s.sessionFromToken(token),null) }))
test('unverified Basic cannot open upgrade', () => withStore(s => { s.cfg.nginxBasicAutoLogin = true; let opened = false, destroyed = false; createGate(s).wrapUpgradeHandler(() => {opened = true})({url:'/api/remote.mux',headers:{authorization:'Basic arbitrary'},socket:{remoteAddress:'127.0.0.1'}},{destroy(){destroyed=true}}); assert.equal(opened,false); assert.equal(destroyed,true) }))
test('remote mux and dynamic replacement are synchronously protected and restored', () => withStore(s => {
 const server = {fallback:undefined,prefixes:new Map(),exact:new Map(),upgrades:new Map()}; const original = () => {}; const first = {handler:original}; server.upgrades.set('/api/remote.mux',first); const dispose = wrapWebServer(server,createGate(s),s); try { assert.notEqual(first.handler, original); const next = {handler:original}; server.upgrades.set('/api/remote.mux',next); assert.notEqual(next.handler,original); dispose(); assert.equal(next.handler,original); assert.equal(first.handler,original) } finally {dispose()}
}))
test('request body enforces byte limit', async () => { await assert.rejects(readBody(Readable.from(['x'.repeat(200000)])), e => e.status === 413) })
test('pairing code pending count is bounded', () => withStore(s => { for(let i=0;i<8;i++) s.peers.createPairingCode(); assert.throws(() => s.peers.createPairingCode(), /limit/) }))
test('revoking bearer closes already authorized upgrade', () => withStore(s => {
 const token = s.tokens.createApiToken('fixture'); let destroyed = false
 createGate(s).wrapUpgradeHandler(() => {})({url:'/api/remote.mux',headers:{authorization:`Bearer ${token.token}`},socket:{remoteAddress:'127.0.0.1'}},{destroy(){destroyed=true},once(){}})
 s.tokens.revokeApiToken(token.id)
 assert.equal(destroyed,true)
}))
test('body deadline is enforced', async () => { const request = { [Symbol.asyncIterator](){return {next(){return new Promise(()=>{})}}} }; await assert.rejects(readBody(request,{timeoutMs:10}), e=>e.status===408) })
test('malformed saved security state fails observably', () => withStore(s => { const path=join(s.dataDir,'bad.json');writeFileSync(path,'{');assert.throws(()=>readJson(path,{})) }))
test('failed atomic write keeps previous file and removes temporary', () => withStore(s => { const path=join(s.dataDir,'atomic.json'); writeJson(path,{before:true}); const bad={};bad.self=bad;assert.throws(()=>writeJson(path,bad));assert.deepEqual(JSON.parse(readFileSync(path)),{before:true});assert.equal(readdirSync(s.dataDir).some(f=>f.endsWith('.tmp')),false) }))
test('lastUsed is persisted once within throttle interval', () => withStore(s => { const token=s.tokens.createApiToken('fixture');s.tokens.verifyApiToken(token.token);const before=readFileSync(join(s.dataDir,'api-tokens.json'),'utf8');s.tokens.verifyApiToken(token.token);assert.equal(readFileSync(join(s.dataDir,'api-tokens.json'),'utf8'),before) }))
test('setup rejects a forwarded loopback request', async () => {const dir=mkdtempSync(join(tmpdir(),'han-setup-'));const s=createStore({dataDir:dir});const gate=createGate(s);try{const req=Readable.from([JSON.stringify({password:'test-password'})]);Object.assign(req,{method:'POST',url:'/dsh-local-hanaccount/api/auth/setup',socket:{remoteAddress:'127.0.0.1'},headers:{'content-type':'application/json',host:'localhost','x-real-ip':'127.0.0.1'}});let status;await createApiHandler({store:s,gate})(req,{writeHead(code){status=code},end(){}});assert.equal(status,403);assert.equal(s.cfg.passwordHash,'')}finally{gate.dispose();rmSync(dir,{recursive:true,force:true})}})
test('idle expired session is rejected', () => withStore(s => {const token=s.issueSession();s.state.sessions[token].lastSeenAt='2000-01-01T00:00:00Z';assert.equal(s.sessionFromToken(token),null)}))
test('pairing randomness does not use Math.random and attempts survive store restart', () => withStore(s => {const random=Math.random;let code;try{Math.random=()=>{throw new Error('insecure random')};code=s.peers.createPairingCode().code}finally{Math.random=random}for(let n=0;n<30;n++)assert.equal(s.peers.claimPairingCode({code:'invalid'}).ok,false);const restarted=createStore({dataDir:s.dataDir});assert.match(restarted.peers.claimPairingCode({code}).error,/limit/)}))
test('duplicate install rejected and dispose permits reapply', () => withStore(s => {const gate=createGate(s);const server={fallback:undefined,prefixes:new Map(),exact:new Map(),upgrades:new Map()};const dispose=wrapWebServer(server,gate,s);assert.throws(()=>wrapWebServer(server,gate,s),/already installed/);dispose();dispose();wrapWebServer(server,gate,s)();gate.dispose()}))
test('peer revocation closes an active upgrade', () => withStore(s => {const claimed=s.peers.claimPairingCode({code:s.peers.createPairingCode().code});const gate=createGate(s);let closed=false;gate.wrapUpgradeHandler(()=>{})({url:'/api/remote.mux',headers:{authorization:`Bearer ${claimed.token}`},socket:{remoteAddress:'127.0.0.1'}},{destroy(){closed=true},once(){}});s.peers.removePeer(claimed.peerId);assert.equal(closed,true);gate.dispose()}))
