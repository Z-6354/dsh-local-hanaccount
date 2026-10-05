import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { Readable } from 'node:stream'
import { createNativeBridge } from '../src/lib/native-bridge.js'
import { createStore } from '../src/lib/store.js'
import { hashPassword } from '../src/lib/password.js'
import { createGate, wrapWebServer } from '../src/gate.js'
import { createApiHandler } from '../src/api.js'
import { verifyAuthentication } from '../src/lib/passkey.js'

function owner(overrides = {}) {
  return {
    requestRejection(req) { if (req.headers.host !== 'localhost') return 403; return req.headers.cookie === 'dsh-auth-fixture=native' ? undefined : 401 },
    authenticatedUrl() { return 'http://localhost/?token=internal-only' },
    authorizeIndex(req,res) { assert.equal(req.url,'/?token=internal-only');res.writeHead(303,{location:'/', 'set-cookie':'dsh-auth-fixture=native; Path=/; HttpOnly; SameSite=Strict'});res.end();return false },
    ...overrides,
  }
}
function fixture(fn) {
  const dir=mkdtempSync(join(tmpdir(),'native-test-'));const store=createStore({dataDir:dir,ipLimitEnabled:false});store.setPasswordHash(hashPassword('fixture-password'));const bridge=createNativeBridge(owner());const gate=createGate(store,bridge)
  return Promise.resolve().then(()=>fn({store,bridge,gate})).finally(()=>{gate.dispose();bridge.dispose();rmSync(dir,{recursive:true,force:true})})
}
async function login({store,bridge,gate}, password='fixture-password', host='localhost') {
  const req=Readable.from([JSON.stringify({password})]);Object.assign(req,{method:'POST',url:'/dsh-local-hanaccount/api/auth/login',headers:{host,'content-type':'application/json'},socket:{remoteAddress:'127.0.0.1'}})
  const response={};await createApiHandler({store,gate,bridge})(req,{writeHead(status,headers){Object.assign(response,{status,headers})},end(body){response.body=JSON.parse(body)}});return response
}
test('public native mint fences original Host and verifies minted cookie without changing request',()=>{
 const bridge=createNativeBridge(owner());const req={method:'POST',url:'/auth/login',headers:{host:'localhost'}};assert.match(bridge.mint(req,true),/; Secure$/);assert.equal(req.url,'/auth/login');assert.throws(()=>bridge.mint({...req,headers:{host:'evil'}}),{code:'access_denied'});bridge.dispose();assert.throws(()=>bridge.mint(req),{code:'native_bridge_unavailable'})
})
test('native mint accepts the official relative 303 to ./ used by dsh 0.2.1',()=>{
 const connection=owner({authorizeIndex(req,res){assert.equal(req.url,'/?token=internal-only');res.writeHead(303,{location:'./','set-cookie':'dsh-auth-fixture=native; Path=/; HttpOnly; SameSite=Strict'});res.end();return false}})
 const bridge=createNativeBridge(connection)
 assert.match(bridge.mint({method:'POST',url:'/auth/login',headers:{host:'localhost'}}),/^dsh-auth-fixture=/)
 bridge.dispose()
})
test('bridge rejects unavailable methods, unexpected response and failed official verification',()=>{
 assert.throws(()=>createNativeBridge({}),{code:'native_bridge_unavailable'});
 for(const connection of [owner({authorizeIndex(){return true}}),owner({requestRejection(){return 401}})]) assert.throws(()=>createNativeBridge(connection).mint({headers:{host:'localhost'}}),{code:'native_bridge_unavailable'})
})
test('password login publishes two independent cookies and stable rejection codes',()=>fixture(async f=>{
 const ok=await login(f);assert.equal(ok.status,200);assert.equal(ok.headers['set-cookie'].length,2);assert.deepEqual(ok.body,{ok:true,protocol:'password-native-v1'});assert.equal((await login(f,'wrong')).body.code,'invalid_password');assert.equal((await login(f,'fixture-password','evil')).status,403)
}))
test('failed storage commit never publishes either cookie and removes pending in-memory session',()=>fixture(async f=>{
 f.store.issueSession=()=>{f.store.state.sessions.pending={};throw Error('secret filesystem path')};const result=await login(f);assert.equal(result.status,503);assert.equal(result.body.code,'storage_unavailable');assert.equal(result.headers['set-cookie'],undefined);assert.deepEqual(f.store.state.sessions,{})
}))
test('fallback existing, late, replacement, owner disposal and reapply remain wrapped',()=>fixture(({store,gate})=>{
 const first=()=>{},second=()=>{};const server={exact:new Map(),prefixes:new Map(),upgrades:new Map(),fallback:first};const dispose=wrapWebServer(server,gate,store);assert.notEqual(server.fallback,first);server.fallback=undefined;assert.equal(server.fallback,undefined);server.fallback=second;assert.notEqual(server.fallback,second);dispose();assert.equal(server.fallback,second);wrapWebServer(server,gate,store)();assert.equal(server.fallback,second)
}))
test('unsupported fallback shape fails closed before mutating maps',()=>fixture(({store,gate})=>{
 const server={exact:new Map(),prefixes:new Map(),upgrades:new Map()};assert.throws(()=>wrapWebServer(server,gate,store),/fallback seat/);assert.equal(Object.hasOwn(server.exact,'set'),false)
}))
test('external token root redirects clean without invoking official mint',()=>fixture(({store,bridge})=>{
 bridge.mint=()=>{throw Error('must never mint')};const gate=createGate(store,bridge);try{let status,headers;gate.wrapHttpHandler(()=>{throw Error('must not reach SPA')})({method:'GET',url:'/?token=external',headers:{host:'localhost'},socket:{remoteAddress:'127.0.0.1'}},{writeHead(s,h){status=s;headers=h},end(){}});assert.equal(status,303);assert.equal(headers.location,'/');assert.equal(headers['set-cookie'],undefined)}finally{gate.dispose()}
}))
for (const path of ['/assets/stream','/plugins/stream']) test(`static-path upgrade ${path} requires both identities and closes on logout`,()=>fixture(({store,gate})=>{
 const token=store.issueSession();const gateCookie=`dsh_gate_token=${token}`,nativeCookie='dsh-auth-fixture=native'
 // Fixture owner's verification accepts one native cookie; retain that behavior for a bundle.
 const bridge=createNativeBridge(owner({requestRejection(req){return req.headers.cookie?.split('; ').includes(nativeCookie) ? undefined : 401}}));const protectedGate=createGate(store,bridge)
 try {
   const sockets=[];let opened=0
   for (const cookie of ['',nativeCookie,gateCookie,`${gateCookie}; ${nativeCookie}`]) {
     const socket={destroyed:false,destroy(){this.destroyed=true},once(){}};sockets.push(socket)
     protectedGate.wrapUpgradeHandler(()=>opened++)({url:path,headers:{host:'localhost',cookie},socket:{remoteAddress:'127.0.0.1'}},socket)
   }
   assert.equal(opened,1);assert.deepEqual(sockets.map(s=>s.destroyed),[true,true,true,false]);store.logout(token);assert.equal(sockets[3].destroyed,true)
 } finally {protectedGate.dispose();bridge.dispose()}
}))
test('static HTTP exemptions permit only GET/HEAD; mutation verbs require both identities',()=>fixture(({store})=>{
 const token=store.issueSession();const native='dsh-auth-fixture=native',both=`dsh_gate_token=${token}; ${native}`
 const bridge=createNativeBridge(owner({requestRejection(req){return req.headers.cookie?.split('; ').includes(native)?undefined:401}}));const gate=createGate(store,bridge)
 try {for(const path of ['/assets/business','/plugins/business']) for(const method of ['POST','PUT','DELETE']) for(const cookie of ['',native,`dsh_gate_token=${token}`,both]) {
   let status;gate.wrapHttpHandler((_req,res)=>{res.writeHead(200);res.end()})({method,url:path,headers:{host:'localhost',cookie},socket:{remoteAddress:'127.0.0.1'}},{writeHead(s){status=s},end(){}});assert.equal(status,cookie===both?200:401)
 }}finally{gate.dispose();bridge.dispose()}
}))
test('key login cannot survive keyAuthEnabled revocation while body is awaiting',()=>fixture(async f=>{
 f.store.cfg.keyAuthEnabled=true;let release;const blocked=new Promise(resolve=>{release=resolve});const req=Readable.from((async function*(){await blocked;yield '{}'})());Object.assign(req,{method:'POST',url:'/dsh-local-hanaccount/api/auth/key/verify',headers:{host:'localhost','content-type':'application/json'},socket:{remoteAddress:'127.0.0.1'}});let status,headers,body;const pending=createApiHandler(f)(req,{writeHead(s,h){status=s;headers=h},end(b){body=JSON.parse(b)}});f.store.updateConfig({keyAuthEnabled:false});release();await pending;assert.equal(status,401);assert.equal(body.code,'key_auth_disabled');assert.equal(headers['set-cookie'],undefined);assert.deepEqual(f.store.state.sessions,{})
}))
test('passkey verification rejects credential deleted during verifier await',()=>fixture(async f=>{
 const stored=f.store.passkeys.addCredential({credentialId:'fixture',publicKey:'ZmFrZQ'});f.store.passkeys.setChallenge('login','challenge');let release;const waiting=new Promise(resolve=>{release=resolve});const pending=verifyAuthentication({headers:{host:'localhost'},socket:{remoteAddress:'127.0.0.1'}},f.store.passkeys,{id:'fixture'},()=>waiting);f.store.passkeys.removeCredential(stored.id);release({verified:true,authenticationInfo:{newCounter:1}});await assert.rejects(pending,{code:'passkey_revoked'})
}))
test('passkey verification rejects a counter update that fails after successful verification',()=>fixture(async f=>{
 f.store.passkeys.addCredential({credentialId:'fixture',publicKey:'ZmFrZQ'});f.store.passkeys.setChallenge('login','challenge');f.store.passkeys.updateCounter=()=>false;await assert.rejects(verifyAuthentication({headers:{host:'localhost'},socket:{remoteAddress:'127.0.0.1'}},f.store.passkeys,{id:'fixture'},async()=>({verified:true,authenticationInfo:{newCounter:1}})),{code:'passkey_revoked'})
}))
test('final passkey grant rechecks same stored identity after await',()=>fixture(async f=>{
 const stored=f.store.passkeys.addCredential({credentialId:'fixture',publicKey:'ZmFrZQ'});let entered,release;const reached=new Promise(resolve=>{entered=resolve});const waiting=new Promise(resolve=>{release=resolve});const req=Readable.from(['{}']);Object.assign(req,{method:'POST',url:'/dsh-local-hanaccount/api/auth/passkey/login/verify',headers:{host:'localhost','content-type':'application/json'},socket:{remoteAddress:'127.0.0.1'}});let status,headers;const pending=createApiHandler({...f,verifyPasskey:async()=>{entered();await waiting;return stored}})(req,{writeHead(s,h){status=s;headers=h},end(){}});await reached;f.store.passkeys.removeCredential(stored.id);release();await pending;assert.equal(status,401);assert.equal(headers['set-cookie'],undefined);assert.deepEqual(f.store.state.sessions,{})
}))


test('persistent valid session restores official browser identity without password login',()=>fixture(({store,gate})=>{
 const token=store.issueSession();let status,headers,body
 gate.wrapHttpHandler(()=>{throw Error('must redirect before SPA')})({method:'GET',url:'/',headers:{host:'localhost',cookie:`dsh_gate_token=${token}`},socket:{remoteAddress:'127.0.0.1'}},{writeHead(s,h){status=s;headers=h},end(b){body=b}})
 assert.equal(status,303);assert.equal(headers.location,'/');assert.match(headers['set-cookie'],/^dsh-auth-fixture=native/)
 store.logout(token)
 gate.wrapHttpHandler(()=>{throw Error('revoked identity must not reach SPA')})({method:'GET',url:'/',headers:{host:'localhost',cookie:`dsh_gate_token=${token}`},socket:{remoteAddress:'127.0.0.1'}},{writeHead(s,h){status=s;headers=h},end(b){body=b}})
 assert.equal(status,200);assert.equal(headers['set-cookie'],undefined);assert.match(body,/登录/)
}))
