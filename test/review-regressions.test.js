import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { spawnSync } from 'node:child_process'
import { apply } from '../src/index.js'
import { AUDITED_BUILD } from '../src/lib/dsh-adapter.js'
import { verifyAuthentication } from '../src/lib/passkey.js'

const native='dsh-auth-fixture=native'
const connection={requestRejection:req => req.headers.cookie?.split('; ').includes(native)?undefined:401,
  authenticatedUrl:() => 'http://localhost/?token=fixture',
  authorizeIndex(_req,res) {res.writeHead(303,{location:'/', 'set-cookie':`${native}; Path=/; HttpOnly; SameSite=Strict`});res.end();return false},
}
function server() {return {exact:new Map(),prefixes:new Map(),upgrades:new Map(),fallback:undefined,
  register(route) {const map=route.kind==='exact'?this.exact:this.prefixes;if(map.has(route.path))throw Error('duplicate');map.set(route.path,route);return () => map.delete(route.path)},
  registerUpgrade(route) {this.upgrades.set(route.path,route);return () => this.upgrades.delete(route.path)},
  registerFallback(handler) {this.fallback=handler;return () => {this.fallback=undefined}},
}}
async function fixture(run, passwordHash='configured') {
  const dir=mkdtempSync(join(tmpdir(),'auth-review-')),web=server();let disposer,service
  const ctx={get:key => key==='webServer'?web:connection, effect(setup) {disposer=setup()}, provide(_key,value) {service=value}}
  const config={officialBuild:AUDITED_BUILD,dataDir:dir,ipLimitEnabled:false,passwordHash}
  await apply(ctx,config)
  try {await run({dir,web,config,get store(){return service.store()},get service(){return service},dispose:() => disposer(), reapply:async() => apply(ctx,config)})}
  finally {disposer?.();rmSync(dir,{recursive:true,force:true})}
}
function response() {return {writeHead(status,headers) {this.status=status;this.headers=headers},end(body) {this.body=JSON.parse(body)}}}
function request(path,method,body,cookie='') {
  const req=body instanceof Readable?body:Readable.from([JSON.stringify(body || {})])
  return Object.assign(req,{url:`/dsh-local-hanaccount/api/${path}`,method,headers:{host:'localhost','content-type':'application/json',cookie},socket:{remoteAddress:'127.0.0.1'}})
}
function call(f,req) {const res=response();const done=f.web.prefixes.get('/dsh-local-hanaccount/api').handler(req,res);return {res,done}}
function delayedBody(body) {
  let enter,release;const entered=new Promise(resolve => {enter=resolve}),waiting=new Promise(resolve => {release=resolve})
  return {stream:Readable.from((async function*(){enter();await waiting;yield JSON.stringify(body)})()),entered,release}
}
function snapshot(f) {return ['config.json','state.json'].map(file => existsSync(join(f.dir,file))?readFileSync(join(f.dir,file),'utf8'):null)}

for(const [method,path,body] of [['PUT','config',{password:'post-revoke-password',ipLimitEnabled:true}],['POST','keys',{publicKey:'untrusted-new-key'}],['POST','api-tokens',{name:'post-revoke-token'}]]) {
  test(`delayed ${method} ${path} loses mutation authority after logout`, () => fixture(async f => {
    const token=f.store.issueSession(),cookie=`dsh_gate_token=${token}; ${native}`,deferred=delayedBody(body)
    const pending=call(f,request(path,method,deferred.stream,cookie));await deferred.entered
    const logout=call(f,request('auth/logout','POST',{},cookie));await logout.done;assert.equal(logout.res.status,200)
    const before=snapshot(f);deferred.release();await pending.done
    assert.equal(pending.res.status,401);assert.equal(pending.res.body.code,'identity_revoked');assert.deepEqual(snapshot(f),before)
    assert.equal(f.store.cfg.passwordHash,'configured');assert.equal(f.store.tokens.listApiTokensPublic().length,0);assert.equal(existsSync(f.store.keysFile),false)
  }))
}

for(const path of ['config','auth/login','auth/setup']) test(`delayed ${path} cannot write retired store after same-directory reapply`, () => fixture(async f => {
  const old=f.store,token=old.issueSession(),cookie=`dsh_gate_token=${token}; ${native}`
  const deferred=delayedBody({password:'delayed-password',ipLimitEnabled:true})
  const pending=call(f,request(path,path==='config'?'PUT':'POST',deferred.stream,cookie));await deferred.entered
  f.dispose();await f.reapply();f.store.setPasswordHash('new-generation');const fresh=f.store.issueSession(),before=snapshot(f)
  deferred.release();await pending.done;assert.equal(pending.res.status,503);assert.deepEqual(snapshot(f),before)
  assert.ok(f.store.sessionFromToken(fresh));assert.equal(f.store.cfg.passwordHash,'new-generation')
  assert.throws(() => old.saveState(),{code:'auth_unavailable'});assert.throws(() => old.tokens.createApiToken('retired'),{code:'auth_unavailable'})
},path==='auth/setup'?'':'configured'))

test('remote pairing completion revalidates revoked session before local credential writes', () => fixture(async f => {
  const original=globalThis.fetch;let enter,release;const entered=new Promise(resolve => {enter=resolve}),waiting=new Promise(resolve => {release=resolve})
  globalThis.fetch=async () => {enter();await waiting;return {ok:true,status:200,json:async() => ({token:'fixture-remote-token'})}}
  try {
    const token=f.store.issueSession(),cookie=`dsh_gate_token=${token}; ${native}`
    const pending=call(f,request('peers/connect','POST',{remoteBaseUrl:'https://fixture.invalid',code:'123456'},cookie));await entered
    f.store.logout(token);release();await pending.done
    assert.equal(pending.res.status,401);assert.equal(f.store.peers.listPeersPublic().length,0);assert.equal(existsSync(join(f.dir,'peers.json')),false)
  } finally {globalThis.fetch=original;release()}
}))

test('delayed private mutation rechecks current IP deny policy', () => fixture(async f => {
  const token=f.store.issueSession(),deferred=delayedBody({name:'denied-token'})
  const req=request('api-tokens','POST',deferred.stream,`dsh_gate_token=${token}; ${native}`);req.socket.remoteAddress='203.0.113.20'
  const pending=call(f,req);await deferred.entered
  f.store.updateConfig({deny:['203.0.113.20']});deferred.release();await pending.done
  assert.equal(pending.res.status,403);assert.equal(f.store.tokens.listApiTokensPublic().length,0)
}))

function breakFile(dir,file) {rmSync(join(dir,file));mkdirSync(join(dir,file))}
for(const kind of ['token','peer']) test(`${kind} failed revoke stops core and open bearer Upgrade synchronously`, () => fixture(async f => {
  let credential
  if(kind==='token') credential=f.store.tokens.createApiToken('fixture')
  else {const code=f.store.peers.createPairingCode();const claimed=f.store.peers.claimPairingCode({code:code.code,peerName:'fixture'});credential={id:claimed.peerId,token:claimed.token}}
  let destroyed=false;f.web.registerUpgrade({path:'/stream',handler(){}})
  const req=request('','GET',{});req.url='/stream';req.headers.cookie=native;req.headers.authorization=`Bearer ${credential.token}`
  f.web.upgrades.get('/stream').handler(req,{destroy(){destroyed=true},once(){}})
  assert.equal(destroyed,false)
  const token=f.store.issueSession(),cookie=`dsh_gate_token=${token}; ${native}`
  breakFile(f.dir,kind==='token'?'api-tokens.json':'peers.json')
  const pending=call(f,request(`${kind==='token'?'api-tokens':'peers'}/${credential.id}`,'DELETE',{},cookie));await pending.done
  assert.equal(pending.res.status,503);assert.equal(pending.res.body.code,'storage_unavailable');assert.equal(destroyed,true);assert.equal(f.service.securityState().ready,false)
}))

for(const kind of ['token','peer']) test(`${kind} failed usage persistence cannot authenticate a throttled retry`, () => fixture(async f => {
  let raw
  if(kind==='token') raw=f.store.tokens.createApiToken('fixture').token
  else {const code=f.store.peers.createPairingCode();raw=f.store.peers.claimPairingCode({code:code.code,peerName:'fixture'}).token}
  const entries=kind==='peer'?f.store.peers.inboundVerifierEntries():[]
  breakFile(f.dir,kind==='token'?'api-tokens.json':'peers.json')
  assert.throws(() => f.store.tokens.verifyAny(raw,entries),{code:'storage_unavailable'})
  assert.equal(f.service.securityState().ready,false)
  assert.throws(() => f.store.tokens.verifyAny(raw,entries),e => ['storage_unavailable','auth_unavailable'].includes(e.code))
}))

function openSessionSocket(f) {
  const token=f.store.issueSession(),cookie=`dsh_gate_token=${token}; ${native}`
  const state={destroyed:false,cookie}
  f.web.registerUpgrade({path:'/passkey-stream',handler(){}})
  const req=request('','GET',{},cookie);req.url='/passkey-stream'
  f.web.upgrades.get('/passkey-stream').handler(req,{destroy(){state.destroyed=true},once(){}})
  return state
}

test('failed passkey revoke returns normalized API failure, stops core and closes live session socket', () => fixture(async f => {
  const stored=f.store.passkeys.addCredential({credentialId:'fixture',publicKey:'ZmFrZQ'})
  const socket=openSessionSocket(f),old=f.store.passkeys
  breakFile(f.dir,'passkeys.json')
  const pending=call(f,request(`passkeys/${stored.id}`,'DELETE',{},socket.cookie));await pending.done
  assert.equal(pending.res.status,503);assert.equal(pending.res.body.code,'storage_unavailable')
  assert.equal(f.service.securityState().ready,false);assert.equal(socket.destroyed,true)
  assert.throws(() => old.findByCredentialId('fixture'),{code:'storage_unavailable'})
  rmSync(join(f.dir,'passkeys.json'),{recursive:true});await f.reapply()
  assert.throws(() => old.addCredential({credentialId:'retired'}),{code:'storage_unavailable'})
  assert.equal(existsSync(join(f.dir,'passkeys.json')),false);assert.equal(f.service.securityState().ready,true)
}))

for(const kind of ['registration','counter','challenge']) test(`failed passkey ${kind} persistence retires core before any retry can use credentials`, () => fixture(async f => {
  f.store.passkeys.addCredential({credentialId:'fixture',publicKey:'ZmFrZQ'})
  const socket=openSessionSocket(f),passkeys=f.store.passkeys
  breakFile(f.dir,'passkeys.json')
  const mutate=kind==='registration'?() => passkeys.addCredential({credentialId:'second'}):kind==='counter'?() => passkeys.updateCounter('fixture',1):() => passkeys.setChallenge('login','challenge')
  assert.throws(mutate,{code:'storage_unavailable'});assert.equal(socket.destroyed,true)
  assert.equal(f.service.securityState().ready,false)
  for(const retry of [mutate,() => passkeys.count(),() => passkeys.listForAuth(),() => passkeys.takeChallenge('login')]) assert.throws(retry,{code:'storage_unavailable'})
}))

test('successful passkey verification cannot grant authentication when counter persistence fails', () => fixture(async f => {
  const passkeys=f.store.passkeys
  passkeys.addCredential({credentialId:'fixture',publicKey:'ZmFrZQ'});passkeys.setChallenge('login','challenge')
  const socket=openSessionSocket(f)
  const pending=verifyAuthentication({headers:{host:'localhost'},socket:{remoteAddress:'127.0.0.1'}},passkeys,{id:'fixture'},async() => {
    breakFile(f.dir,'passkeys.json');return {verified:true,authenticationInfo:{newCounter:1}}
  })
  await assert.rejects(pending,{code:'storage_unavailable'})
  assert.equal(f.service.securityState().ready,false);assert.equal(socket.destroyed,true)
  assert.throws(() => passkeys.findByCredentialId('fixture'),{code:'storage_unavailable'})
}))

test('permanent guard allows removed routes, fallback owners and repeated auth stores to be garbage-collected', () => {
  const script=`
    import assert from 'node:assert/strict';
    import {createDshAdapter,AUDITED_BUILD} from './src/lib/dsh-adapter.js';
    const web={exact:new Map(),prefixes:new Map(),upgrades:new Map(),fallback:undefined,register(){},registerUpgrade(){},registerFallback(){}};
    const connection={requestRejection(){return 401},authenticatedUrl(){},authorizeIndex(){}};
    const refs=[];
    function epoch() {
      const owner={secretState:Buffer.alloc(1024)};
      const gate={wrapHttpHandler:f=>f,wrapUpgradeHandler:f=>f,dispose(){},owner};
      const adapter=createDshAdapter(web,connection,{officialBuild:AUDITED_BUILD});adapter.activate(gate);
      const original=()=>owner;
      const route={handler:original};refs.push(new WeakRef(owner),new WeakRef(route),new WeakRef(gate));
      web.exact.set('/account',route);web.exact.get('/account').handler({},{});
      web.fallback=original;web.fallback=undefined;
      web.exact.delete('/account');adapter.stop();
    }
    for(let i=0;i<50;i++)epoch();
    for(let i=0;i<10;i++){await new Promise(r=>setImmediate(r));global.gc();}
    assert.ok(refs.every(ref=>ref.deref()===undefined),'removed route or retired epoch retained');
    assert.equal(web.exact.size,0);console.log('all 150 removed owners collected; permanent closed layer remains');
  `
  const result=spawnSync(process.execPath,['--expose-gc','--input-type=module','-e',script],{cwd:new URL('..',import.meta.url),encoding:'utf8',windowsHide:true})
  assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/150 removed owners collected/)
})
