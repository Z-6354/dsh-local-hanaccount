// Explicit local-only contract run. Launch with cwd=audited official checkout:
// node --import tsx/esm /absolute/plugin/scripts/official-auth-fixture.mjs
// No existing DSH config, home, listener, credentials or model service is used.
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { connect } from 'node:net'
import { request as httpRequest } from 'node:http'
import { once } from 'node:events'
import { execFileSync } from 'node:child_process'
import * as Hanaccount from '../src/index.js'
import { AUDITED_BUILD, ADAPTER_ID } from '../src/lib/dsh-adapter.js'
import { createNativeBridge } from '../src/lib/native-bridge.js'
import { hashPassword } from '../src/lib/password.js'

const source=process.cwd()
assert.equal(execFileSync('git',['rev-parse','HEAD'],{cwd:source,encoding:'utf8'}).trim(),AUDITED_BUILD)
const moduleUrl = relative => pathToFileURL(join(source,relative)).href
const {Context,FiberState}=await import(moduleUrl('vendor/cordis/src/index.ts'))
const {default:Loader}=await import(moduleUrl('vendor/loader/src/index.ts'))
const {default:WebServer}=await import(moduleUrl('packages/host/webserver/src/index.ts'))
const {BrowserAuth}=await import(moduleUrl('packages/client/connection/src/browser-auth.ts'))
const {HostConnectionService}=await import(moduleUrl('packages/client/connection/src/rpc-host.ts'))

async function composition(authModule=Hanaccount, authConfig={}) {
  const dir=await mkdtemp(join(tmpdir(),'han-real-host-')),ctx=new Context()
  ctx.logger.exporter({export(message) {if (message.type==='error') console.log('fixture lifecycle error:',message.args.map(arg => arg instanceof Error ? arg.message : String(arg)).join(' '))}})
  let record
  const nativeOwner={async apply(ownerCtx) {
    const credentials={async modifyRecord(_key,update) {const next=await update(record);if(next!==undefined)record=next;return record}}
    new HostConnectionService(ownerCtx,[],await BrowserAuth.create(ctx,credentials,1))
  }}
  const routes={inject:['webServer','connection'],apply(routeCtx) {
    routeCtx.effect(() => routeCtx.webServer.register({kind:'exact',path:'/api/business',handler(req,res) {
      const rejected=routeCtx.connection.requestRejection(req)
      res.writeHead(rejected || 200);res.end(rejected?'rejected':'fixture business')
    }}))
    routeCtx.effect(() => routeCtx.webServer.registerFallback((_req,res) => {res.writeHead(200);res.end('fixture official page')}))
    routeCtx.effect(() => routeCtx.webServer.registerUpgrade({path:'/assets/stream',handler(_req,socket) {socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: fixture\r\n\r\n')}}))
    routeCtx.effect(() => routeCtx.webServer.register({kind:'exact',path:'/hanui-assets/login.css',handler(_req,res) {res.writeHead(200,{'content-type':'text/css'});res.end('body.han-login{overflow-wrap:anywhere}')}}))
  }}
  await ctx.plugin(Loader)
  const modules=new Map([['host',WebServer],['native',nativeOwner],['routes',routes],['auth',authModule]])
  ctx.loader.internal={version:'v2',async import(specifier) {if(!modules.has(specifier))throw Error('fixture import missing');return modules.get(specifier)}}
  await ctx.loader.create({name:'host',config:{host:'127.0.0.1',port:0}})
  await ctx.loader.create({name:'native'})
  await ctx.loader.create({name:'routes'})
  await ctx.loader.await()
  const canonicalOrigin=`https://127.0.0.1:${ctx.webServer.port}`
  const authId=await ctx.loader.create({name:'auth',config:{officialBuild:AUDITED_BUILD,dataDir:dir,ipLimitEnabled:false,passwordHash:hashPassword('fixture-password'),canonicalOrigin,loginStylesheetUrl:`${canonicalOrigin}/hanui-assets/login.css`,...authConfig}})
  await ctx.loader.await()
  const auth=ctx.loader.resolve(authId)
  return {ctx,auth,dir,async close(){await ctx.fiber.dispose();await rm(dir,{recursive:true,force:true})}}
}

async function request(f,path, cookie='',init={}) {
  // OS-assigned loopback ports can be on fetch's browser forbidden-port list.
  // This fixture checks server contracts, not browser/TLS rendering.
  return new Promise((resolve,reject) => {
    const req=httpRequest({hostname:'127.0.0.1',port:f.ctx.webServer.port,path,method:init.method || 'GET',headers:{cookie,...init.headers}},res => {
      const chunks=[]
      res.on('data',chunk => chunks.push(chunk));res.on('error',reject)
      res.on('end',() => resolve({status:res.statusCode,cookies:res.headers['set-cookie'] || [],body:Buffer.concat(chunks).toString()}))
    })
    req.on('error',reject);req.end(init.body)
  })
}
async function openSocket(f,cookie='') {
  const socket=connect(f.ctx.webServer.port,'127.0.0.1')
  socket.setTimeout(3000,() => socket.destroy(new Error('fixture socket timeout')))
  await once(socket,'connect')
  const result=Promise.race([once(socket,'data').then(([data]) => String(data)),once(socket,'close').then(() => '')])
  socket.write(`GET /assets/stream HTTP/1.1\r\nHost: 127.0.0.1:${f.ctx.webServer.port}\r\nCookie: ${cookie}\r\nConnection: Upgrade\r\nUpgrade: fixture\r\n\r\n`)
  return {socket,data:await result}
}

const good=await composition()
try {
  await good.auth.fiber.await()
  assert.equal((await request(good,'/api/business')).status,401)
  assert.match((await request(good,'/')).body,/data-lha-dialog/)
  const proxyHeaders={'x-forwarded-proto':'https','x-real-ip':'127.0.0.1'}
  const styled=await request(good,'/','',{headers:proxyHeaders})
  assert.match(styled.body,/<link rel="stylesheet" href="https:\/\/127\.0\.0\.1:\d+\/hanui-assets\/login.css">/)
  const stylesheet=await request(good,'/hanui-assets/login.css','',{headers:proxyHeaders})
  assert.equal(stylesheet.status,200);assert.match(stylesheet.body,/body.han-login/)
  assert.equal((await request(good,'/hanui-assets/login.css')).status,401)
  const login=await request(good,'/dsh-local-hanaccount/api/auth/login','',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:'fixture-password'})})
  assert.equal(login.status,200);assert.equal(login.cookies.length,2)
  const gate=login.cookies.find(cookie => cookie.startsWith('dsh_gate_token='))?.split(';')[0]
  const native=login.cookies.find(cookie => cookie.startsWith('dsh-auth-'))?.split(';')[0]
  const restored=await request(good,'/',gate)
  assert.equal(restored.status,303);assert.ok(restored.cookies.some(cookie=>cookie.startsWith('dsh-auth-')))
  assert.equal((await request(good,'/api/business',`${gate}; ${restored.cookies[0].split(';')[0]}`)).status,200)
  assert.ok(gate);assert.ok(native);const both=`${gate}; ${native}`
  for(const cookie of ['',gate,native]) {
    assert.equal((await request(good,'/api/business',cookie)).status,401)
    const denied=await openSocket(good,cookie);assert.equal(denied.data,'')
  }
  assert.equal((await request(good,'/api/business',both)).status,200)
  assert.equal((await request(good,'/deep/spa/path',both)).body,'fixture official page')
  const open=await openSocket(good,both);assert.match(open.data,/101/)
  const closed=once(open.socket,'close'),started=Date.now()
  assert.equal((await request(good,'/dsh-local-hanaccount/api/auth/logout',both,{method:'POST'})).status,200)
  assert.equal((await request(good,'/',gate)).cookies.length,0,'revoked persistent session cannot restore official identity')
  await closed;assert.ok(Date.now()-started<1000,'event revocation must close fixture socket within 1 second')
  assert.equal((await request(good,'/api/business',both)).status,401)
  await good.auth.fiber.dispose()
  assert.equal((await request(good,'/api/business',native)).status,503)
  assert.equal((await request(good,'/deep/spa/path',native)).status,503)
  const disposed=await openSocket(good,both);assert.equal(disposed.data,'')
  await good.ctx.loader.create({name:'auth',config:{officialBuild:AUDITED_BUILD,dataDir:good.dir,ipLimitEnabled:false,passwordHash:hashPassword('fixture-password')}})
  await good.ctx.loader.await()
  const status=await request(good,'/dsh-local-hanaccount/api/status')
  assert.equal(status.status,200);assert.equal(JSON.parse(status.body).security.ready,true)
  assert.equal(JSON.parse(status.body).security.deploymentReady,false)
  const relogin=await request(good,'/dsh-local-hanaccount/api/auth/login','',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:'fixture-password'})})
  assert.equal(relogin.status,200)
  const renewed=relogin.cookies.map(cookie => cookie.split(';')[0]).join('; ')
  const live=await openSocket(good,renewed);assert.match(live.data,/101/)
  const service=good.ctx.get('dshLocalHanaccount')
  const credential=service.store().passkeys.addCredential({credentialId:'fixture',publicKey:'ZmFrZQ'})
  await rm(join(good.dir,'passkeys.json'));await mkdir(join(good.dir,'passkeys.json'))
  const revokedSocket=once(live.socket,'close')
  const failedRevoke=await request(good,`/dsh-local-hanaccount/api/passkeys/${credential.id}`,renewed,{method:'DELETE'})
  assert.equal(failedRevoke.status,503);assert.equal(JSON.parse(failedRevoke.body).code,'storage_unavailable')
  await revokedSocket;assert.equal(service.securityState().ready,false)
  assert.equal((await request(good,'/api/business',renewed)).status,503)
  console.log('PASS real WebServer + Loader + HostConnectionService/BrowserAuth: two-cookie login, HTTP/Upgrade rejection, logout/replay, dispose deny, reapply, failed Passkey revoke closes socket/core')
} finally {await good.close()}

// Deliberate optional-plugin failure confirms why plugin throw is no ingress gate.
const failed=await composition({apply(){throw Error('intentional optional auth failure')}})
try {
  assert.equal(failed.auth.fiber.state,FiberState.FAILED)
  assert.equal((await request(failed,'/')).status,200)
  const nativeBridge=createNativeBridge(failed.ctx.connection)
  const native=nativeBridge.mint({headers:{host:`127.0.0.1:${failed.ctx.webServer.port}`},method:'GET',url:'/'}).split(';')[0]
  assert.equal((await request(failed,'/api/business',native)).status,200);nativeBridge.dispose()
  const open=await openSocket(failed);assert.match(open.data,/101/);open.socket.destroy()
  console.log('PASS optional Loader failure: sibling HTTP/Upgrade remains exposed (DEPLOYMENT BLOCKED)')
} finally {await failed.close()}

const unsupported=await composition(Hanaccount,{officialBuild:'unrecognized-build'})
try {
  assert.equal(unsupported.auth.fiber.state,FiberState.FAILED)
  assert.equal((await request(unsupported,'/')).status,200)
  const nativeBridge=createNativeBridge(unsupported.ctx.connection)
  const native=nativeBridge.mint({headers:{host:`127.0.0.1:${unsupported.ctx.webServer.port}`},method:'GET',url:'/'}).split(';')[0]
  assert.equal((await request(unsupported,'/api/business',native)).status,200);nativeBridge.dispose()
  console.log('PASS unknown build refuses activation; optional Loader still serves sibling fallback (DEPLOYMENT BLOCKED)')
} finally {await unsupported.close()}
console.log(JSON.stringify({officialBuild:AUDITED_BUILD,adapterId:ADAPTER_ID,node:process.version,cordis:'4.0.2 source',deploymentReady:false}))
