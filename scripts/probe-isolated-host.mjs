// Explicit, isolated official CLI composition; never addresses a pre-existing host.
import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createRequire } from 'node:module'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
const password = `isolated-${randomBytes(18).toString('hex')}`
const serve = process.argv.includes('--serve-for-qa')
const root = resolve(process.argv[2] || '')
if (!process.argv[2] || !existsSync(join(root,'apps/cli/src/bin.ts'))) throw new Error('explicit official checkout required')
const requireHost = createRequire(join(root,'package.json'))
const temporary = mkdtempSync(join(tmpdir(),'han-host-probe-'))
const patch = join(temporary,'probe.yml')
const plugin = pathToFileURL(resolve('src/index.js')).href
const observerFile = join(temporary,'observer.mjs')
const observations = join(temporary,'observations.jsonl')
writeFileSync(observerFile, `import {appendFileSync} from 'node:fs'; import {createRequire} from 'node:module'; const {WebSocketServer}=createRequire(${JSON.stringify(join(root,'packages/api/gateway/package.json'))})('ws'); export const name='isolated-observer'; export const inject=['webServer']; export function apply(ctx) {
 ctx.on('session/event',(session,event)=>appendFileSync(${JSON.stringify(observations)},JSON.stringify({sessionId:session.id,seq:event.seq,type:event.type,logLength:session.seq})+'\\n'),{global:true});
 const server=ctx.get('webServer');
 const fixtureWs=new WebSocketServer({noServer:true});ctx.effect(()=>()=>{for(const s of fixtureWs.clients)s.terminate();fixtureWs.close()});
 for(const path of ['/assets/stream','/plugins/stream']) ctx.effect(()=>server.registerUpgrade({path,handler(req,socket,head){fixtureWs.handleUpgrade(req,socket,head,s=>fixtureWs.emit('connection',s,req))}}));
 for(const path of ['/assets/business','/plugins/business']) ctx.effect(()=>server.register({kind:'exact',path,handler(req,res){res.writeHead(200);res.end('fixture')}}));
 const register=()=>server.registerUpgrade({path:'/isolated-upgrade',handler(req,socket){socket.end('HTTP/1.1 418 Probe\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n')}});
 let unreg=register();ctx.effect(()=>()=>unreg());
 ctx.effect(()=>server.register({kind:'exact',path:'/isolated-upgrade-control',handler(req,res){unreg();unreg=register();res.writeHead(200);res.end('replaced')}}));
}`)
writeFileSync(patch, `- insert:\n    - id: isolated-hanaccount\n      name: ${JSON.stringify(plugin)}\n      config:\n        dataDir: ${JSON.stringify(join(temporary,'plugin'))}\n        ipLimitEnabled: false\n    - id: isolated-observer\n      name: ${JSON.stringify(pathToFileURL(observerFile).href)}\n`)
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/KEY|SECRET|TOKEN|PASSWORD|DSH_|DEEPSEEK_/i.test(key)))
Object.assign(env,{DSH_HOME:join(temporary,'home'),DSH_AGENTS_HOME:join(temporary,'agents'),DSH_TELEMETRY_DISABLED:'1',DEEPSEEK_API_KEY:'isolated-no-model',DEEPSEEK_BASE_URL:'http://127.0.0.1:1',TSX_TSCONFIG_PATH:join(root,'tsconfig.json'),NODE_NO_WARNINGS:'1'})
const child = spawn(process.execPath,['--import',pathToFileURL(requireHost.resolve('tsx/esm')).href,join(root,'apps/cli/src/bin.ts'),'web','--patch',patch,'--no-open','--port','0'],{cwd:temporary,env,windowsHide:true,stdio:['ignore','pipe','pipe']})
const sockets = []
let output = ''; let launch
child.stdout.on('data',chunk => { output += chunk; launch ||= output.match(/dsh web: (http:\/\/[^/\s]+)/)?.[1] })
child.stderr.on('data',chunk => { output += chunk })
try {
 const deadline = Date.now()+60000
 while (!launch && Date.now()<deadline && child.exitCode === null) await new Promise(r=>setTimeout(r,100))
 if (!launch) throw new Error(`isolated Host not ready (exit=${child.exitCode}); diagnostics: ${output.replace(/token=[^\s]+/g,'token=[redacted]').slice(-1800)}`)
 const origin = new URL(launch).origin
 assert.equal(new URL(origin).hostname,'127.0.0.1')
 const request = (path, options={}) => { assert.ok(!new URL(origin+path).searchParams.has('token')); return fetch(origin+path,{...options,signal:AbortSignal.timeout(10000),redirect:'manual'}) }
 const status = await request('/dsh-local-hanaccount/api/status')
 assert.equal(status.status,200,'plugin status mounted')
 assert.equal((await request('/dsh-local-hanaccount/api/status',{headers:{origin:'null'}})).status,403,'null Origin fence')
 assert.equal((await request('/dsh-local-hanaccount/api/status',{headers:{origin:'https://attacker.invalid'}})).status,403,'foreign Origin fence')
 assert.equal((await request('/dsh-local-hanaccount/api/status',{headers:{'sec-fetch-site':'cross-site'}})).status,403,'cross-site fence')
 const setup = await request('/dsh-local-hanaccount/api/auth/setup',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password})})
 assert.equal(setup.status,200,'loopback setup')
 const setupCookies = setup.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ')
 assert.equal((await request('/dsh-local-hanaccount/api/auth/logout',{method:'POST',headers:{cookie:setupCookies}})).status,200)
 const login = await request('/dsh-local-hanaccount/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password})})
 assert.equal(login.status,200,'clean origin password login')
 assert.equal((await login.json()).protocol,'password-native-v1')
 const cookies = login.headers.getSetCookie().map(c=>c.split(';')[0])
 assert.equal(cookies.length,2)
 const pluginCookie = cookies.find(c=>c.startsWith('dsh_gate_token='))
 const nativeCookie = cookies.find(c=>c.startsWith('dsh-auth-'))
 assert.ok(nativeCookie && pluginCookie)
 const authHeaders = {cookie:`${pluginCookie}; ${nativeCookie}`,'content-type':'application/json'}
 for(const path of ['/assets/business','/plugins/business']) for(const method of ['POST','PUT','DELETE']) {
   for(const headers of [{},{cookie:nativeCookie},{cookie:pluginCookie}]) assert.equal((await request(path,{method,headers})).status,401,'static HTTP mutation requires dual identity')
   assert.equal((await request(path,{method,headers:authHeaders})).status,200,'dual identity reaches static-path HTTP mutation fixture')
 }
 const tokenResponse = await request('/dsh-local-hanaccount/api/api-tokens',{method:'POST',headers:authHeaders,body:JSON.stringify({name:'probe'})})
 assert.equal(tokenResponse.status,200)
 const {token} = await tokenResponse.json()
 const rpc = (headers, method='session/list', args={_request:{}}) => request('/api/'+method,{method:'POST',headers:{'content-type':'application/json',...headers},body:JSON.stringify({type:'client-request',rpcId:'probe',method,payload:{args}})})
 assert.equal((await rpc({})).status,401)
 assert.equal((await rpc({cookie:pluginCookie})).status,401,'gate cookie alone insufficient')
 assert.equal((await rpc({cookie:nativeCookie})).status,401,'native cookie alone insufficient')
 const me = await (await request('/dsh-local-hanaccount/api/auth/me',{headers:authHeaders})).json()
 assert.equal(me.authenticated,true); assert.equal(me.nativeAuthenticated,true)
 assert.equal((await rpc({authorization:`Bearer ${token.token}`})).status,401,'plugin bearer alone does not satisfy native auth')
 const listed = await rpc(authHeaders)
 assert.equal(listed.status,200)
 assert.equal((await listed.json()).result.ok,true,'native RPC business result')
 const WebSocket = createRequire(join(root,'packages/api/gateway/package.json'))('ws')
 async function upgradeOutcome(path, headers) {
   const socket = new WebSocket(origin.replace('http:','ws:')+path,{headers}); sockets.push(socket)
   return new Promise((resolve,reject)=>{
     const timer=setTimeout(()=>{socket.terminate();reject(new Error('upgrade outcome deadline'))},5000)
     socket.once('open',()=>{clearTimeout(timer);socket.terminate();resolve(101)})
     socket.once('unexpected-response',(_req,res)=>{clearTimeout(timer);res.resume();socket.terminate();resolve(res.statusCode)})
     socket.on('error',()=>{clearTimeout(timer);resolve(0)})
   })
 }
 assert.equal(await upgradeOutcome('/api/remote.mux',{}),0,'unauthenticated actual mux upgrade denied')
 const staticSockets=[]
 for (const path of ['/assets/stream','/plugins/stream']) {
   for (const headers of [{},{cookie:nativeCookie},{cookie:pluginCookie}]) assert.equal(await upgradeOutcome(path,headers),0,`${path} requires both identities`)
   const socket=new WebSocket(origin.replace('http:','ws:')+path,{headers:authHeaders});sockets.push(socket);staticSockets.push(socket)
   await new Promise((resolve,reject)=>{socket.once('open',resolve);socket.once('error',reject)})
 }
 assert.equal(await upgradeOutcome('/isolated-upgrade',{}),0,'late registered upgrade denied')
 assert.equal(await upgradeOutcome('/isolated-upgrade',authHeaders),418,'authenticated late route reached')
 assert.equal((await request('/isolated-upgrade-control',{headers:authHeaders})).status,200)
 assert.equal((await request('/isolated-upgrade-control')).status,401,'dynamic HTTP route remains gated')
 assert.equal(await upgradeOutcome('/isolated-upgrade',{}),0,'same path replacement still denied')
 assert.equal(await upgradeOutcome('/isolated-upgrade',authHeaders),418,'replacement route reached')
 const ws = new WebSocket(origin.replace('http:','ws:')+'/api/remote.mux',{headers:authHeaders}); sockets.push(ws)
 await new Promise((resolve,reject)=>{const t=setTimeout(()=>reject(new Error('WS upgrade deadline')),5000);ws.once('open',()=>{clearTimeout(t);resolve()});ws.once('error',e=>{clearTimeout(t);reject(e)})})
 const ready = new Promise((resolve,reject)=>{const t=setTimeout(()=>reject(new Error('mux ready deadline')),5000);ws.on('message',raw=>{const frame=JSON.parse(String(raw));if(frame.type==='item'&&frame.value?.type==='ready'){clearTimeout(t);resolve(frame)}})})
 ws.send(JSON.stringify({type:'open',streamId:'probe-events',endpoint:'$events',payload:{args:{}}}))
 await ready
 const created = await (await rpc(authHeaders,'session/create',{request:{sessionId:'isolated-probe-session',cwd:temporary}})).json()
 assert.equal(created.result.ok,true,JSON.stringify(created.result))
 const renamed = await (await rpc(authHeaders,'session/rename',{request:{sessionId:'isolated-probe-session',title:'isolated probe'}})).json()
 assert.equal(renamed.result.ok,true,JSON.stringify(renamed.result))
 const snapshot = new Promise((resolve,reject)=>{const t=setTimeout(()=>reject(new Error('session snapshot deadline')),5000);ws.on('message',raw=>{const frame=JSON.parse(String(raw));if(frame.streamId==='probe-session'&&frame.value?.type==='snapshot'){clearTimeout(t);resolve(frame.value)}})})
 ws.send(JSON.stringify({type:'open',streamId:'probe-session',endpoint:'session/follow',payload:{args:{request:{address:{kind:'session',sessionId:'isolated-probe-session'}}}}}))
 const baseline = await snapshot
 assert.ok(baseline.cursor >= renamed.result.value.seq)
 const observed = readFileSync(observations,'utf8').trim().split('\n').map(line=>JSON.parse(line))
 assert.ok(observed.some(row=>row.sessionId==='isolated-probe-session'&&row.seq===renamed.result.value.seq))
 // Revoke the exact bearer owning another active socket; no native signature fabrication.
 const bearerWs = new WebSocket(origin.replace('http:','ws:')+'/api/remote.mux',{headers:{cookie:nativeCookie,authorization:`Bearer ${token.token}`}}); sockets.push(bearerWs)
 await new Promise((resolve,reject)=>{bearerWs.once('open',resolve);bearerWs.once('error',reject)})
 const revoked = new Promise((resolve,reject)=>{const t=setTimeout(()=>reject(new Error('active WS revoke deadline')),5000);bearerWs.once('close',()=>{clearTimeout(t);resolve()})})
 assert.equal((await request('/dsh-local-hanaccount/api/api-tokens/'+token.id,{method:'DELETE',headers:authHeaders})).status,200)
 await revoked
 assert.equal((await request('/dsh-local-hanaccount/api/config',{method:'PUT',headers:authHeaders,body:JSON.stringify({ipLimitEnabled:false,deny:['203.0.113.77']})})).status,200)
 assert.equal((await rpc({...authHeaders,'x-real-ip':'203.0.113.77'})).status,403,'deny independent of disabled allowlist')
 assert.equal(await upgradeOutcome('/api/remote.mux',{...authHeaders,'x-real-ip':'203.0.113.77'}),0,'denied actual mux upgrade')
 if (serve) {
   console.log(JSON.stringify({qaOrigin:origin,fixturePassword:password,sessionId:'isolated-probe-session',expiresInSec:1800}))
   await new Promise(resolve=>{const timeout=setTimeout(resolve,1800000); process.stdin.resume(); process.stdin.once('data',()=>{clearTimeout(timeout);resolve()})})
 } else {
   const staticClosed=staticSockets.map(socket=>new Promise((resolve,reject)=>{const t=setTimeout(()=>reject(new Error('static-path logout socket close deadline')),5000);socket.once('close',()=>{clearTimeout(t);resolve()})}))
   const closed = new Promise((resolve,reject)=>{const t=setTimeout(()=>reject(new Error('logout socket close deadline')),5000);ws.once('close',()=>{clearTimeout(t);resolve()})})
   assert.equal((await request('/dsh-local-hanaccount/api/auth/logout',{method:'POST',headers:authHeaders})).status,200)
   await closed
   await Promise.all(staticClosed)
   assert.equal((await rpc(authHeaders)).status,401)
   const rootAfter = await request('/',{headers:{cookie:nativeCookie}})
   assert.equal(rootAfter.status,200); assert.match(await rootAfter.text(),/Harness sign in/)
 }
 console.log(JSON.stringify({node:process.version,pluginStatus:true,loopbackSetup:true,passwordNativeBridge:true,dualCookieMe:true,singleCookieRejected:true,logoutSocketClosed:!serve,logoutRootProtected:!serve,unauthenticatedRejected:true,bearerOnlyNativeRejected:true,cookieRpc:true,remoteMuxReady:true,sessionEventObserved:true,canonicalSnapshot:true,activeBearerWsRevoked:true,staticHttpMutationDualAuth:true,staticUpgradeDualAuth:true,staticUpgradeLogoutClosed:!serve,dynamicUpgradeProtected:true,replacementProtected:true,denyIndependent:true,scopedDeviceCredentials:false,durableNotificationReplay:false}))
} finally {
 for (const ws of sockets) ws.terminate()
 if (process.platform === 'win32' && child.exitCode === null) spawnSync('taskkill',['/PID',String(child.pid),'/T','/F'],{windowsHide:true,stdio:'ignore'})
 else child.kill()
 await Promise.race([new Promise(r=>child.once('exit',r)),new Promise(r=>setTimeout(r,5000))])
 if(child.exitCode===null) child.kill('SIGKILL')
 rmSync(temporary,{recursive:true,force:true})
}
