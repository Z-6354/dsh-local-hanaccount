import test from 'node:test'
import assert from 'node:assert/strict'
import { Script, createContext } from 'node:vm'
import { renderLoginPage } from '../src/lib/login-page.js'

test('standalone login emits runnable script with nonce-only assets and previous dialog styling', () => {
  const html = renderLoginPage('test-nonce')
  const script = html.match(/<script nonce="test-nonce">([\s\S]*?)<\/script>/)[1]
  assert.doesNotThrow(() => new Script(script))
  assert.match(html, /<style nonce="test-nonce">/)
  assert.match(html, /data-lha-dialog/)
  assert.match(html, /border-radius:24px/)
  assert.match(html, /输入访问密码以继续使用 DSH/)
  assert.doesNotMatch(html, /\sstyle=|\sonclick=|Harness sign in|\?token=/)
})

const tick = () => new Promise(resolve => setImmediate(resolve))

test('设备缓存桥无响应时，登录表单等待不超过一秒半', async () => {
  const delays = []
  await page({passwordConfigured:true}, () => assert.fail(), {
    window:{HanApp:{postMessage(){}}},
    setTimeout:(_,delay)=>{delays.push(delay);return delays.length}, clearTimeout(){}
  })
  assert.ok(Math.max(0, ...delays.filter(delay => delay < 8000))<=1500, `实际等待 ${delays.join(',')} 毫秒`)
})
async function page(me, login, options = {}) {
  const elements = new Map(), redirects = [], requests = [], cancelStates = [], readiness = []
  const bridge = options.window?.HanApp
  if (bridge) {
    const post = bridge.postMessage
    bridge.postMessage = raw => { const message = JSON.parse(raw); if (message.type === 'pageReady') readiness.push(message); else post.call(bridge, raw) }
  }
  const element = id => {
    if (!elements.has(id)) {
      const node = {value:'',hidden:false,disabled:false,textContent:'',attributes:{},classList:{toggle(){}},setAttribute(name,value){this.attributes[name]=value},hasAttribute(name){return Object.hasOwn(this.attributes,name)},removeAttribute(name){delete this.attributes[name]}}
      if (id === 'cancel') {
        let hidden = true // Initial HTML hides this control.
        Object.defineProperty(node, 'hidden', {get:() => hidden,set(value){hidden=!!value;cancelStates.push(hidden)}})
      }
      elements.set(id,node)
    }
    return elements.get(id)
  }
  element('body').setAttribute('data-checking','')
  element('submit').textContent='继续'
  element('passkeyButton').textContent='使用 Passkey 登录'
  const context = createContext({document:{body:element('body'),getElementById:element,querySelector:()=>element('dialog')},
    URL,setTimeout:options.setTimeout||setTimeout,clearTimeout:options.clearTimeout||clearTimeout,window:options.window||{},confirm:()=>true,AbortController,isSecureContext:!!options.passkey,PublicKeyCredential:options.passkey?function(){}:undefined,location:{hostname:'fixture.test',port:'',protocol:'https:',origin:'https://fixture.test',assign:url=>redirects.push(url),replace:url=>redirects.push(url),...options.location},
    fetch:async (url, requestOptions) => {
      requests.push({url,options:requestOptions})
      if(url.endsWith('/auth/me')){
        if(options.hangMe) return new Promise((_,reject)=>{
          const fail=()=>reject(Object.assign(new Error('aborted'),{name:'AbortError'}))
          if(requestOptions.signal?.aborted) return fail()
          requestOptions.signal?.addEventListener('abort',fail)
        })
        if(options.meFailure?.())throw Error('network');return {ok:true,json:async()=>options.mePromise||me}
      }
      return login(requestOptions)
    }})
  new Script(renderLoginPage('nonce').match(/<script nonce="nonce">([\s\S]*?)<\/script>/)[1]).runInContext(context)
  await tick()
  return {element,redirects,requests,context,cancelStates,readiness}
}

test('previous login form reports refusal and redirects only after successful password login', async () => {
  let accepted=false
  const p=await page({passwordConfigured:true,authenticated:false,ip:'127.0.0.1',whitelisted:true},async()=>({ok:accepted,json:async()=>accepted?{ok:true}:{code:'invalid_password'}}))
  p.element('password').value='fixture-password';p.element('password').oninput()
  p.element('form').onsubmit({preventDefault(){}});await tick()
  assert.match(p.element('error').textContent,/密码不正确/);assert.deepEqual(p.redirects,[])
  accepted=true;p.element('form').onsubmit({preventDefault(){}});await tick()
  assert.deepEqual(p.redirects,['/']);assert.equal(p.element('password').value,'')
  assert.equal(JSON.parse(p.requests.at(-1).options.body).password,'fixture-password')
})

test('unchanged loopback HTTP keeps local setup origin',async()=>{
  const p=await page({passwordConfigured:false},async()=>({ok:true,json:async()=>({ok:true})}),{location:{hostname:'127.0.0.1',port:'8080',protocol:'http:',origin:'http://127.0.0.1:8080'}})
  p.element('password').value=p.element('confirm').value='fixture-secret';p.element('password').oninput()
  assert.equal(p.element('submit').disabled,false)
  p.element('form').onsubmit({preventDefault(){}});await tick()
  assert.match(p.requests.at(-1).url,/auth\/setup$/)
})

test('editing a target exits Passkey mode and refuses old-server Passkey operations',async()=>{
  const p=await page({passwordConfigured:true,passkey:{available:true,count:1}},async()=>assert.fail('old-server auth must not run'),{passkey:true})
  assert.equal(p.element('form').hidden,false)
  p.element('passkeyTab').onclick();assert.equal(p.element('form').hidden,true)
  p.element('serverHost').value='other.test';p.element('serverHost').oninput()
  assert.equal(p.element('form').hidden,false);assert.equal(p.element('passkeyButton').disabled,true)
  p.element('passkeyButton').onclick();await tick();assert.equal(p.requests.length,1)
})

test('native remembered password arrives only while the matching target remains selected',async()=>{
  let deliverRead;const bridge={postMessage(raw){const request=JSON.parse(raw);if(request.type==='capabilities')queueMicrotask(()=>bridge.onmessage({data:JSON.stringify({version:1,id:request.id,ok:true,result:{credentialStorage:true}})}));else if(request.type==='readCredential')deliverRead=()=>bridge.onmessage({data:JSON.stringify({version:1,id:request.id,ok:true,result:{saved:true,password:'fixture-secret'}})})}}
  const p=await page({passwordConfigured:true},async()=>assert.fail('no password POST'),{window:{HanApp:bridge}})
  await tick();assert.equal(typeof deliverRead,'function')
  p.element('serverHost').value='other.test';p.element('serverHost').oninput();deliverRead();await tick()
  assert.equal(p.element('password').value,'');assert.equal(p.requests.length,1)
})

test('first setup requires confirmation and uses setup endpoint',async()=>{
  const p=await page({passwordConfigured:false},async()=>({ok:true,json:async()=>({ok:true})}))
  assert.equal(p.element('title').textContent,'设置访问密码')
  p.element('password').value='fixture-password';p.element('password').oninput()
  assert.equal(p.element('submit').disabled,true)
  p.element('confirm').value='fixture-password';p.element('confirm').oninput()
  assert.equal(p.element('submit').disabled,false)
  p.element('form').onsubmit({preventDefault(){}});await tick()
  assert.match(p.requests.at(-1).url,/auth\/setup$/)
})

test('访问检查请求一直挂起时会在超时后揭开登录表单',async()=>{
  const p=await page({passwordConfigured:true},()=>assert.fail('login must not run'),{
    hangMe:true,
    window:{HanApp:{postMessage(){}}},
    setTimeout:(fn,delay)=>{if(delay>=8000){fn();return 1}return 0},
    clearTimeout(){}
  })
  await tick();await tick()
  assert.equal(p.element('body').hasAttribute('data-checking'),false)
  assert.match(p.element('error').textContent,/连接暂不可用/)
  assert.equal(p.readiness.at(-1)?.type,'pageReady')
})

test('cancel aborts the pending request without navigating',async()=>{
  const p=await page({passwordConfigured:true},options=>new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(Object.assign(new Error('cancel'),{name:'AbortError'})))))
  p.element('password').value='fixture-password';p.element('password').oninput()
  p.element('form').onsubmit({preventDefault(){}});p.element('cancel').onclick();await tick()
  assert.equal(p.requests.at(-1).options.signal.aborted,true)
  assert.deepEqual(p.redirects,[]);assert.equal(p.element('status').textContent,'已取消')
})

test('editing the server clears secrets and refuses password POST to the old server',async()=>{
  const p=await page({passwordConfigured:true},async()=>({ok:true,json:async()=>({ok:true})}))
  p.element('password').value='fixture-secret'
  p.element('serverHost').value='other.test';p.element('serverHost').oninput()
  assert.equal(p.element('password').value,'');assert.equal(p.element('password').disabled,true)
  p.element('password').value='new-secret';p.element('password').oninput()
  p.element('form').onsubmit({preventDefault(){}});await tick()
  assert.equal(p.requests.length,1)
  assert.deepEqual(p.redirects,['https://other.test/']);assert.equal(p.element('password').value,'')
})

test('overlapping native replies in either order restore the original handler',async()=>{
  for(const order of [[0,1],[1,0]]){
    const sent=[];let forwarded=0;const original=()=>forwarded++
    const bridge={onmessage:original,postMessage:raw=>sent.push(JSON.parse(raw))}
    const p=await page({passwordConfigured:false},()=>assert.fail(),{window:{HanApp:bridge}})
    const first=new Script("platform('readCredential')").runInContext(p.context)
    const second=new Script("platform('capabilities')").runInContext(p.context)
    bridge.onmessage({data:JSON.stringify({version:1,id:'unrelated',ok:true,result:{}})})
    assert.equal(forwarded,1)
    for(const i of order)bridge.onmessage({data:JSON.stringify({version:1,id:sent[i].id,ok:true,result:{index:i}})})
    assert.equal((await first).index,0);assert.equal((await second).index,1)
    assert.equal(bridge.onmessage,original)
  }
})

test('native request timeout restores previous handler without retaining finished requests',async()=>{
  const timers=new Map();let sequence=0;const original=()=>{}
  const bridge={onmessage:original,postMessage(){}}
  const p=await page({passwordConfigured:false},()=>assert.fail(),{window:{HanApp:bridge},setTimeout:callback=>{const id=++sequence;timers.set(id,callback);return id},clearTimeout:id=>timers.delete(id)})
  const pending=new Script("platform('readCredential')").runInContext(p.context)
  const rejected=assert.rejects(pending,/platform_timeout/)
  const expire=timers.values().next().value;expire();await rejected
  assert.equal(bridge.onmessage,original)
  assert.equal(new Script('platformPending.size').runInContext(p.context),0)
})

test('capability handshake retries an early dropped message and stops after reply',async()=>{
  const timers=new Map();let sequence=0;const sent=[];const original=()=>{}
  const bridge={onmessage:original,postMessage:raw=>sent.push(JSON.parse(raw))}
  const p=await page({passwordConfigured:false},()=>assert.fail(),{window:{HanApp:bridge},setTimeout:(callback,delay)=>{const id=++sequence;timers.set(id,{callback,delay});return id},clearTimeout:id=>timers.delete(id)})
  const pending=new Script("platform('capabilities')").runInContext(p.context)
  const [retryId,retry]=[...timers].find(([,timer])=>timer.delay===200)
  timers.delete(retryId);retry.callback()
  assert.equal(sent.length,2);assert.equal(sent[0].id,sent[1].id)
  bridge.onmessage({data:JSON.stringify({version:1,id:sent[1].id,ok:true,result:{credentialStorage:true}})})
  assert.equal((await pending).credentialStorage,true)
  assert.equal(timers.size,0);assert.equal(bridge.onmessage,original)
})

test('only successful password login requests native encryption before clearing the input',async()=>{
  const calls=[];let accepted=false
  const bridge={postMessage(raw){const request=JSON.parse(raw);calls.push(request);queueMicrotask(()=>bridge.onmessage({data:JSON.stringify({version:1,id:request.id,ok:true,result:request.type==='capabilities'?{credentialStorage:true}:request.type==='readCredential'?{saved:false}:{saved:true}})}))}}
  const p=await page({passwordConfigured:true},async()=>({ok:accepted,json:async()=>accepted?{ok:true}:{code:'invalid_password'}}),{window:{HanApp:bridge}})
  p.element('password').value='fixture-secret';p.element('password').oninput()
  p.element('form').onsubmit({preventDefault(){}});await tick()
  assert.equal(calls.some(call=>call.type==='saveCredential'),false)
  accepted=true;p.element('form').onsubmit({preventDefault(){}});await tick()
  assert.deepEqual(calls.filter(call=>call.type==='saveCredential').map(call=>call.payload),[{password:'fixture-secret'}])
  assert.deepEqual(p.redirects,['/']);assert.equal(p.element('password').value,'')
})

test('departing during optional encryption cancels the login continuation and redirect',async()=>{
  const events=new Map(),calls=[];const bridge={postMessage:raw=>calls.push(JSON.parse(raw))}
  const p=await page({passwordConfigured:false},async()=>({ok:true,json:async()=>({ok:true})}),{window:{HanApp:bridge,addEventListener:(name,callback)=>events.set(name,callback)}})
  p.element('password').value=p.element('confirm').value='fixture-secret';p.element('password').oninput()
  p.element('form').onsubmit({preventDefault(){}});await tick();assert.equal(calls.length,1)
  events.get('pagehide')();await tick()
  assert.deepEqual(p.redirects,[]);assert.equal(calls.length,1)
  assert.equal(new Script('platformPending.size').runInContext(p.context),0)
})

test('departing during a password request prevents a late response from saving or navigating',async()=>{
  const events=new Map(),calls=[];let finish
  const p=await page({passwordConfigured:false},()=>new Promise(resolve=>{finish=resolve}),{window:{HanApp:{postMessage:raw=>calls.push(raw)},addEventListener:(name,callback)=>events.set(name,callback)}})
  p.element('password').value=p.element('confirm').value='fixture-secret';p.element('password').oninput()
  p.element('form').onsubmit({preventDefault(){}});await tick()
  events.get('pagehide')();finish({ok:true,json:async()=>({ok:true})});await tick()
  assert.deepEqual(p.redirects,[]);assert.deepEqual(calls,[])
  assert.equal(p.requests.at(-1).options.signal.aborted,true)
})

test('cached device password logs in automatically without revealing the login form',async()=>{
  const bridge={postMessage(raw){const req=JSON.parse(raw);queueMicrotask(()=>bridge.onmessage({data:JSON.stringify({version:1,id:req.id,ok:true,result:req.type==='capabilities'?{credentialStorage:true}:{saved:true,password:'fixture-secret'}})}))}}
  const p=await page({passwordConfigured:true},async()=>({ok:true,json:async()=>({ok:true})}),{window:{HanApp:bridge}})
  await tick()
  assert.deepEqual(p.redirects,['/']);assert.equal(p.requests.length,2)
  assert.equal(JSON.parse(p.requests[1].options.body).password,'fixture-secret')
  assert.equal(Object.hasOwn(p.element('body').attributes,'data-checking'),true)
})

test('pending cached auto-login never flashes Cancel or reveals manual controls',async()=>{
  let finish
  const bridge={postMessage(raw){const req=JSON.parse(raw);queueMicrotask(()=>bridge.onmessage({data:JSON.stringify({version:1,id:req.id,ok:true,result:req.type==='capabilities'?{credentialStorage:true}:{saved:true,password:'fixture-secret'}})}))}}
  const p=await page({passwordConfigured:true},()=>new Promise(resolve=>{finish=resolve}),{window:{HanApp:bridge}})
  await tick()
  assert.equal(typeof finish,'function');assert.equal(p.requests.length,2)
  assert.equal(p.element('body').hasAttribute('data-checking'),true)
  assert.equal(p.element('cancel').hidden,true)
  assert.equal(p.element('status').textContent,'登录中…')
  p.element('form').onsubmit({preventDefault(){}});await tick()
  assert.equal(p.requests.length,2,'busy auto-login must not repeat the password POST')
  finish({ok:true,json:async()=>({ok:true})});await tick()
  assert.deepEqual(p.redirects,['/'])
  assert.equal(p.element('body').hasAttribute('data-checking'),true)
  assert.equal(p.cancelStates.includes(false),false,'Cancel must remain hidden throughout the operation')
})

for(const setup of [false,true]) test(`manual ${setup?'setup':'login'} shows progress on Continue without a separate Cancel control`,async()=>{
  let finish
  const p=await page({passwordConfigured:!setup},()=>new Promise(resolve=>{finish=resolve}))
  p.element('password').value=p.element('confirm').value='fixture-secret';p.element('password').oninput()
  const label=p.element('submit').textContent
  assert.equal(p.element('body').hasAttribute('data-checking'),false)
  p.element('form').onsubmit({preventDefault(){}})
  assert.equal(p.element('submit').textContent,'登录中…');assert.equal(p.element('submit').disabled,true)
  assert.equal(p.element('cancel').hidden,true);assert.equal(p.element('status').textContent,'')
  assert.equal(p.element('form').hidden,false)
  finish({ok:false,json:async()=>({code:'invalid_password'})});await tick()
  assert.equal(p.element('submit').textContent,label);assert.equal(p.element('submit').disabled,false)
  assert.equal(p.cancelStates.includes(false),false);assert.deepEqual(p.redirects,[])
  assert.match(p.element('error').textContent,/密码不正确/)
  assert.equal(p.requests.length,2,'manual action must send one password request')
})

test('missing or rejected cached device password reveals login and does not retry automatically',async()=>{
  for(const saved of [false,true]){
    const bridge={postMessage(raw){const req=JSON.parse(raw);queueMicrotask(()=>bridge.onmessage({data:JSON.stringify({version:1,id:req.id,ok:true,result:req.type==='capabilities'?{credentialStorage:true}:saved?{saved:true,password:'fixture-secret'}:{saved:false}})}))}}
    const p=await page({passwordConfigured:true},async()=>({ok:false,json:async()=>({code:'invalid_password'})}),{window:{HanApp:bridge}})
    await tick();assert.deepEqual(p.redirects,[])
    assert.equal(p.requests.length,saved?2:1)
    assert.equal(Object.hasOwn(p.element('body').attributes,'data-checking'),false)
    if(saved)assert.match(p.element('error').textContent,/密码不正确/)
  }
})

test('returning after interrupted cached-password lookup reveals the login without retry',async()=>{
  const events=new Map(),calls=[];const bridge={postMessage:raw=>calls.push(JSON.parse(raw))}
  const p=await page({passwordConfigured:true},()=>assert.fail('no late login'),{window:{HanApp:bridge,addEventListener:(name,callback)=>events.set(name,callback)}})
  assert.equal(calls.length,1)
  events.get('pagehide')();events.get('pageshow')();await tick()
  assert.equal(Object.hasOwn(p.element('body').attributes,'data-checking'),false)
  assert.equal(calls.length,1);assert.deepEqual(p.redirects,[])
})

test('返回中断的访问检查时仅重试检查，不重新加载整页',async()=>{
  const events=new Map();let finish,reloads=0
  const mePromise=new Promise(resolve=>{finish=resolve})
  const p=await page({},()=>assert.fail(),{mePromise,location:{reload:()=>reloads++},window:{addEventListener:(name,callback)=>events.set(name,callback)}})
  events.get('pagehide')();events.get('pageshow')()
  finish({authenticated:true,nativeAuthenticated:true,passwordConfigured:true});await tick()
  assert.equal(reloads,0)
  assert.equal(p.requests.filter(request=>request.url.endsWith('/auth/me')).length,2)
  assert.equal(Object.hasOwn(p.element('body').attributes,'data-checking'),false)
})

test('访问检查短暂断网自动重试，无需用户刷新',async()=>{
  const timers=[];let failures=1
  const p=await page({passwordConfigured:true},()=>assert.fail(),{meFailure:()=>failures-->0,setTimeout:(fn,delay)=>{timers.push({fn,delay});return timers.length},clearTimeout(){}})
  assert.equal(new Script('ready').runInContext(p.context),false)
  const retry=timers.find(timer=>timer.delay===400)
  assert.equal(retry?.delay,400)
  retry.fn();await tick()
  assert.equal(p.requests.length,2)
  p.element('password').value='fixture-secret';p.element('password').oninput()
  assert.equal(p.element('submit').disabled,false)
  assert.deepEqual(p.redirects,[])
})

test('returning during interrupted automatic login cannot revive its late redirect',async()=>{
  const events=new Map();let finish
  const bridge={postMessage(raw){const req=JSON.parse(raw);queueMicrotask(()=>bridge.onmessage({data:JSON.stringify({version:1,id:req.id,ok:true,result:req.type==='capabilities'?{credentialStorage:true}:{saved:true,password:'fixture-secret'}})}))}}
  const p=await page({passwordConfigured:true},()=>new Promise(resolve=>{finish=resolve}),{window:{HanApp:bridge,addEventListener:(name,callback)=>events.set(name,callback)}})
  await tick();assert.equal(typeof finish,'function')
  events.get('pagehide')();events.get('pageshow')();finish({ok:true,json:async()=>({ok:true})});await tick()
  assert.deepEqual(p.redirects,[])
  assert.equal(Object.hasOwn(p.element('body').attributes,'data-checking'),false)
})

test('unauthenticated login uncovers before the credential bridge replies', async () => {
  const delays = []
  const bridge = { postMessage() {} }
  const p = await page({ passwordConfigured: true, authenticated: false }, () => assert.fail(), {
    window: { HanApp: bridge },
    setTimeout: (_, delay) => { delays.push(delay); return delays.length },
    clearTimeout() {},
  })
  assert.equal(p.readiness.length, 1)
  assert.equal(p.readiness[0].type, 'pageReady')
  assert.equal(p.element('body').hasAttribute('data-checking'), true)
})

test('revealed login sends only generic readiness without installing a reply handler', async () => {
  const original = () => {}
  const bridge = {onmessage:original,postMessage(){assert.fail('no credential operation for setup')}}
  const p = await page({passwordConfigured:false},()=>assert.fail(),{window:{HanApp:bridge}})
  assert.equal(p.readiness.length,1)
  assert.deepEqual(JSON.parse(JSON.stringify(p.readiness[0].payload)),{})
  assert.equal(bridge.onmessage,original)
})


test('explicit logout prevents automatic saved-password login across app restarts',async()=>{
 const bridge={postMessage(){assert.fail('must not read saved password after explicit logout')}}
 const p=await page({passwordConfigured:true,authenticated:false},()=>assert.fail('must not login automatically'),{window:{HanApp:bridge,localStorage:{getItem:()=> '1'}}})
 assert.equal(p.requests.length,1);assert.equal(p.redirects.length,0)
 assert.equal(p.element('body').hasAttribute('data-checking'),false)
})
