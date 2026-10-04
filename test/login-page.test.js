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
async function page(me, login) {
  const elements = new Map(), redirects = [], requests = []
  const element = id => {
    if (!elements.has(id)) elements.set(id, {value:'',hidden:false,disabled:false,textContent:'',classList:{toggle(){}},setAttribute(){}})
    return elements.get(id)
  }
  const context = createContext({document:{getElementById:element,querySelector:()=>element('dialog')},
    AbortController,isSecureContext:false,location:{replace:url=>redirects.push(url)},
    fetch:async (url, options) => {
      requests.push({url,options})
      if(url.endsWith('/auth/me'))return {ok:true,json:async()=>me}
      return login(options)
    }})
  new Script(renderLoginPage('nonce').match(/<script nonce="nonce">([\s\S]*?)<\/script>/)[1]).runInContext(context)
  await tick()
  return {element,redirects,requests}
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

test('cancel aborts the pending request without navigating',async()=>{
  const p=await page({passwordConfigured:true},options=>new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(Object.assign(new Error('cancel'),{name:'AbortError'})))))
  p.element('password').value='fixture-password';p.element('password').oninput()
  p.element('form').onsubmit({preventDefault(){}});p.element('cancel').onclick();await tick()
  assert.equal(p.requests.at(-1).options.signal.aborted,true)
  assert.deepEqual(p.redirects,[]);assert.equal(p.element('status').textContent,'已取消')
})
