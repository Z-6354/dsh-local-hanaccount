#!/usr/bin/env node
/**
 * Manual attack simulation against a running DSH instance.
 * Usage: node scripts/simulate-attacks.mjs [baseUrl]
 */
const BASE = (process.argv[2] || process.env.DSH_ATTACK_TARGET || 'http://127.0.0.1:3080').replace(/\/$/, '')

const ATTACKERS = [
  '203.0.113.99',
  '198.51.100.42',
  '203.0.113.88',
]

async function probe(name, fn) {
  try {
    const result = await fn()
    const ok = result.pass
    console.log(`${ok ? '✓' : '✗'} ${name}: ${result.detail}`)
    return ok
  } catch (e) {
    console.log(`✗ ${name}: ${e.message}`)
    return false
  }
}

async function fetchStatus(extraHeaders = {}) {
  const r = await fetch(`${BASE}/dsh-local-hanaccount/api/status`, { headers: extraHeaders })
  const text = await r.text()
  let json = null
  try { json = JSON.parse(text) } catch { /* */ }
  return { status: r.status, text, json }
}

async function main() {
  console.log(`DSH attack simulation → ${BASE}\n`)

  let passed = 0
  let total = 0

  const ping = await fetchStatus()
  total++
  if (ping.status === 200 && ping.json?.ip) {
    console.log(`✓ DSH 在线: 当前 IP=${ping.json.ip}, IP限制=${ping.json.ipLimitEnabled}`)
    passed++
  } else {
    console.log(`✗ DSH 不可达 (${ping.status}): ${ping.text.slice(0, 120)}`)
    console.log('\n请先启动 DSH（桌面「DSH Web」），或指定 baseUrl。')
    process.exit(1)
  }

  for (const ip of ATTACKERS) {
    total++
    const r = await fetch(`${BASE}/api/events.host`, {
      headers: { 'X-Real-IP': ip, 'User-Agent': 'lha-attack-sim/1.0' },
    })
    const ok = r.status === 403
    console.log(`${ok ? '✓' : '✗'} 非白名单 IP ${ip} → /api/events.host: HTTP ${r.status}${ok ? ' (已拦截)' : ''}`)
    if (ok) passed++
  }

  total++
  const unauth = await fetch(`${BASE}/api/events.host`)
  const unauthOk = unauth.status === 401
  console.log(`${unauthOk ? '✓' : '✗'} 本机未登录访问 API: HTTP ${unauth.status}${unauthOk ? ' (需登录)' : ''}`)
  if (unauthOk) passed++

  total++
  const loginBlocked = await fetch(`${BASE}/dsh-local-hanaccount/api/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Real-IP': '203.0.113.88',
      'User-Agent': 'lha-attack-sim/1.0',
    },
    body: JSON.stringify({ password: 'wrong-password-simulation' }),
  })
  const blockedOk = loginBlocked.status === 403
  console.log(`${blockedOk ? '✓' : '✗'} 外网 IP 尝试登录: HTTP ${loginBlocked.status}${blockedOk ? ' (IP 门禁先拦截)' : ''}`)
  if (blockedOk) passed++

  total++
  const login = await fetch(`${BASE}/dsh-local-hanaccount/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'wrong-password-simulation' }),
  })
  const loginOk = login.status === 401
  console.log(`${loginOk ? '✓' : '✗'} 本机错误密码: HTTP ${login.status}${loginOk ? ' (密码拒绝)' : ''}`)
  if (loginOk) passed++

  total++
  const spoof = await fetch(`${BASE}/api/events.host`, {
    headers: {
      'X-Forwarded-For': '127.0.0.1',
      'X-Real-IP': '127.0.0.1',
      'User-Agent': 'lha-attack-sim/1.0',
    },
  })
  // Direct connection from 127.0.0.1: spoof headers are honored for X-Real-IP from trusted proxy.
  // Without going through nginx, we're trusted proxy ourselves — this is expected on localhost dev.
  const spoofNote = spoof.status === 401
    ? '本机直连仍识别为 127.0.0.1（可信代理），得 401 而非 403'
    : `HTTP ${spoof.status}`
  console.log(`${spoof.status === 401 || spoof.status === 403 ? '✓' : '✗'} 伪造 XFF 从本机探测: ${spoofNote}`)
  if (spoof.status === 401 || spoof.status === 403) passed++

  console.log(`\n结果: ${passed}/${total} 通过`)
  console.log('请在 DSH 设置 → 访问控制 →「最近可疑 IP」查看是否出现 203.0.113.x 记录。')
  process.exit(passed === total ? 0 : 1)
}

main()
