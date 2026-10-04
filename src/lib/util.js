import { existsSync, mkdirSync, readFileSync, openSync, writeFileSync, fsyncSync, closeSync, renameSync, unlinkSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { randomBytes } from 'node:crypto'

export const COOKIE = 'dsh_gate_token'
export const API_PREFIX = '/dsh-local-hanaccount/api'

export function dshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh')
}

export function defaultDataDir() {
  return join(dshHome(), 'storages', 'dsh-local-hanaccount')
}

export function nowIso() {
  return new Date().toISOString()
}

export function id(prefix) {
  return `${prefix}_${randomBytes(12).toString('hex')}`
}

export function readJson(file, fallback) {
  try {
    if (!existsSync(file)) return fallback
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch (err) {
    if (err.code === 'ENOENT') return fallback
    throw err
  }
}

export function writeJson(file, value) {
  mkdirSync(dirname(file), { recursive: true })
  const temporary = `${file}.${randomBytes(12).toString('hex')}.tmp`
  let fd
  try {
    fd = openSync(temporary, 'wx', 0o600)
    writeFileSync(fd, JSON.stringify(value, null, 2) + '\n', 'utf8')
    fsyncSync(fd)
    closeSync(fd); fd = undefined
    renameSync(temporary, file)
  } finally {
    if (fd !== undefined) closeSync(fd)
    try { unlinkSync(temporary) } catch (err) { if (err.code !== 'ENOENT') throw err }
  }
}

export function httpError(status, message) {
  const e = new Error(message)
  e.status = status
  return e
}

export function parseCookies(req) {
  const header = req.headers?.cookie || ''
  const out = {}
  for (const part of header.split(';')) {
    const i = part.indexOf('=')
    if (i < 0) continue
    try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()) } catch {}
  }
  return out
}

export async function readBody(req, { maxBytes = 65536, timeoutMs = 10000 } = {}) {
  const chunks = []; let bytes = 0; let timer
  const iterator = req[Symbol.asyncIterator]()
  const deadline = new Promise((_, reject) => { timer = setTimeout(() => reject(httpError(408, 'body timeout')), timeoutMs) })
  try {
    while (true) {
      const {value, done} = await Promise.race([iterator.next(), deadline])
      if (done) break
      const chunk = Buffer.from(value); bytes += chunk.length
      if (bytes > maxBytes) throw httpError(413, 'body too large')
      chunks.push(chunk)
    }
    if (!bytes) return {}
    try { return JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { throw httpError(400, 'bad json') }
  } finally { clearTimeout(timer) }
}

export function sendJson(res, status, value, headers = {}) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers })
  res.end(JSON.stringify(value))
}

export function sendText(res, status, text, headers = {}) {
  res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', ...headers })
  res.end(text)
}

export function setCookieHeader(token, maxAgeDays = 7, secure = false) {
  const maxAge = Math.max(1, Number(maxAgeDays) || 7) * 24 * 60 * 60
  return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? '; Secure' : ''}`
}

export function clearCookieHeader() {
  return `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
}

export function normalizeStringList(list) {
  const out = []
  const seen = new Set()
  for (const raw of Array.isArray(list) ? list : []) {
    const s = String(raw ?? '').trim()
    if (!s || seen.has(s)) continue
    seen.add(s)
    out.push(s)
  }
  return out
}
