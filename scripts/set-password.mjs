#!/usr/bin/env node
// Sets the access password without a browser: node scripts/set-password.mjs [--data-dir DIR] [--force]
// The password is read from DSH_HANACCOUNT_PASSWORD_FILE / DSH_HANACCOUNT_PASSWORD, from piped stdin, or prompted
// (hidden) on a terminal. It is never taken from argv, which other local users can read in the process list.
//
// Stop DSH first: a running instance keeps its own copy of the config and would overwrite this change.
import { createInterface } from 'node:readline'
import { createStore } from '../src/lib/store.js'
import { hashPassword } from '../src/lib/password.js'
import { readInitialPassword, MIN_PASSWORD_LENGTH } from '../src/lib/initial-password.js'

const args = process.argv.slice(2)
const flag = (name) => args.includes(name)
const value = (name) => { const at = args.indexOf(name); return at >= 0 ? args[at + 1] : undefined }

if (flag('--help') || flag('-h')) {
  console.log('usage: node scripts/set-password.mjs [--data-dir DIR] [--force]\n  --force  replace an existing password (this signs every session out)')
  process.exit(0)
}

function readHidden(prompt) {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true })
    const write = rl._writeToOutput
    rl._writeToOutput = (text) => { if (text.startsWith(prompt)) write.call(rl, text); else if (text === '\r\n' || text === '\n') write.call(rl, text) }
    rl.question(prompt, (answer) => { rl.close(); resolve(answer) })
  })
}

async function readStdin() {
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(chunk)
  return Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '')
}

let password = readInitialPassword()
if (!password) {
  if (process.stdin.isTTY) {
    password = await readHidden('New access password: ')
    const again = await readHidden('Repeat it: ')
    if (password !== again) { console.error('The two entries differ; nothing changed.'); process.exit(1) }
  } else {
    password = await readStdin()
  }
}
if (password.length < MIN_PASSWORD_LENGTH) { console.error(`The password must be at least ${MIN_PASSWORD_LENGTH} characters; nothing changed.`); process.exit(1) }

const store = createStore({ dataDir: value('--data-dir') || '' })
if (store.cfg.passwordHash && !flag('--force')) {
  console.error('A password is already set; nothing changed. Use --force to replace it (all sessions are signed out).')
  process.exit(2)
}
store.setPasswordHash(hashPassword(password))
console.log(`Access password set in ${store.dataDir}. Start DSH and log in with it.`)
