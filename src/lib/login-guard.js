/**
 * Process-wide protection for password verification, in memory only.
 *
 * Per-address lockout cannot stop a distributed guesser: every IPv4 address gets its own five tries, and each try costs
 * a scrypt. Two bounds sit above it:
 *  1. a global failure budget: too many failed logins inside a window put password login into a cooldown that doubles
 *     while the pressure continues (explicitly allow-listed addresses, Passkey and key login are not affected);
 *  2. a concurrency cap on verification itself, so a flood queues briefly and is then refused instead of exhausting the
 *     libuv thread pool or piling up memory.
 */
export function createLoginGuard({
  now = () => Date.now(),
  failureLimit = 30,
  windowMs = 60_000,
  baseCooldownMs = 60_000,
  maxCooldownMs = 15 * 60_000,
  calmMs = 60 * 60_000,
  maxConcurrent = 2,
  maxQueue = 8,
} = {}) {
  let failures = []
  let cooldownUntil = 0
  let level = 0
  let lastTrigger = 0
  let running = 0
  const queue = []

  function check() {
    const t = now()
    if (cooldownUntil > t) return { ok: false, retryAfterSec: Math.ceil((cooldownUntil - t) / 1000) }
    return { ok: true }
  }

  function recordFailure() {
    const t = now()
    failures = failures.filter((at) => t - at < windowMs)
    failures.push(t)
    if (failures.length < failureLimit) return
    if (t - lastTrigger > calmMs) level = 0
    const cooldown = Math.min(maxCooldownMs, baseCooldownMs * 2 ** level)
    cooldownUntil = t + cooldown
    lastTrigger = t
    level = Math.min(level + 1, 30)
    failures = []
  }

  function drain() {
    while (running < maxConcurrent && queue.length) {
      const next = queue.shift()
      running++
      Promise.resolve().then(next.task).then(next.resolve, next.reject).finally(() => { running--; drain() })
    }
  }

  /** Runs `task` once a verification slot is free; rejects with `login_busy` when the wait queue is already full. */
  function run(task) {
    if (running >= maxConcurrent && queue.length >= maxQueue) {
      return Promise.reject(Object.assign(new Error('login_busy'), { status: 429, code: 'login_busy' }))
    }
    return new Promise((resolve, reject) => { queue.push({ task, resolve, reject }); drain() })
  }

  return { check, recordFailure, run, _state: () => ({ running, queued: queue.length, cooldownUntil, level }) }
}
