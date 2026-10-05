import { getPasskeyContext } from './passkey-context.js'

let implementation
async function optional(name, args) {
  try { implementation ||= import('@simplewebauthn/server'); return (await implementation)[name](...args) }
  catch (error) {
    // Loading the optional library must never uninstall password authentication.
    if (error?.code === 'ERR_MODULE_NOT_FOUND' || error?.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED') {
      throw Object.assign(new Error('passkey_unavailable'), {status:503, code:'passkey_unavailable'})
    }
    throw error
  }
}
const generateAuthenticationOptions = (...args) => optional('generateAuthenticationOptions', args)
const generateRegistrationOptions = (...args) => optional('generateRegistrationOptions', args)
const verifyAuthenticationResponse = (...args) => optional('verifyAuthenticationResponse', args)
const verifyRegistrationResponse = (...args) => optional('verifyRegistrationResponse', args)

const RP_NAME = 'DSH Access Control'
const USER_ID = Buffer.from('dsh-gate-operator', 'utf8')
const USER_NAME = 'operator'

function requirePasskeyContext(req) {
  const ctx = getPasskeyContext(req)
  if (!ctx.available) {
    const err = new Error(ctx.hint || 'passkey unavailable')
    err.status = 400
    throw err
  }
  return ctx
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) return value
  if (value instanceof Uint8Array) return Buffer.from(value)
  return Buffer.from(String(value), 'base64url')
}

export async function registrationOptions(req, passkeyStore, revalidate = () => {}) {
  revalidate()
  const ctx = requirePasskeyContext(req)
  const existing = passkeyStore.listForAuth()
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: ctx.rpId,
    userName: USER_NAME,
    userID: USER_ID,
    attestationType: 'none',
    excludeCredentials: existing.map((c) => ({
      id: c.id,
      transports: c.transports,
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  })
  revalidate()
  passkeyStore.setChallenge('register', options.challenge)
  return options
}

export async function verifyRegistration(req, passkeyStore, body, revalidate = () => {}) {
  revalidate()
  const ctx = requirePasskeyContext(req)
  const expectedChallenge = passkeyStore.takeChallenge('register')
  if (!expectedChallenge) {
    const err = new Error('registration challenge expired')
    err.status = 400
    throw err
  }
  const verification = await verifyRegistrationResponse({
    response: body,
    expectedChallenge,
    expectedOrigin: ctx.origin,
    expectedRPID: ctx.rpId,
    requireUserVerification: false,
  })
  revalidate()
  if (!verification.verified || !verification.registrationInfo) {
    const err = new Error('passkey registration failed')
    err.status = 400
    throw err
  }
  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo
  return passkeyStore.addCredential({
    credentialId: credential.id,
    publicKey: toBuffer(credential.publicKey).toString('base64url'),
    counter: credential.counter,
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,
    transports: credential.transports,
    name: String(body?.name || '').trim() || 'Passkey',
  })
}

export async function authenticationOptions(req, passkeyStore, revalidate = () => {}) {
  revalidate()
  const ctx = requirePasskeyContext(req)
  if (passkeyStore.count() === 0) {
    const err = new Error('no passkeys registered')
    err.status = 400
    throw err
  }
  const options = await generateAuthenticationOptions({
    rpID: ctx.rpId,
    allowCredentials: passkeyStore.listForAuth().map((c) => ({
      id: c.id,
      transports: c.transports,
    })),
    userVerification: 'preferred',
  })
  revalidate()
  passkeyStore.setChallenge('login', options.challenge)
  return options
}

export async function verifyAuthentication(req, passkeyStore, body, verifyResponse = verifyAuthenticationResponse, revalidate = () => {}) {
  revalidate()
  const ctx = requirePasskeyContext(req)
  const expectedChallenge = passkeyStore.takeChallenge('login')
  if (!expectedChallenge) {
    const err = new Error('login challenge expired')
    err.status = 400
    throw err
  }
  const credId = body?.id || body?.rawId
  const stored = passkeyStore.findByCredentialId(
    typeof credId === 'string' ? credId : Buffer.from(credId || []).toString('base64url'),
  )
  if (!stored) {
    const err = new Error('unknown passkey')
    err.status = 401
    throw err
  }
  const verification = await verifyResponse({
    response: body,
    expectedChallenge,
    expectedOrigin: ctx.origin,
    expectedRPID: ctx.rpId,
    requireUserVerification: false,
    credential: {
      id: stored.credentialId,
      publicKey: toBuffer(stored.publicKey),
      counter: stored.counter,
      transports: stored.transports,
    },
  })
  revalidate()
  if (!verification.verified) {
    const err = new Error('passkey verification failed')
    err.status = 401
    throw err
  }
  if (passkeyStore.findByCredentialId(stored.credentialId) !== stored
    || !passkeyStore.updateCounter(stored.credentialId, verification.authenticationInfo.newCounter)) {
    throw Object.assign(new Error('passkey_revoked'), {status:401, code:'passkey_revoked'})
  }
  return stored
}
