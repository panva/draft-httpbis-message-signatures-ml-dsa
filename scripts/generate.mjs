// Generates the test vectors under examples/, which the draft pulls in with
// {::include ...} directives.
//
//   npm run update          # only fills in what is missing
//   npm run force-update    # regenerates everything with fresh keys
//
// Regenerating produces different keys and signatures, so it churns the draft.
// Without --force this script leaves existing vectors alone.

import { mkdirSync, writeFileSync, existsSync } from 'node:fs'
import { ALGS, TEST_REQUEST, LABEL, signatureBase, b64, pem } from './lib.mjs'

const dir = (...p) => new URL(`../examples/${p.join('/')}`, import.meta.url)
const force = process.argv.includes('--force')

mkdirSync(dir(), { recursive: true })
writeFileSync(dir('test-request.http'), TEST_REQUEST)

for (const alg of ALGS) {
  mkdirSync(dir(alg.http), { recursive: true })

  if (!force && existsSync(dir(alg.http, 'signature-fields.txt'))) {
    console.log(`${alg.http}: present, skipping (use --force to regenerate)`)
    continue
  }

  const kid = `test-key-${alg.http}`
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: alg.jose },
    true,
    ['sign', 'verify'],
  )

  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey))
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey))
  const exported = await crypto.subtle.exportKey('jwk', privateKey)

  // RFC 9964 AKP keys carry kty, alg, pub and (for private keys) priv. Drop the
  // key_ops and ext parameters that Web Crypto adds on export; alg is REQUIRED.
  const jwk = {
    kty: exported.kty,
    alg: exported.alg,
    kid,
    pub: exported.pub,
    priv: exported.priv,
  }

  const seed = Buffer.from(exported.priv, 'base64url')
  const rawPub = Buffer.from(exported.pub, 'base64url')
  if (seed.length !== 32) throw new Error(`${alg.http}: seed is ${seed.length} bytes`)
  if (rawPub.length !== alg.pubLen) {
    throw new Error(`${alg.http}: public key is ${rawPub.length} bytes, want ${alg.pubLen}`)
  }

  const { base, params } = signatureBase(kid, alg.http)
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: alg.jose }, privateKey, Buffer.from(base, 'utf8')),
  )
  if (sig.length !== alg.sigLen) {
    throw new Error(`${alg.http}: signature is ${sig.length} bytes, want ${alg.sigLen}`)
  }
  const ok = await crypto.subtle.verify(
    { name: alg.jose },
    publicKey,
    sig,
    Buffer.from(base, 'utf8'),
  )
  if (!ok) throw new Error(`${alg.http}: generated signature does not verify`)

  writeFileSync(dir(alg.http, 'seed.txt'), `${b64(seed)}\n`)
  writeFileSync(dir(alg.http, 'public-key.txt'), `${b64(rawPub)}\n`)
  writeFileSync(dir(alg.http, 'private-key.pem'), pem('PRIVATE KEY', pkcs8))
  writeFileSync(dir(alg.http, 'public-key.pem'), pem('PUBLIC KEY', spki))
  writeFileSync(dir(alg.http, 'key.jwk'), `${JSON.stringify(jwk, null, 2)}\n`)
  writeFileSync(dir(alg.http, 'signature-base.txt'), `${base}\n`)
  writeFileSync(
    dir(alg.http, 'signature-fields.txt'),
    `Signature-Input: ${LABEL}=${params}\nSignature: ${LABEL}=:${b64(sig)}:\n`,
  )

  console.log(`${alg.http}: generated`)
}
