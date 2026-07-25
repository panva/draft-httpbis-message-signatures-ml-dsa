// Verifies the test vectors under examples/.
//
//   npm test
//
// The draft includes these files verbatim via {::include ...}, so checking them
// is equivalent to checking what a reader copies out of the document. Run this
// before every submission: a broken test vector is the worst failure mode here.

import { readFileSync } from 'node:fs'
import { ALGS, LABEL, signatureBase } from './lib.mjs'

const read = (...p) =>
  readFileSync(new URL(`../examples/${p.join('/')}`, import.meta.url), 'utf8')

let failures = 0
const check = (label, cond) => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${label}`)
  if (!cond) failures++
}

function pemToDer(text) {
  return Buffer.from(
    text.split('\n').filter((l) => l && !l.startsWith('-----')).join(''),
    'base64',
  )
}

for (const alg of ALGS) {
  console.log(`\n${alg.jose}`)
  const kid = `test-key-${alg.http}`

  const seed = Buffer.from(read(alg.http, 'seed.txt').trim(), 'base64')
  const rawPub = Buffer.from(read(alg.http, 'public-key.txt').trim(), 'base64')
  const jwk = JSON.parse(read(alg.http, 'key.jwk'))
  const spki = pemToDer(read(alg.http, 'public-key.pem'))
  const pkcs8 = pemToDer(read(alg.http, 'private-key.pem'))

  check('seed is 32 bytes', seed.length === 32)
  check(`raw public key is ${alg.pubLen} bytes`, rawPub.length === alg.pubLen)
  check(
    'SPKI wraps the published raw public key',
    spki.subarray(spki.length - alg.pubLen).equals(rawPub),
  )

  // RFC 9964 AKP requirements.
  check('JWK kty is AKP', jwk.kty === 'AKP')
  check(`JWK alg is ${alg.jose} (REQUIRED for AKP)`, jwk.alg === alg.jose)
  check('JWK kid matches the key name', jwk.kid === kid)
  check('JWK has no Web Crypto export parameters', !('key_ops' in jwk) && !('ext' in jwk))
  check('JWK pub matches the raw public key', Buffer.from(jwk.pub, 'base64url').equals(rawPub))
  check('JWK priv is the 32-byte seed', Buffer.from(jwk.priv, 'base64url').equals(seed))

  // The seed-form PKCS#8 must regenerate the published public key.
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: alg.jose }, true, [
    'sign',
  ])
  const derived = await crypto.subtle.exportKey('jwk', privateKey)
  check(
    'PKCS#8 private key derives the published public key',
    Buffer.from(derived.pub, 'base64url').equals(rawPub),
  )
  check(
    'PKCS#8 private key carries the published seed',
    Buffer.from(derived.priv, 'base64url').equals(seed),
  )

  // The signature base must be exactly what RFC 9421 says it should be.
  const { base, params } = signatureBase(kid, alg.http)
  check(
    'published signature base matches the recomputed one',
    read(alg.http, 'signature-base.txt') === `${base}\n`,
  )

  const fields = read(alg.http, 'signature-fields.txt')
  check(
    'Signature-Input matches the signature parameters',
    fields.match(new RegExp(`^Signature-Input: ${LABEL}=(.*)$`, 'm'))?.[1] === params,
  )

  const sigB64 = fields.match(new RegExp(`^Signature: ${LABEL}=:(.*):$`, 'm'))?.[1]
  const sig = Buffer.from(sigB64 ?? '', 'base64')
  check(`signature is ${alg.sigLen} bytes`, sig.length === alg.sigLen)

  const publicKey = await crypto.subtle.importKey('spki', spki, { name: alg.jose }, true, [
    'verify',
  ])
  check(
    'SIGNATURE VERIFIES over the signature base',
    await crypto.subtle.verify({ name: alg.jose }, publicKey, sig, Buffer.from(base, 'utf8')),
  )
}

console.log(failures === 0 ? '\nAll test vectors verify.' : `\n${failures} check(s) failed.`)
process.exit(failures === 0 ? 0 : 1)
