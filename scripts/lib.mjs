// Shared helpers for generating and verifying the test vectors in examples/.
//
// RFC 8792 line folding is NOT done here: kramdown-rfc folds the included
// files at build time via the post="fold69hard..." attributes in the draft, and
// only emits the folding note when a line actually needed folding. The files in
// examples/ therefore hold the true, unfolded bytes.

export const ALGS = [
  { jose: 'ML-DSA-44', http: 'ml-dsa-44', sigLen: 2420, pubLen: 1312 },
  { jose: 'ML-DSA-65', http: 'ml-dsa-65', sigLen: 3309, pubLen: 1952 },
  { jose: 'ML-DSA-87', http: 'ml-dsa-87', sigLen: 4627, pubLen: 2592 },
]

// The test request from Appendix B.2 of RFC 9421.
export const TEST_REQUEST = `POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Length: 18

{"hello": "world"}
`

// The covered components, matching Appendix B.2.6 of RFC 9421, plus the alg
// signature parameter — the parameter this document exists to make usable.
const COMPONENTS = [
  ['"date"', 'Tue, 20 Apr 2021 02:07:55 GMT'],
  ['"@method"', 'POST'],
  ['"@path"', '/foo'],
  ['"@authority"', 'example.com'],
  ['"content-type"', 'application/json'],
  ['"content-length"', '18'],
]

const CREATED = 1618884473
export const LABEL = 'sig-mldsa'

/**
 * Build the RFC 9421 signature base. Lines are LF-separated with no trailing
 * newline; this construction was checked against the published ed25519 vector
 * in Appendix B.2.6 of RFC 9421, which it verifies correctly.
 */
export function signatureBase(keyid, alg) {
  const names = COMPONENTS.map(([n]) => n).join(' ')
  const params = `(${names});created=${CREATED};keyid="${keyid}";alg="${alg}"`
  const lines = COMPONENTS.map(([n, v]) => `${n}: ${v}`)
  lines.push(`"@signature-params": ${params}`)
  return { base: lines.join('\n'), params }
}

export const b64 = (bytes) => Buffer.from(bytes).toString('base64')

export function pem(label, der) {
  const body = Buffer.from(der).toString('base64').match(/.{1,64}/g).join('\n')
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`
}

export function pemToDer(text) {
  const body = text
    .split('\n')
    .filter((l) => l && !l.startsWith('-----'))
    .join('')
  return Buffer.from(body, 'base64')
}
