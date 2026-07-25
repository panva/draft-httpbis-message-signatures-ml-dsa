---
title: "Use of ML-DSA in HTTP Message Signatures"
abbrev: "ML-DSA in HTTP Message Signatures"
category: std

docname: draft-skokan-httpbis-message-signatures-ml-dsa-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Web and Internet Transport"
workgroup: "HTTP"
keyword:
 - http
 - signatures
 - ml-dsa
 - post-quantum
venue:
  group: "HTTP"
  type: "Working Group"
  mail: "ietf-http-wg@w3.org"
  arch: "https://lists.w3.org/Archives/Public/ietf-http-wg/"
  github: "panva/draft-httpbis-message-signatures-ml-dsa"
  latest: "https://panva.github.io/draft-httpbis-message-signatures-ml-dsa/draft-skokan-httpbis-message-signatures-ml-dsa.html"

author:
 -
    fullname: Filip Skokan
    organization: Okta
    email: panva.ip@gmail.com

normative:
  RFC9421:
  FIPS204:
    title: "Module-Lattice-Based Digital Signature Standard"
    author:
      org: "National Institute of Standards and Technology (NIST)"
    date: 2024-08
    seriesinfo:
      "NIST": "FIPS 204"
      "DOI": "10.6028/NIST.FIPS.204"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf

informative:
  RFC7468:
  RFC8792:
  RFC9958:
  RFC9881:
  RFC9882:
  RFC9964:
  HTTPSIG-PQ:
    title: "Post-Quantum Algorithms for HTTP Message Signatures"
    author:
      - name: "Soatok Dreamseeker"
    date: false
    target: https://c2sp.org/httpsig-pq

...

--- abstract

This document registers algorithm identifiers for the Module-Lattice-Based
Digital Signature Algorithm (ML-DSA) in the "HTTP Signature Algorithms"
registry, and defines the `HTTP_SIGN` and `HTTP_VERIFY` primitive functions for
them.


--- middle

# Introduction

The Module-Lattice-Based Digital Signature Algorithm (ML-DSA) {{FIPS204}} is a
signature scheme believed to resist an adversary in possession of a
Cryptographically Relevant Quantum Computer (CRQC).

HTTP Message Signatures {{RFC9421}} establishes the "HTTP Signature Algorithms"
registry ({{Section 6.2 of RFC9421}}). Every digital signature algorithm in its
initial contents rests on integer factorization or on the discrete logarithm
problem, so none of them resists a CRQC.

{{RFC9964}} registers ML-DSA identifiers for JOSE and COSE, but those cannot be
reused here. {{Section 3.3.7 of RFC9421}} states that JSON Web Algorithm values
"are not registered in the 'HTTP Signature Algorithms' registry (Section 6.2),
and so the explicit alg signature parameter is not used at all when using JOSE
signing algorithms". A signer using ML-DSA therefore has no way to name the
algorithm in the `alg` signature parameter ({{Section 2.3 of RFC9421}}), and a
verifier has no way to request it in the `Accept-Signature` field
({{Section 5 of RFC9421}}).

This document registers three ML-DSA algorithm identifiers and defines the
`HTTP_SIGN` and `HTTP_VERIFY` primitive functions ({{Section 3.3 of RFC9421}})
for each.

## Scope {#scope}

This document defines algorithm identifiers and the signing and verification
procedures they denote. It does not define key formats, key discovery or
distribution mechanisms, or policy for when an application selects ML-DSA.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

ML-DSA-44, ML-DSA-65, and ML-DSA-87 refer to ML-DSA with the parameter choices
given in Table 1 of {{FIPS204}}.


# ML-DSA Signature Algorithms {#algorithms}

These algorithms use ML-DSA as specified in {{FIPS204}}. HashML-DSA, the
pre-hash variant in Section 5.4 of {{FIPS204}}, is not used; see {{no-prehash}}.

To sign using these algorithms, the signer applies `ML-DSA.Sign` (Algorithm 2 of
{{FIPS204}}) with the signer's private signing key and the signature base
({{Section 2.5 of RFC9421}}) as the message (`M`). The signature base is taken
as the input message with no prehash function. The context string (`ctx`) MUST
be the empty string. The resulting signature, encoded as described in Section
7.2 of {{FIPS204}}, is the byte array (`S`) used as the HTTP message signature
output in {{Section 3.1 of RFC9421}}.

To verify using these algorithms, the verifier applies `ML-DSA.Verify`
(Algorithm 3 of {{FIPS204}}) using the public key portion of the verification
key material and the signature base recreated as described in
{{Section 3.2 of RFC9421}}. The signature base is taken as the input message
with no prehash function. The context string (`ctx`) MUST be the empty string.
The verifier extracts the HTTP message signature to be verified (`S`) as
described in {{Section 3.2 of RFC9421}}. The results of the verification
function indicate whether the signature presented is valid.

Implementations MUST pass the signature base to `ML-DSA.Sign` and
`ML-DSA.Verify` unaltered: they MUST NOT append a trailing newline, alter its
line endings, or apply any further encoding.

A signer SHOULD use the hedged variant of `ML-DSA.Sign`, the default in
{{FIPS204}}, and MAY use the deterministic variant; see {{signing-mode}}.

## ML-DSA-44 {#ml-dsa-44}

This algorithm uses the ML-DSA-44 parameter set. Signatures are 2420 bytes.

The use of this algorithm can be indicated at runtime using the `ml-dsa-44`
value for the `alg` signature parameter.

## ML-DSA-65 {#ml-dsa-65}

This algorithm uses the ML-DSA-65 parameter set. Signatures are 3309 bytes.

The use of this algorithm can be indicated at runtime using the `ml-dsa-65`
value for the `alg` signature parameter.

## ML-DSA-87 {#ml-dsa-87}

This algorithm uses the ML-DSA-87 parameter set. Signatures are 4627 bytes.

The use of this algorithm can be indicated at runtime using the `ml-dsa-87`
value for the `alg` signature parameter.


# Signature Size Considerations {#sizes}

ML-DSA signatures are much larger than those of the algorithms {{RFC9421}}
originally registered. The `Signature` field carries a signature as a Structured
Fields Byte Sequence, Base64 encoded and delimited by colons, so the encoded
value is approximately a third larger than the signature itself.

| Algorithm | Signature | Encoded in the Signature field |
|---|---|---|
| `ed25519` | 64 bytes | approximately 90 bytes |
| `ml-dsa-44` | 2420 bytes | approximately 3.2 kilobytes |
| `ml-dsa-65` | 3309 bytes | approximately 4.4 kilobytes |
| `ml-dsa-87` | 4627 bytes | approximately 6.2 kilobytes |
{: title="Signature sizes by algorithm"}

Servers and intermediaries limit how large header fields may be. Two kinds of
limit are common, and both are often set to around 8 kilobytes: one on any
single field, and one on the request line and all header fields together.

Under a per-field limit of that size, one `ml-dsa-87` signature fits with little
room to spare, and two do not fit at all. Under a combined limit, one
`ml-dsa-87` signature leaves less than 2 kilobytes for the request line and
every other field, including the `Signature-Input` field that accompanies every
signature. Messages carrying more than one signature
({{Section 4.3 of RFC9421}}) multiply these figures.

A signature value differs on every message, so HTTP/2 and HTTP/3 header
compression does not help: the full value is sent each time. {{RFC9958}}
discusses the operational effects of post-quantum algorithm sizes more
generally.

\[\[ Editor's note: is ml-dsa-87 worth registering at all? One signature eats
most of an 8 kilobyte limit before anything else is in the message. \]\]


# Security Considerations

The security considerations of {{RFC9421}} and {{RFC9881}} apply to this
document. {{RFC9958}} provides general background on the threat posed by CRQCs
and on the transition to post-quantum cryptography.

## Rationale for Not Supporting HashML-DSA {#no-prehash}

This document does not define algorithms for HashML-DSA, the pre-hash variant in
Section 5.4 of {{FIPS204}}. ML-DSA and HashML-DSA are incompatible and require
different verification routines, so supporting HashML-DSA would mean registering
further identifiers.

Pre-hashing accommodates signers that cannot pass a complete message to the
signing module. The signature base ({{Section 2.5 of RFC9421}}) is built in full
before signing begins and is small enough to pass to the signing module
directly.

## Rationale for the Empty Context String {#empty-ctx}

ML-DSA accepts a context string (`ctx`) that separates signatures made in
different application contexts. This document fixes it to the empty string, as
do other documents that use ML-DSA ({{RFC9881}}, {{RFC9882}}, {{RFC9964}}).

In HTTP message signatures that separation comes from the signature base, which
covers the signature parameters, including the application-specific `tag`
parameter ({{Section 2.3 of RFC9421}}); a signature made over one set of
parameters does not verify against another.

Fixing the context string also keeps every parameter of these algorithms
determined by this document, as {{Section 6.2 of RFC9421}} expects of a
registered algorithm identifier.

An application needing cryptographic separation between HTTP message signatures
and other uses of the same signing key SHOULD use a separate key for each.

## Deterministic and Randomized Signing {#signing-mode}

ML-DSA permits deterministic and hedged (randomized) signing, hedged being the
default in {{FIPS204}}. Both verify with the same procedure and a verifier
cannot tell them apart, so the choice rests with the signer. {{algorithms}}
recommends the hedged variant because mixing in fresh randomness hardens an
implementation against fault and side-channel attacks, as
{{Section 9 of RFC9881}} discusses.

Two hedged signatures over the same signature base with the same key will
differ. A verifier MUST NOT check a signature by re-signing the signature base
and comparing the result, as {{Section 7.3.5 of RFC9421}} warns; the procedure
in {{algorithms}} is the only correct one.

## Algorithm Downgrade During Migration {#downgrade}

During migration to post-quantum algorithms a verifier is likely to accept both
ML-DSA and a classical algorithm. {{Section 7.3.6 of RFC9421}} describes the
downgrade risk that follows: an attacker who can influence algorithm selection
can have a verifier accept a signature made with the weaker one.

A verifier accepting ML-DSA for its resistance to a CRQC gains that resistance
only for signatures actually made with ML-DSA. A verifier SHOULD therefore take
the acceptable algorithm from the key material or from configuration rather than
from the `alg` signature parameter, and SHOULD NOT accept a classical algorithm
from a signer for which ML-DSA is expected.

## Binding of the Public Key

ML-DSA computes the message representative over a hash of the public key, which
binds a signature to the key that produced it. That mitigates the key
substitution concerns of {{Section 7.3.4 of RFC9421}}, where a signature is
verified under a key other than the signer's. Verifiers still need to check that
the key material and the algorithm both suit the application, as
{{Section 7.3.6 of RFC9421}} notes.


# IANA Considerations

## HTTP Signature Algorithms Registry

IANA is requested to add the following entries to the "HTTP Signature
Algorithms" registry established in {{Section 6.2 of RFC9421}}.

| Algorithm Name | Description | Status | Reference |
|---|---|---|---|
| `ml-dsa-44` | ML-DSA using the ML-DSA-44 parameter set | Active | {{ml-dsa-44}} of this document |
| `ml-dsa-65` | ML-DSA using the ML-DSA-65 parameter set | Active | {{ml-dsa-65}} of this document |
| `ml-dsa-87` | ML-DSA using the ML-DSA-87 parameter set | Active | {{ml-dsa-87}} of this document |
{: title="Additions to the HTTP Signature Algorithms registry"}


--- back

# Test Vectors {#test-vectors}

These test vectors are non-normative, and may be used to check an
implementation.

ML-DSA signing is randomized by default; see {{signing-mode}}. The signature
values below are therefore recorded outputs, and an implementation signing the
same signature base with the same key will produce a different, equally valid
signature.

## Example Request {#test-request}

The test cases below sign portions of the following request, the test request
used in Appendix B.2 of {{RFC9421}}.

~~~ http-message
{::include examples/test-request.http}
~~~
{: title="The test request"}

## Example Keys {#test-keys}

Each key pair is presented in several encodings for convenience. This document
does not define a key format; see {{scope}}.

### ML-DSA-44 Test Key {#test-key-ml-dsa-44}

The following key pair uses the ML-DSA-44 parameter set and is referred to in
this appendix as test-key-ml-dsa-44. The 32-byte seed from which the key pair is
derived, in Base64:

~~~
{::include examples/ml-dsa-44/seed.txt}
~~~
{: title="test-key-ml-dsa-44, seed"}

The 1312-byte public key, encoded as described in Section 7.2 of {{FIPS204}},
in Base64:

~~~
{::include examples/ml-dsa-44/public-key.txt}
~~~
{: title="test-key-ml-dsa-44, public key" post="fold69hardleftdry"}

The same key pair in PKCS #8 and SubjectPublicKeyInfo form, using the textual
encoding of {{RFC7468}} with no encryption. The private key uses the seed
representation.

~~~
{::include examples/ml-dsa-44/private-key.pem}
~~~
{: title="test-key-ml-dsa-44, PKCS #8"}

~~~
{::include examples/ml-dsa-44/public-key.pem}
~~~
{: title="test-key-ml-dsa-44, SubjectPublicKeyInfo"}

The same key pair as a JSON Web Key, using the AKP key type defined in
{{Section 3 of RFC9964}}:

~~~ json
{::include examples/ml-dsa-44/key.jwk}
~~~
{: title="test-key-ml-dsa-44, JSON Web Key" post="fold69hardleft4dry"}

### ML-DSA-65 Test Key {#test-key-ml-dsa-65}

The following key pair uses the ML-DSA-65 parameter set and is referred to in
this appendix as test-key-ml-dsa-65. The 32-byte seed from which the key pair is
derived, in Base64:

~~~
{::include examples/ml-dsa-65/seed.txt}
~~~
{: title="test-key-ml-dsa-65, seed"}

The 1952-byte public key, encoded as described in Section 7.2 of {{FIPS204}},
in Base64:

~~~
{::include examples/ml-dsa-65/public-key.txt}
~~~
{: title="test-key-ml-dsa-65, public key" post="fold69hardleftdry"}

The same key pair in PKCS #8 and SubjectPublicKeyInfo form:

~~~
{::include examples/ml-dsa-65/private-key.pem}
~~~
{: title="test-key-ml-dsa-65, PKCS #8"}

~~~
{::include examples/ml-dsa-65/public-key.pem}
~~~
{: title="test-key-ml-dsa-65, SubjectPublicKeyInfo"}

The same key pair as a JSON Web Key:

~~~ json
{::include examples/ml-dsa-65/key.jwk}
~~~
{: title="test-key-ml-dsa-65, JSON Web Key" post="fold69hardleft4dry"}

### ML-DSA-87 Test Key {#test-key-ml-dsa-87}

The following key pair uses the ML-DSA-87 parameter set and is referred to in
this appendix as test-key-ml-dsa-87. The 32-byte seed from which the key pair is
derived, in Base64:

~~~
{::include examples/ml-dsa-87/seed.txt}
~~~
{: title="test-key-ml-dsa-87, seed"}

The 2592-byte public key, encoded as described in Section 7.2 of {{FIPS204}},
in Base64:

~~~
{::include examples/ml-dsa-87/public-key.txt}
~~~
{: title="test-key-ml-dsa-87, public key" post="fold69hardleftdry"}

The same key pair in PKCS #8 and SubjectPublicKeyInfo form:

~~~
{::include examples/ml-dsa-87/private-key.pem}
~~~
{: title="test-key-ml-dsa-87, PKCS #8"}

~~~
{::include examples/ml-dsa-87/public-key.pem}
~~~
{: title="test-key-ml-dsa-87, SubjectPublicKeyInfo"}

The same key pair as a JSON Web Key:

~~~ json
{::include examples/ml-dsa-87/key.jwk}
~~~
{: title="test-key-ml-dsa-87, JSON Web Key" post="fold69hardleft4dry"}

## Test Cases {#test-cases}

Each test case covers the same components of {{test-request}}, using the `alg`
signature parameter to name the algorithm.

### Signing a Request Using ml-dsa-44

This example uses the `ml-dsa-44` algorithm and the key test-key-ml-dsa-44. The
corresponding signature base is:

~~~
{::include examples/ml-dsa-44/signature-base.txt}
~~~
{: title="Signature base, ml-dsa-44" post="fold69hardleftdry"}

This results in the following Signature-Input and Signature fields being added
to the message under the label sig-mldsa:

~~~ http-message
{::include examples/ml-dsa-44/signature-fields.txt}
~~~
{: title="Signature fields, ml-dsa-44" post="fold69hardleftdry"}

### Signing a Request Using ml-dsa-65

This example uses the `ml-dsa-65` algorithm and the key test-key-ml-dsa-65. The
corresponding signature base is:

~~~
{::include examples/ml-dsa-65/signature-base.txt}
~~~
{: title="Signature base, ml-dsa-65" post="fold69hardleftdry"}

This results in the following Signature-Input and Signature fields being added
to the message under the label sig-mldsa:

~~~ http-message
{::include examples/ml-dsa-65/signature-fields.txt}
~~~
{: title="Signature fields, ml-dsa-65" post="fold69hardleftdry"}

### Signing a Request Using ml-dsa-87

This example uses the `ml-dsa-87` algorithm and the key test-key-ml-dsa-87. The
corresponding signature base is:

~~~
{::include examples/ml-dsa-87/signature-base.txt}
~~~
{: title="Signature base, ml-dsa-87" post="fold69hardleftdry"}

This results in the following Signature-Input and Signature fields being added
to the message under the label sig-mldsa:

~~~ http-message
{::include examples/ml-dsa-87/signature-fields.txt}
~~~
{: title="Signature fields, ml-dsa-87" post="fold69hardleftdry"}


# Acknowledgments
{:numbered="false"}

The algorithm identifiers registered by this document are the same as those used in
earlier work by Soatok Dreamseeker {{HTTPSIG-PQ}}.
