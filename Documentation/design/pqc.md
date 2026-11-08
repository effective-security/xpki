# Post-quantum signatures: ML-DSA (FIPS 204)

Cross-cutting design and code inventory for adding ML-DSA (Module-Lattice
Digital Signature Algorithm, FIPS 204, formerly CRYSTALS-Dilithium) as a
key type for CSRs, certificates, CRLs and proofs, and for detecting
post-quantum keys and algorithms. The roadmap item is in
[ROADMAP.md](../../ROADMAP.md#post-quantum-signatures-ml-dsa-fips-204) and
the execution plan in [PLAN.md](../../PLAN.md#pqc-execution-plan-ml-dsa).
The starting point is [PR 568](https://github.com/effective-security/xpki/pull/568),
which adds the `csr` constants, parameter validation and
`IsPostQuantumAlgo`; its review notes that key generation is not
implemented, which this document plans.

## Scope

In scope for the first milestone:

- ML-DSA-44, ML-DSA-65 and ML-DSA-87 signing keys, generated and used
  through `cryptoprov` providers: `inmemcrypto`/`testprov` (standard
  library), `awskmscrypto`, `gcpkmscrypto` and `crypto11` (the last gated
  on a PKCS#11 v3.2 fixture).
- CSR creation and parsing, certificate issuance and root bootstrap,
  detached proofs, key info and PEM round trips with ML-DSA keys.
- Detection helpers: by algorithm name (`csr.IsPostQuantumAlgo`) and by
  key or certificate (`certutil`).
- CLI (`hsm-tool hsm generate --algo ML-DSA --size 65`) and documentation.

Out of scope for the first milestone, each a separate roadmap item when
wanted: hybrid or composite signatures (draft-ietf-lamps-pq-composite-sigs),
SLH-DSA (FIPS 205), ML-KEM key encapsulation (FIPS 203, `crypto/mlkem`) for
`dataprotection` or TLS, ML-DSA in `jwt`/`jwt/dpop` (RFC 9964 defines the
JOSE algorithms `ML-DSA-44/65/87` and the `AKP` key type; go-jose v4.1.9
implements them on Go 1.27, so this is a natural second milestone), and
OCSP responses signed directly by an ML-DSA key (library limit, see D5).

## Verified baseline (2026-11-08)

Checked on this machine; recheck when a version changes.

| Component                                   | Version          | ML-DSA support                                                                                                                                                                                                                             |
| ------------------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Go standard library (`go.mod` targets 1.27) | go1.27.3         | `crypto/mldsa`: `GenerateKey`, `NewPrivateKey(seed)`, `NewPublicKey`, `Sign`, `SignDeterministic`, `Verify`, `Options{Context}`; `crypto.MLDSAMu` for a pre-hashed μ (64 bytes). `crypto/x509`: `PublicKeyAlgorithm` `MLDSA`, `SignatureAlgorithm` `MLDSA44/65/87`, PKCS#8 marshal/parse (seed form, 54 bytes DER), PKIX marshal/parse, `CreateCertificateRequest`/`ParseCertificateRequest`/`CheckSignature`, `CreateCertificate`/`ParseCertificate`/`Verify`, `CreateRevocationList`: all verified with a probe program for the three parameter sets. `crypto/tls` has `SignatureScheme` `MLDSA44/65/87`. Unavailable under the FIPS 140-3 Go Cryptographic Module v1.0.0 (functions return errors). |
| `golang.org/x/crypto/ocsp`                  | v0.58.0          | **No.** `signingParamsForPublicKey` accepts RSA and ECDSA only, so `ocsp.CreateResponse` fails with an ML-DSA signer.                                                                                                                      |
| `github.com/miekg/pkcs11`                   | v1.1.2           | **No** PKCS#11 v3.2 constants (`CKK_ML_DSA`, `CKM_ML_DSA*`, `CKA_PARAMETER_SET`, `CKP_ML_DSA_*`); declare them locally.                                                                                                                    |
| SoftHSM (test fixture)                      | 2.6.1            | **No** ML-DSA mechanisms. A PKCS#11 v3.2 software token (for example Kryoptic) or a vendor HSM is needed for `crypto11` tests.                                                                                                              |
| AWS KMS SDK (`service/kms`)                 | v1.62.5          | `KeySpec` `ML_DSA_44/65/87`, `SigningAlgorithmSpec` `ML_DSA_SHAKE_256`. The service signs a `RAW` message or an `EXTERNAL_MU` 64-byte μ; the RAW message size is bounded by the API (4096 bytes), to be confirmed against the live service. |
| `nsmithuk/local-kms` (test fixture)         | 3.11.7           | **No.** `CreateKey` with `KeySpec=ML_DSA_65` returns `ValidationException` listing only RSA, ECC and symmetric specs (checked against the running container).                                                                               |
| GCP KMS SDK (`cloud.google.com/go/kms`)     | v1.36.1          | `CryptoKeyVersion` algorithms `PQ_SIGN_ML_DSA_44/65/87` and `PQ_SIGN_ML_DSA_*_EXTERNAL_MU` (plus SLH-DSA variants). PQ algorithms take the message in `AsymmetricSignRequest.data`, not a digest; the `EXTERNAL_MU` variants take μ.           |
| `github.com/go-jose/go-jose/v4`             | v4.1.9           | RFC 9964 ML-DSA algorithms and `AKP` JWKs on Go 1.27 (recognized but unusable on older toolchains).                                                                                                                                         |
| OpenSSL (interop vectors)                   | 3.5.5            | `ML-DSA-44/65/87` signature algorithms available (`openssl list -signature-algorithms`); can generate PKCS#8, SPKI, CSR and certificate test vectors.                                                                                        |

## The central design problem: message-based signing

Every signer in this module today follows hash-then-sign: the caller
hashes, passes the digest, and `opts.HashFunc()` names the hash (the KMS
signers reject nil options, XPKI-025; `inmemcrypto.provImpl.Sign` defaults
nil options to SHA-256). ML-DSA signs the **message**:

- `(*mldsa.PrivateKey).Sign(rand, message, opts)` requires `opts` nil or
  with `HashFunc() == 0` (`*mldsa.Options` carries an optional context
  string), or `crypto.MLDSAMu` with a 64-byte pre-hashed μ. Passing
  `crypto.SHA256` fails with `mldsa: invalid SignerOpts` (verified).
- `x509.CreateCertificate`, `CreateCertificateRequest` and
  `CreateRevocationList` call an opaque signer with the full TBS bytes and
  `crypto.Hash(0)` (verified), so a provider signer that forwards the
  message as is works with the standard library unchanged.
- KMS and PKCS#11 signers therefore need a second mode. For KMS the
  robust choice is to compute μ locally and sign it with the external-μ
  algorithm: μ = SHAKE256(tr ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ M, 64) with
  tr = SHAKE256(pk, 64) (FIPS 204 Algorithm 7; `crypto/sha3.NewSHAKE256`
  is in the standard library). This avoids the RAW message size bound and
  keeps the private key operation remote. The same μ path serves PKCS#11
  modules that implement it; modules that do not get the message.

Rule for the module (decision D4): an ML-DSA signer returned by any
provider accepts a message with nil or `*mldsa.Options`, and a μ with
`crypto.MLDSAMu`; it rejects every other hash. Callers that hash first
(`authority.SignProof`, `jwt`, OCSP) branch on the key type.

## Code inventory

Where the key type is assumed, grouped by package, with the change needed
and the plan phase (PQ0..PQ6, see PLAN.md). "Verified" means exercised with
the probe program on 2026-11-08.

### cryptoprov (PQ0, PQ1)

| File / symbol                                   | Today                                                                 | Change                                                                                                                                      |
| ----------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `provider.go` `KeyGenerator`                    | RSA and ECDSA generators                                              | D1: add optional `MLDSAKeyGenerator` interface (`GenerateMLDSAKey(label string, params mldsa.Parameters) (crypto.PrivateKey, error)`) and a helper that reports whether a provider implements it; promote into `KeyGenerator` in the next major version |
| `provider.go` `KeyInfo`                         | `Type` free-form                                                      | D3: `Type = "ML-DSA"`, parameter set in `Meta["parameter_set"]` (`ML-DSA-65`)                                                               |
| `utils.go` `ParsePrivateKeyDER`                 | Returns `*rsa`, `*ecdsa`, `ed25519`                                   | Return `*mldsa.PrivateKey` (PKCS#8 only; PKCS#1/SEC1 do not apply)                                                                          |
| `utils.go` `TLSKeyPair`                         | `Equal`-based match                                                   | None (verified `Equal` exists)                                                                                                              |
| `inmemcrypto/provider.go` `provImpl.Sign`       | nil opts → `crypto.SHA256`                                            | Default only for RSA/ECDSA; forward nil for ML-DSA, else `mldsa: invalid SignerOpts`                                                        |
| `inmemcrypto/provider.go` generators            | RSA, ECDSA                                                            | `GenerateMLDSAKey`; a `mldsaKeyGenerator` seam like the existing two                                                                        |
| `inmemcrypto/provider.go` `ExportKey`           | PKCS#1 / SEC1 PEM, panics on other types                              | `*mldsa.PrivateKey` → PKCS#8 `PRIVATE KEY` PEM (seed form); keep the panic only for truly impossible types                                  |
| `testprov/provider.go`                          | Same shape as inmemcrypto, URI export                                 | `GenerateMLDSAKey`, `Sign` forwarding                                                                                                       |
| `awskmscrypto/awskmsprov.go` `rsaKeySpecs`, generators | RSA/ECDSA key specs                                            | `GenerateMLDSAKey` → `KeySpec` `ML_DSA_44/65/87`; `GetKey` accepts the spec; `EnumKeys` `KeyInfo.Type`                                       |
| `awskmscrypto/signer.go` `signingAlgorithms`, `Sign` | Digest + hash → algorithm; comment says x509 cannot parse ML-DSA keys (outdated since Go 1.27) | ML-DSA branch: compute μ, `MessageType=EXTERNAL_MU`, `SigningAlgorithm=ML_DSA_SHAKE_256`; accept nil/`*mldsa.Options`/`MLDSAMu`; update the comment |
| `awskmscrypto/fake_test.go`                     | Real local RSA/ECDSA keys                                              | ML-DSA keys and the two message types; local-kms cannot be used (verified), so the gated integration test is skipped unless a real KMS is configured |
| `gcpkmscrypto/signer.go` `signSchemes`, `x509SignatureAlgorithms`, `signDigest`, `Sign` | Digest-only request                            | `PQ_SIGN_ML_DSA_*_EXTERNAL_MU` (preferred) or `PQ_SIGN_ML_DSA_*` with `data`; `SignatureAlgorithm()` → `x509.MLDSA*`; CRC32C over the sent field |
| `gcpkmscrypto/gcpkmsprov.go` generators, `GetKey` | RSA/ECDSA algorithms                                                 | `GenerateMLDSAKey`; accept PQ algorithms in `GetKey`                                                                                        |
| `gcpkmscrypto/kmsserver_test.go`                | Fake gRPC KMS with RSA/ECDSA                                           | ML-DSA versions, `data`/μ handling                                                                                                          |

### crypto11 (PQ5)

See the table in [crypto11.md](crypto11.md#post-quantum-readiness):
constants, `KeyTypeNames`, `findKeyPairOnSession`, a `PKCS11PrivateKeyMLDSA`
type with message semantics, `GenerateMLDSAKey`, public key export from
`CKA_VALUE` and `CKA_PARAMETER_SET`, `ConvertToPublic`, `IdentifyKey`,
`getPublicKeyPEM`, and a gated second fixture.

### csr (PQ0)

See the table in [csr.md](csr.md#post-quantum-readiness): constants and
validation from PR 568, `KeyRequest.Generate` ML-DSA case (calling the
optional generator, "not implemented" otherwise), `SigAlgo` and
`DefaultSigAlgo` mappings. `SignRequest` and `Parse` verified unchanged.

### certutil (PQ0)

| File / symbol                                       | Today                                                  | Change                                                                                                                                 |
| --------------------------------------------------- | ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| `keyinfo.go` `NewKeyInfo`, `hashAlgo`               | RSA/ECDSA; error for other keys                        | `*mldsa.PrivateKey`/`*mldsa.PublicKey` (also via `crypto.Signer`/JWK): `Type = "ML-DSA"`, `KeySize` per D3, `Hash = 0`                 |
| new `pqc.go`                                        | —                                                      | `IsPostQuantumKey(crypto.PublicKey) bool`, `IsPostQuantumCertificate(*x509.Certificate) bool` (public key or signature algorithm); the leaf package so `authority`, `jwt`, `x/print` and the CLIs share one definition |
| `pem.go` `ParsePrivateKeyDER`                       | RSA/ECDSA/Ed25519                                      | `*mldsa.PrivateKey`                                                                                                                     |
| `pem.go` `EncodePrivateKeyToPEM`                    | PKCS#1 / SEC1                                          | PKCS#8 for ML-DSA (`x509.MarshalPKCS8PrivateKey`)                                                                                       |
| `pem.go` `ParseRSAPublicKeyFromPEM`                 | RSA only by contract                                   | None                                                                                                                                   |
| `bundler.go` leaf key check (`Bundle`, ~line 737)   | `switch cert.PublicKeyAlgorithm { RSA, ECDSA }`, `unsupported key` otherwise | Add `x509.MLDSA` (or compare through the `Equal` interface for every supported algorithm)                                      |
| `testdata/`                                         | RSA/EC/Ed25519 PKCS#8 fixtures                         | ML-DSA PKCS#8, SPKI, CSR and certificate vectors generated with OpenSSL 3.5 (`certutil/testdata/pqc/`), the one case where checked-in fixtures beat `testca` because they prove interoperability |

### authority (PQ2)

See the table in [authority.md](authority.md#post-quantum-readiness):
`CreateIssuer` key info, `SignProof`/`VerifyProof`, the OCSP constraint
(D5), the delegated responder key, an optional profile key policy (D7).

### jwt (second milestone)

| File / symbol                                  | Today                                              | Change (later)                                                                                           |
| ---------------------------------------------- | -------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `sign.go` `NewSignerInfo`, `sign`, `VerifySignature` | RS*/ES*/HS* from key type; hash-then-sign      | `ML-DSA-44/65/87` algorithms (RFC 9964), message signing, `mldsa.Verify`                                  |
| `jwks.go` `PublicKeys`, `keyMatchesAlg`, `selectKey` | RSA/ECDSA JWKs                               | `AKP` keys via go-jose                                                                                   |
| `dpop/verify.go` algorithm allow-list          | RS*, PS*, ES*, EdDSA                               | Add ML-DSA algorithms                                                                                     |
| `oauth2client/client.go` `PublicKey`           | `*rsa.PublicKey` only                              | Widen to `crypto.PublicKey` in the next major version                                                     |

### CLIs, printing, tests (PQ6)

| File / symbol                                   | Today                                   | Change                                                                                         |
| ----------------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `cmd/hsm-tool/cli/hsm.go` `HsmGenKeyCmd.Algo`   | help `RSA\|ECDSA`                       | `RSA\|ECDSA\|ML-DSA`; `--size` doubles as the parameter set; regenerate `cmd/hsm-tool/README.md` and `Documentation/cli/` |
| `cmd/hsm-tool/cli/csr.go` defaults              | `ECDSA`, 256                            | Unchanged default; accept profiles with `algo: ml-dsa`                                          |
| `x/print/certutil.go` `Certificate`             | Prints no key or signature algorithm    | Print `Public Key Algorithm` and `Signature Algorithm` lines so a PQ certificate is visible     |
| `testca/*`                                      | RSA/ECDSA (Ed25519 in `utils.go`)        | ML-DSA entity option; `ToPKCS8` already generic through `x509.MarshalPKCS8PrivateKey`           |
| `authority/testdata/csrprofiles`                | RSA/ECDSA samples                        | One ML-DSA sample                                                                              |

### Unaffected

`dataprotection` (symmetric), `armor`, `oid` (no new OIDs needed by this
module; `crypto/x509` knows the ML-DSA OIDs), `metricskey`,
`internal/version`.

## Decisions (proposed, Needs Approval)

| ID | Question                                                                                      | Recommendation                                                                                                                                                                                                                                                                                       |
| -- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D1 | How does `cryptoprov` expose ML-DSA generation?                                               | Optional interface `MLDSAKeyGenerator` type-asserted by `csr.KeyRequest.Generate`; a provider without it fails with "ML-DSA key generation is not implemented by provider X". No break for external `Provider` implementers. Fold into `KeyGenerator` at the next major version.                     |
| D2 | `KeyRequest` encoding and the PR 568 error text                                               | `algo: ML-DSA` (case-insensitive; `MLDSA` accepted, `DILITHIUM` only as a documented legacy alias or dropped), `size: 44\|65\|87`. Until D1 lands, `Generate` returns "ML-DSA key generation is not implemented", as the PR 568 review asks, and the test expectation follows.                      |
| D3 | `certutil.KeyInfo` and `cryptoprov.KeyInfo` for ML-DSA                                        | `Type = "ML-DSA"`; `certutil.KeyInfo.KeySize = 44\|65\|87` (same number as `KeyRequest.Size`); `Hash = crypto.Hash(0)` meaning "sign the message"; `cryptoprov.KeyInfo.Meta["parameter_set"] = "ML-DSA-65"`.                                                                                        |
| D4 | Signer contract for ML-DSA keys from any provider                                             | Message with nil or `*mldsa.Options`, or μ with `crypto.MLDSAMu`; any other hash is an error. KMS and PKCS#11 signers compute μ locally and use the external-μ operation where the backend offers it.                                                                                                |
| D5 | OCSP for an ML-DSA issuer                                                                     | Phase 1: `CreateIssuer` rejects an ML-DSA signer unless `aia.delegated_ocsp_profile` is set (the responder key stays classical), or when no `aia` block exists at all (no OCSP). Phase 2: build the response locally (or upstream x/crypto) so an ML-DSA responder becomes possible.                 |
| D6 | Deterministic or hedged signing                                                               | Hedged (`Sign`), the FIPS 204 default; `SignDeterministic` only where a backend offers nothing else. Context strings are not used by X.509 (empty).                                                                                                                                                  |
| D7 | Profile policy on the CSR public key                                                          | New optional `allowed_key_algorithms` list on `CertProfile` (`rsa`, `ecdsa`, `ed25519`, `ml-dsa`); empty keeps today's behavior (any key x509 accepts). Lets an operator run PQ-only or classical-only profiles and gives `IsPostQuantumKey` a consumer.                                             |

## Risks and constraints

- **Sizes.** ML-DSA-65 public keys are 1952 bytes and signatures 3309
  bytes (ML-DSA-87: 2592 and 4627). Certificates grow to roughly 4–8 KB;
  the bundler's 1 MiB AIA limit is unaffected, but JWTs and DPoP proofs
  would grow by the signature size (second milestone).
- **FIPS builds.** With `GOFIPS140` and the v1.0.0 module, `crypto/mldsa`
  returns errors; providers must surface that as a clear error, not a
  panic.
- **Fixtures.** No local emulator for KMS ML-DSA; `crypto11` needs a new
  software token in CI. Tests for those providers rely on in-process fakes
  for coverage and on gated integration tests that skip when the fixture
  is absent (`internal/testenv`), with the limitation recorded.
- **Hash-based call sites.** Every `h.Sum(nil)` followed by `Sign` is a
  latent bug for ML-DSA keys; the inventory lists them (`SignProof`,
  `jwt`, OCSP). Add a test per site that an ML-DSA key is either handled
  or rejected with an error, never a panic.
- **API drift.** The AWS and GCP request shapes for PQ algorithms (RAW vs
  EXTERNAL_MU, `data` vs `digest`) are taken from the SDK types and
  documentation; confirm against the live services before the KMS batches
  close, and record the result.
