# Roadmap

Open work. Shipped behavior is documented in [README.md](README.md) and
[`Documentation/codemap.md`](Documentation/codemap.md), and open
defects in [FINDINGS.md](FINDINGS.md). Completed milestones live in git history.

Items here are larger than a bug fix: they change an API, a contract, or the
shape of the module. A defect that can be fixed in place belongs in FINDINGS.

Every work item has a number, never reused. A finished item keeps its row in
the table below as `Done` with the release notes that describe it, and loses
its text in the section.

## Status

`Open` can be picked up, `Blocked` is waiting for what the row names, `Later`
is deliberately not started, `Done` shipped in the named version.

| #    | Work item                                                                                              | Status                                                                                 |
| ---- | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| 1    | [Provider interface: context propagation](#1-provider-interface-context-propagation)                   | Open: the signing path (loading and generation shipped in v2.0)                        |
| 2    | [KMS encryption keys](#2-kms-encryption-keys)                                                          | Open                                                                                   |
| 3    | [Post-quantum signatures: ML-DSA (FIPS 204)](#3-post-quantum-signatures-ml-dsa-fips-204)               | See 3.1 to 3.7                                                                         |
| 3.1  | `crypto11` verification on a PKCS#11 v3.2 token                                                        | Done (v1.1, [release notes](Documentation/RELEASE_NOTES_1.1.md))                       |
| 3.2  | Live KMS confirmation                                                                                  | Blocked: no ML-DSA for HSM keys on Cloud KMS (2026-11-12); AWS passed on 2026-11-09    |
| 3.3  | OCSP with an ML-DSA responder                                                                          | Done (v1.1, [release notes](Documentation/RELEASE_NOTES_1.1.md))                       |
| 3.4  | ML-DSA in `jwt` and `jwt/dpop`                                                                         | Done (v1.1, [release notes](Documentation/RELEASE_NOTES_1.1.md))                       |
| 3.5  | Composite/hybrid signatures                                                                            | Later                                                                                  |
| 3.6  | SLH-DSA (FIPS 205)                                                                                     | Later                                                                                  |
| 3.7  | ML-KEM (FIPS 203)                                                                                      | Later                                                                                  |
| 4    | [DPoP: replay protection and access-token binding](#4-dpop-replay-protection-and-access-token-binding) | See 4.1 and 4.2                                                                        |
| 4.1  | Shared `ReplayCache` implementation                                                                    | Open                                                                                   |
| 4.2  | Server-issued nonces                                                                                   | Open                                                                                   |
| 5    | [JWKS client hardening](#5-jwks-client-hardening)                                                      | Open                                                                                   |
| 6    | [PKCS#11 session management](#6-pkcs11-session-management)                                             | Open                                                                                   |
| 7    | [certutil bundler concurrency](#7-certutil-bundler-concurrency)                                        | Open                                                                                   |
| 8    | [Dependency hygiene](#8-dependency-hygiene)                                                            | See 8.1 and 8.2                                                                        |
| 8.1  | Replace `gopkg.in/yaml.v3`                                                                             | Open                                                                                   |
| 8.2  | Move to `crypto/hkdf`                                                                                  | Open                                                                                   |
| 9    | [dataprotection: versioned blobs and key rotation](#9-dataprotection-versioned-blobs-and-key-rotation) | Open                                                                                   |
| 10   | [Tooling and CI](#10-tooling-and-ci)                                                                   | See 10.1                                                                               |
| 10.1 | Regenerate `cmd/*/README.md` from `--help`                                                             | Open                                                                                   |
| 11   | [OCSP responder authorization](#11-ocsp-responder-authorization)                                       | Open                                                                                   |
| 12   | [Key management interfaces (v2)](#12-key-management-interfaces-keymanager-and-keygenerator-v2)         | Done (v2.0, [release notes](Documentation/RELEASE_NOTES_2.0.md)); live runs in PLAN.md |

## 1. Provider interface: context propagation

v2.0 gave every `cryptoprov.KeyGenerator` and `KeyManager` method a
`context.Context` and threaded it through the functions that load or
generate a key (`Crypto.LoadPrivateKey`, `csr.KeyRequest.Generate`,
`authority.NewIssuer`, `jwt.NewProvider` and their siblings). What remains is
the signing path: `crypto.Signer` has no context, so `Signer.Sign` of
`awskmscrypto` and `gcpkmscrypto` still calls the SDK with
`context.Background()` and can hang on a network stall, and
`authority.Issuer.Sign`, `csr.Provider.SignRequest`, the CRL and OCSP signers
and `jwt` have no way to hand theirs to a KMS signer. Related: XPKI-024.

It changes exported signatures, so it should land in v2 before porto and the
applications migrate (decision K9 of
[`Documentation/design/keymanager.md`](Documentation/design/keymanager.md);
the gate is in PLAN.md).

## 2. KMS encryption keys

`awskmscrypto` and `gcpkmscrypto` answer `GenerateKeyRequest.Usage:
KeyUsageEncrypt` with `cryptoprov.ErrNotSupported` and return no handle for
an `ENCRYPT_DECRYPT` key, since neither implements `crypto.Decrypter`. A
KMS-backed decrypter (AWS `RSAES_OAEP_SHA_256`, GCP `RSA_DECRYPT_OAEP_*`)
needs `GetKey` to return a decrypter for such keys and
`crypto11`-compatible `*rsa.OAEPOptions` handling; add it when a caller needs
KMS-held encryption keys.

The contract is ready for it since v2.0: `KeyFilter.Usage` lists encryption
keys on both providers, and `KeyInfo.Usage` reports them. This item is
additive.

## 3. Post-quantum signatures: ML-DSA (FIPS 204)

v1.1 ships ML-DSA-44/65/87 keys through every provider, CSRs,
certificates, CRLs, proofs, OCSP responders, `jwt` and `jwt/dpop`, detection
helpers, an `allowed_key_algorithms` profile policy and `hsm-tool` support (see
[`Documentation/RELEASE_NOTES_1.1.md`](Documentation/RELEASE_NOTES_1.1.md)
and [`Documentation/design/pqc.md`](Documentation/design/pqc.md)). Open
work, each item its own change when wanted:

- **3.2 Live KMS confirmation** (PLAN.md PQ7): AWS is confirmed,
  `TestLiveKMSMLDSA` passed for all three parameter sets on 2026-11-09. On
  Google Cloud the run of 2026-11-12 (`us-central1`) could not create a key:
  Cloud KMS answered `PQ_SIGN_ML_DSA_*_EXTERNAL_MU` with "not supported for
  protection level: HSM", and `genKey` creates HSM keys only. `GenerateKey`
  reports that as `cryptoprov.ErrNotSupported`. The GCP request shapes
  (`PQ_SIGN_ML_DSA_*`, `data`/`data_crc32c`) therefore still follow the SDK
  types and documentation only, and are exercised against an in-process fake.
  This stays open until Cloud KMS offers ML-DSA for HSM keys; then run
  `TestLiveKMSMLDSA` in `gcpkmscrypto` once with an existing key ring
  (`XPKI_LIVE_GCP_KMS_KEYRING`; it creates billable keys and schedules them for
  deletion) and record the result. The Cloud KMS
  [algorithms page](https://docs.cloud.google.com/kms/docs/algorithms) lists
  ML-DSA under the `software` protection level only, so the alternative is a
  provider setting for the protection level that creates ML-DSA keys as
  software keys; that is not decided.
- **3.5 Composite/hybrid signatures**: draft-ietf-lamps-pq-composite-sigs.
- **3.6 SLH-DSA**: FIPS 205.
- **3.7 ML-KEM**: FIPS 203, `crypto/mlkem`, for `dataprotection` or TLS.

## 4. DPoP: replay protection and access-token binding

`dpop.VerifyConfig` has an opt-in `ReplayCache` (in-memory only), `ath` and
`cnf.jkt` binding, and a trusted `ExternalURL` (v1.0). Remaining:

- **4.1** a shared `ReplayCache` implementation (for example Redis `SET NX` with
  an expiry) for servers with several instances;
- **4.2** server-issued nonces (RFC 9449 §8/§9): generating and rotating
  `DPoP-Nonce` values and the `use_dpop_nonce` error. `ExpectedNonce`
  compares only a caller-provided value today.

## 5. JWKS client hardening

`jwt.RemoteKeySet` has an injected client, a timeout, a body limit and a
refresh cooldown (v1.0). Remaining: TTL-based background refresh (honouring
`Cache-Control`), so removed keys expire and new keys are picked up before the
first miss, and `ParserConfig` fields for the `RemoteKeySet` options, which
`NewParser` currently leaves at the defaults.

## 6. PKCS#11 session management

Remaining after v2.0: the borrow of `Sign` and `Decrypt` still waits at the
session limit without a deadline, since `crypto.Signer` has no context; it
follows item 1. The key generation, lookup and management calls borrow with
their context since v2.0, which also removed `BytesToUlong` and made
`PKCS11Object.Handle` an accessor.

## 7. certutil bundler concurrency

Remaining after v2.0, which replaced the exported pool fields with accessors:
coalescing concurrent AIA fetches of the same URL across calls (each call
still fetches once). Encrypted PKCS#8 supports PBES2 with
PBKDF2 and AES-CBC only; scrypt and PBES1 are not planned unless a caller
needs them. Drop legacy RFC 1423 PEM decryption
(`x509.DecryptPEMBlock`) once callers have migrated to PKCS#8.

## 8. Dependency hygiene

- **8.1** `gopkg.in/yaml.v3` is archived; `go.yaml.in/yaml/v3` is already an
  indirect dependency. Switch the four direct importers in one change.
- **8.2** `golang.org/x/crypto/hkdf` in `dataprotection` can move to
  `crypto/hkdf`.

## 9. dataprotection: versioned blobs and key rotation

`NewSymmetric` blobs are `nonce || ciphertext || tag` with no version or key
id, so callers track which secret protected a blob and re-protect on read
(v1.0 documents the limits: key material of 32 bytes or more, at most 2^32
messages per secret). Add a versioned format (`version || key-id || nonce ||
ciphertext || tag`), a multi-key provider that decrypts with retired secrets
and encrypts with the current one, and a per-secret `Protect` counter or
time-based rotation hook against the message budget; keep `Unprotect`
accepting the legacy unversioned blob during migration.

## 10. Tooling and CI

- **10.1** Regenerate `cmd/*/README.md` from `--help` output and add per-command
  examples.

## 11. OCSP responder authorization

RFC 6960 §4.2.2.2 has the relying party reject a response unless its signer is
the CA itself or a certificate the CA issued with `id-kp-OCSPSigning`. That
decision belongs to the service that reads the response: `xpki` is a library, so
`certutil.ParseOCSPResponseForCert` does what `golang.org/x/crypto/ocsp` does and
checks signatures only, not the responder's EKU or validity, and matches a
response by serial number, not the issuer hashes of its CertID. Any certificate
from a CA, such as a client certificate, can therefore sign a `good` this function
accepts, for any serial number of that CA (verified on 2026-11-09 with a
`clientAuth`-only leaf, through `ocsp.ParseResponse` with ECDSA and
`certutil.ParseOCSPResponse` with ML-DSA). Recorded earlier as XPKI-126.

Give services a helper so that each does not write this check: an opt-in
`certutil.VerifyOCSPResponder`, leaving `ParseOCSPResponse` as it is, for
classical and ML-DSA alike. An embedded certificate other than the issuer itself
must carry the OCSP signing EKU and be valid at `ThisUpdate`, and the CertID
hashes must match the issuer (`ocsp.Response` does not expose them, so this needs
the local decode). Use it in `xpki-tool cert validate --revocation`
(`OCSPValidation`), which trusts the parsed response and checks only `NextUpdate`.

## 12. Key management interfaces: `KeyManager` and `KeyGenerator` (v2)

Done in v2.0: see
[`Documentation/RELEASE_NOTES_2.0.md`](Documentation/RELEASE_NOTES_2.0.md) and
[`Documentation/design/keymanager.md`](Documentation/design/keymanager.md).
The runs against the real AWS and Google Cloud services, the `release-v1`
branch and the migration of the client repositories are in
[PLAN.md](PLAN.md#key-management-interfaces-xpki-v2-remaining-work).
