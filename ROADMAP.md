# Roadmap

Open work only. Shipped behavior is documented in [README.md](README.md) and
[`Documentation/codemap.md`](Documentation/codemap.md), and open
defects in [FINDINGS.md](FINDINGS.md). Completed milestones live in git history.

Items here are larger than a bug fix: they change an API, a contract, or the
shape of the module. A defect that can be fixed in place belongs in FINDINGS.

## Provider interface: context propagation

`cryptoprov.Provider`, `KeyGenerator` and `KeyManager` take no
`context.Context`, so `awskmscrypto` and `gcpkmscrypto` call the cloud SDKs
with `context.Background()` and a `Sign` can hang on a network stall. Add
`ctx` to the interfaces (or context-aware variants), thread it through
`csr.Provider`, `authority.Issuer.Sign` and `jwt`. Related: XPKI-024.

## KMS encryption keys

`awskmscrypto` and `gcpkmscrypto` reject `GenerateRSAKey` purpose 2 and
return no key for an `ENCRYPT_DECRYPT` key, since neither implements
`crypto.Decrypter` (v1.0). A KMS-backed decrypter (AWS `RSAES_OAEP_SHA_256`,
GCP `RSA_DECRYPT_OAEP_*`) needs `KeyManager` listing and `GetKey` to return
a decrypter for such keys, and `crypto11`-compatible `*rsa.OAEPOptions`
handling; add it when a caller needs KMS-held encryption keys.

## Post-quantum signatures: ML-DSA (FIPS 204)

v1.1 ships ML-DSA-44/65/87 keys through every provider, CSRs,
certificates, CRLs, proofs, detection helpers, an `allowed_key_algorithms`
profile policy and `hsm-tool` support (see
[`Documentation/RELEASE_NOTES_1.1.md`](Documentation/RELEASE_NOTES_1.1.md)
and [`Documentation/design/pqc.md`](Documentation/design/pqc.md)). Open
work, each item its own change when wanted:

- **`crypto11` verification** (PLAN.md PQ5b): the PKCS#11 v3.2 ML-DSA code
  has not run against a token; provision a v3.2 software token (Kryoptic)
  as a fixture, verify and fix, add the parameter set to `KeyInfo.Meta`,
  decide on `CK_SIGN_ADDITIONAL_CONTEXT` (context strings, deterministic
  signing).
- **Live KMS confirmation**: the AWS (`EXTERNAL_MU`/`ML_DSA_SHAKE_256`) and
  GCP (`PQ_SIGN_ML_DSA_*`, `data`/`data_crc32c`) request shapes follow the
  SDK types and documentation and are exercised against in-process fakes;
  `local-kms` 3.11.7 rejects ML-DSA key specs. Run `TestKmsProviderMLDSA`
  and a GCP smoke test against the real services once and record the result.
- **OCSP with an ML-DSA responder**: `golang.org/x/crypto/ocsp` signs with
  RSA/ECDSA only, so an ML-DSA issuer needs a delegated classical
  responder (D5). Build the response locally (or upstream the change) so an
  ML-DSA key can sign OCSP, and make the delegated responder key algorithm
  configurable.
- **ML-DSA in `jwt`/`jwt/dpop`** (RFC 9964: `ML-DSA-44/65/87` JOSE
  algorithms, `AKP` JWKs; go-jose v4.1.9 implements them on Go 1.27):
  `NewSignerInfo`, `VerifySignature`, JWKS `AKP` keys, the DPoP algorithm
  allow-list, and `oauth2client.Client.PublicKey` widened to
  `crypto.PublicKey`. Today an ML-DSA signer is rejected with an error.
- Later: composite/hybrid signatures (draft-ietf-lamps-pq-composite-sigs),
  SLH-DSA (FIPS 205), ML-KEM (FIPS 203, `crypto/mlkem`) for
  `dataprotection` or TLS.

## DPoP: replay protection and access-token binding

`dpop.VerifyConfig` has an opt-in `ReplayCache` (in-memory only), `ath` and
`cnf.jkt` binding, and a trusted `ExternalURL` (v1.0). Remaining:

- a shared `ReplayCache` implementation (for example Redis `SET NX` with an
  expiry) for servers with several instances;
- server-issued nonces (RFC 9449 §8/§9): generating and rotating
  `DPoP-Nonce` values and the `use_dpop_nonce` error. `ExpectedNonce`
  compares only a caller-provided value today.

## JWKS client hardening

`jwt.RemoteKeySet` has an injected client, a timeout, a body limit and a
refresh cooldown (v1.0). Remaining: TTL-based background refresh (honouring
`Cache-Control`), so removed keys expire and new keys are picked up before the
first miss, and `ParserConfig` fields for the `RemoteKeySet` options, which
`NewParser` currently leaves at the defaults.

## PKCS#11 session management

Remaining after v1.0: a `context.Context`-aware borrow (today a borrower at
the session limit waits without a deadline, since `crypto.Signer` has no
context). The deprecated exported `BytesToUlong` can be removed in the next
major version, and `PKCS11Object.Handle` (stale after a logout since v1.0
refreshes handles internally) can become an accessor.

## certutil bundler concurrency

Remaining after v1.0: coalescing concurrent AIA fetches of
the same URL across calls (each call still fetches once), and replacing the
exported mutable `RootPool`/`IntermediatePool`/`KnownIssuers` fields with
accessors in the next major version. Encrypted PKCS#8 supports PBES2 with
PBKDF2 and AES-CBC only; scrypt and PBES1 are not planned unless a caller
needs them. Drop legacy RFC 1423 PEM decryption
(`x509.DecryptPEMBlock`) once callers have migrated to PKCS#8.

## Dependency hygiene

- `gopkg.in/yaml.v3` is archived; `go.yaml.in/yaml/v3` is already an indirect
  dependency. Switch the four direct importers in one change.
- `golang.org/x/crypto/hkdf` in `dataprotection` can move to `crypto/hkdf`.

## dataprotection: versioned blobs and key rotation

`NewSymmetric` blobs are `nonce || ciphertext || tag` with no version or key
id, so callers track which secret protected a blob and re-protect on read
(v1.0 documents the limits: key material of 32 bytes or more, at most 2^32
messages per secret). Add a versioned format (`version || key-id || nonce ||
ciphertext || tag`), a multi-key provider that decrypts with retired secrets
and encrypts with the current one, and a per-secret `Protect` counter or
time-based rotation hook against the message budget; keep `Unprotect`
accepting the legacy unversioned blob during migration.

## Tooling and CI

- Regenerate `cmd/*/README.md` from `--help` output and add per-command
  examples.
