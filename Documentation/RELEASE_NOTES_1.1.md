# xpki v1.1 release notes

v1.1 adds post-quantum signatures: ML-DSA-44, ML-DSA-65 and ML-DSA-87
(FIPS 204) as a key type for CSRs, certificates, CRLs and proofs, through
every `cryptoprov` provider, with detection helpers, an authority key
policy and CLI support. It is a **breaking** release for implementers of
`cryptoprov.Provider`. The design, the verified toolchain baseline and the
decisions are in [`Documentation/design/pqc.md`](design/pqc.md).

## Breaking changes

- **cryptoprov**: `KeyGenerator`, and therefore `Provider`, gained
  `GenerateMLDSAKey(label string, params mldsa.Parameters)`. Every
  provider in this module implements it; an external implementation must
  add the method (return an error when the backend has no ML-DSA). This
  resolves design decision D1 by folding the generator into the interface
  instead of the optional interface the design proposed, since v1.1 allows
  breaking changes.
- **cryptoprov** (AWS KMS, GCP KMS): `KeyInfo.Type` is now set for every
  listed or described key (`RSA`, `ECDSA`, `ML-DSA`); it was empty before.
- **csr**: `KeyRequest` with `algo: ML-DSA` generates a key instead of
  returning the "not implemented" error of PR 568. The `DILITHIUM` alias
  of that PR is not accepted: the keys are FIPS 204 ML-DSA, not round-3
  Dilithium.
- **certutil**: `Bundler.Bundle` accepts a leaf with an ML-DSA key; a key
  of another type than the leaf's is reported as `key mismatch`, as before.
- **inmemcrypto**: `ExportKey` of an unexpected key type returns an error
  instead of panicking.
- **x/print**: `Certificate` and `CertificateRequest` print two new lines,
  `Public Key Algorithm:` and `Signature Algorithm:`, when the algorithms
  are known. Tools that parse the output line by line must allow them.

## New

- **cryptoprov**: `MLDSAParameters` (44/65/87), the signer contract
  `MLDSASignerOptions` and `MLDSAMu` (FIPS 204 Algorithm 7) in `mldsa.go`;
  `MLDSA44/65/87`, `MetaParameterSet`, `MLDSAMuSize`.
  `ParsePrivateKeyDER` and `ParsePrivateKeyPEM` return `*mldsa.PrivateKey`
  for a PKCS#8 seed-form key. The signer contract: an ML-DSA signer from
  any provider signs the **message** with nil options, a zero hash
  (`x509.CreateCertificate` passes `crypto.Hash(0)`) or `*mldsa.Options`,
  signs a 64-byte μ with `crypto.MLDSAMu`, and rejects every digest hash
  (and a nil pointer of any other options type), so hash-then-sign callers
  fail instead of signing a digest as a message.
- **inmemcrypto**, **testprov**: `GenerateMLDSAKey`; `ExportKey` writes a
  PKCS#8 `PRIVATE KEY` block (seed form) for ML-DSA keys; `Sign` defaults
  nil options to SHA-256 only for RSA and ECDSA keys.
- **awskmscrypto**: `GenerateMLDSAKey` creates `ML_DSA_44/65/87` keys.
  `Signer.Sign` on an ML-DSA key computes μ locally and calls KMS with
  `MessageType` `EXTERNAL_MU` and `ML_DSA_SHAKE_256`, so the message never
  leaves the process and the RAW message size limit does not apply.
  `KeyInfo` and `EnumKeys` report `Type` and `parameter_set`.
- **gcpkmscrypto**: `GenerateMLDSAKey` creates
  `PQ_SIGN_ML_DSA_*_EXTERNAL_MU` keys; `GetKey` and `Signer.Sign` also
  support `PQ_SIGN_ML_DSA_*` keys created elsewhere (the message is sent
  in `data`). Requests carry `data`/`data_crc32c` and responses are
  checked with `verified_data_crc32c`. Public keys of ML-DSA versions are
  fetched in the `NIST_PQC` format (KMS returns no PEM for them) and
  accepted only with a matching `crc32c_checksum`; `KeyInfo.PublicKey`
  re-encodes them as PEM. `Signer.SignatureAlgorithm` maps the
  six algorithms to `x509.MLDSA44/65/87`.
- **crypto11**: PKCS#11 v3.2 ML-DSA support (`PKCS11PrivateKeyMLDSA`,
  `GenerateMLDSAKey`, lookup, public key export) with locally declared
  constants. See "Validation" below: this code is not yet exercised against
  a token.
- **csr**: `AlgoRSA`, `AlgoECDSA`, `AlgoMLDSA`, `MLDSA44/65/87`,
  `IsPostQuantumAlgo`; `SigAlgo("ML-DSA", n)` and `DefaultSigAlgo` return
  `x509.MLDSA44/65/87`; `KeyRequest.Generate` calls `GenerateMLDSAKey` and
  rejects the encryption purpose for ML-DSA, a signature scheme.
- **certutil**: `IsPostQuantumKey`, `IsPostQuantumCertificate`,
  `IsPostQuantumSignatureAlgorithm`, `KeyTypeRSA/ECDSA/MLDSA`;
  `NewKeyInfo` reports `Type` `ML-DSA`, `KeySize` 44/65/87 and `Hash` 0;
  `EncodePrivateKeyToPEM` writes PKCS#8 for ML-DSA keys;
  `ParsePrivateKeyDER` reads them. `testdata/pqc/` holds OpenSSL 3.5.5
  interoperability vectors (keys, SPKIs, CSRs, certificates).
- **authority**: ML-DSA issuers and roots (`NewRoot`, `CreateIssuer`,
  `Sign`, CRLs); `SignProof`/`VerifyProof` sign the message with ML-DSA
  keys and `VerifyProof` returns an error for unknown key types instead of
  panicking; `CertProfile.AllowedKeyAlgorithms` (`allowed_key_algorithms`:
  `rsa`, `ecdsa`, `ed25519`, `ml-dsa`) restricts the CSR public key
  algorithm per profile. `testdata/csrprofiles/mldsa_server.yaml` is a
  sample request.
- **testca**: `MLDSAKey(params)` option, `GenerateMLDSAKeyInPEM`;
  `PrivKeyToPEM`, `ToDER`, `ToPKCS8` and `ToPFX` handle ML-DSA keys.
- **hsm-tool**: `hsm generate --algo ML-DSA --size 65` (the size is the
  parameter set); CSR profiles accept `algo: ML-DSA`.
- **x/print**: key and signature algorithm lines, so post-quantum
  certificates and requests are recognisable.

## Constraints

- **OCSP** (decision D5): `golang.org/x/crypto/ocsp` signs with RSA and
  ECDSA keys only. `CreateIssuer` rejects an ML-DSA signer whose
  `aia.ocsp_url` is set unless `aia.delegated_ocsp_profile` names a profile
  for the (classical, in-memory P-256) delegated responder; an issuer
  without an OCSP URL is accepted, and `SignOCSP` refuses to sign with an
  ML-DSA CA key.
- **jwt**: ML-DSA keys are rejected with `public key not supported`
  (RFC 9964 JOSE algorithms are a later milestone).
- **PKCS#8**: only the seed form of an ML-DSA private key is accepted, as
  `x509.MarshalPKCS8PrivateKey` and
  `openssl genpkey -provparam ml-dsa.output_formats=seed-only` write it;
  OpenSSL's default seed-and-expanded form fails to parse.
- **FIPS 140-3 Go module v1.0.0**: `crypto/mldsa` returns errors there; the
  providers surface them as errors.
- Context strings (`*mldsa.Options.Context`) are accepted by the in-memory,
  AWS and GCP EXTERNAL_MU signers and rejected by `crypto11` and the GCP
  message algorithms; X.509 uses no context.

## Client changes

- Implementers of `cryptoprov.Provider` add `GenerateMLDSAKey`.
- Hash-then-sign callers that may receive an ML-DSA signer must branch on
  the key type (`certutil.IsPostQuantumKey`) and pass the message, as
  `authority.SignProof` does.
- Configurations that run an ML-DSA issuer with OCSP add
  `aia.delegated_ocsp_profile`.
- Parsers of `x/print` output allow the two new algorithm lines.

## Validation

Run on 2026-11-08 with Go 1.27.3, SoftHSM 2.6.1 and `local-kms` 3.11.7:

- Unit tests for every package above, including the KMS fakes with real
  ML-DSA keys and both message types (the GCP fake also enforces the
  `NIST_PQC` public key format), the in-memory concurrency test with
  ML-DSA keys, the OpenSSL 3.5.5 vectors and end-to-end issuance for the
  three parameter sets; `make lint`; `go test -race` on the provider,
  `authority`, `csr`, `certutil` and `testca` packages; `make covtest`.
- An independent code review of the change found the GCP public key
  format gap above (fixed before release) and no other defect; its notes
  are reflected in the constraints above.
- `TestKmsProviderMLDSA` reaches `local-kms`, which rejects the `ML_DSA_*`
  key specs with a `ValidationException`, and skips with that reason; the
  AWS and GCP code paths were not run against the live services.
- `crypto11`: the SoftHSM failure path (`CKM_ML_DSA_KEY_PAIR_GEN` rejected,
  no orphan key) and the pure helpers are tested; the generate, find, sign
  and export path (`TestMLDSAOnPKCS11v32Token`) needs the token config of
  a PKCS#11 v3.2 module in `XPKI_PKCS11_V32_CONFIG` and was **not run**: no
  such module was available. Treat `crypto11` ML-DSA as unverified until
  it is.
