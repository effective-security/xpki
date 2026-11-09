# xpki v1.1 release notes

v1.1 adds post-quantum signatures: ML-DSA-44, ML-DSA-65 and ML-DSA-87
(FIPS 204) as a key type for CSRs, certificates, CRLs, proofs, OCSP responses,
JWTs and DPoP proofs, through every `cryptoprov` provider, with detection
helpers, an authority key policy and CLI support. It is a **breaking** release
for implementers of `cryptoprov.Provider` and callers of
`oauth2client.Client.PublicKey`. The design, the verified toolchain baseline
and the decisions are in [`Documentation/design/pqc.md`](design/pqc.md); what
remains is item 3 of the [roadmap](../ROADMAP.md).

One check that needs outside infrastructure is **not** done, see "Validation":
the GCP request shapes have not run against the live service.

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
- **jwt/oauth2client**: `Client.PublicKey` returns `crypto.PublicKey` and
  `Client.SetPubKey` takes one, instead of `*rsa.PublicKey`. `New` accepts a
  PEM encoded RSA, ECDSA or ML-DSA key in `PubKey`, the types `jwt` verifies
  with; ECDSA and ML-DSA used to be errors, and every other type still is.

### Changes from v1.1.320 and v1.1.321

Those tags carried the first part of v1.1: ML-DSA in `cryptoprov`, CSRs,
certificates, CRLs and proofs. Anyone already on them also gets these changes:

- **authority**: `CreateIssuer` no longer rejects an ML-DSA signer with
  `aia.ocsp_url` and no `aia.delegated_ocsp_profile`, and `SignOCSP` no longer
  refuses an ML-DSA key: the CA key signs the response. See the OCSP client
  constraint below before relying on this.
- **authority**: a request for an ML-DSA certificate with a key usage RFC 9881
  forbids fails instead of being issued (XPKI-127), see "New".
- **authority**: `CreateIssuer` rejects a `delegated_ocsp_profile` whose
  `allowed_key_algorithms` excludes the responder key algorithm, ECDSA by
  default. Such a profile used to fail at the first responder issuance.
- **jwt**: `NewSignerInfo` and the provider constructors accept an ML-DSA
  signer instead of returning `public key not supported`, and
  `StaticKeySet.PublicKeys` accepts `*mldsa.PublicKey`.
- **crypto11**: `EnumKeys` and `KeyInfo` read `CKA_PARAMETER_SET` of an ML-DSA
  key and return an error when the token does not report it.

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
  six algorithms to `x509.MLDSA44/65/87`. For every key type, a key that exists
  but whose signer cannot be returned, because its version never becomes usable
  or its public key cannot be fetched or parsed, is scheduled for destruction, as
  `awskmscrypto` does, instead of staying billable with no id for the caller. This
  is best effort: KMS refuses a version still `PENDING_GENERATION`, and a failure
  is logged with the version name.
- **crypto11**: PKCS#11 v3.2 ML-DSA support (`PKCS11PrivateKeyMLDSA`,
  `GenerateMLDSAKey`, lookup, public key export) with locally declared
  constants, and `KeyInfo.Meta[cryptoprov.MetaParameterSet]` for ML-DSA keys.
- **csr**: `AlgoRSA`, `AlgoECDSA`, `AlgoMLDSA`, `MLDSA44/65/87`,
  `IsPostQuantumAlgo`; `SigAlgo("ML-DSA", n)` and `DefaultSigAlgo` return
  `x509.MLDSA44/65/87`; `KeyRequest.Generate` calls `GenerateMLDSAKey` and
  rejects the encryption purpose for ML-DSA, a signature scheme.
  `KeyRequest.Validate` checks the algorithm, size and purpose without
  generating a key.
- **certutil**: `IsPostQuantumKey`, `IsPostQuantumCertificate`,
  `IsPostQuantumSignatureAlgorithm`, `KeyTypeRSA/ECDSA/MLDSA`;
  `NewKeyInfo` reports `Type` `ML-DSA`, `KeySize` 44/65/87 and `Hash` 0;
  `EncodePrivateKeyToPEM` writes PKCS#8 for ML-DSA keys;
  `ParsePrivateKeyDER` reads them. `ParsePublicKeyFromPEM` reads
  SubjectPublicKeyInfo and PKCS#1 public keys, returning any type
  `x509.ParsePKIXPublicKey` does. `testdata/pqc/` holds OpenSSL 3.5.5
  interoperability vectors (keys, SPKIs, CSRs, certificates, OCSP responses).
- **certutil**: `CreateOCSPResponse` signs with RSA, ECDSA and ML-DSA keys from
  any provider. Classical keys go through `ocsp.CreateResponse` unchanged; for
  an ML-DSA key `golang.org/x/crypto/ocsp` encodes the response and the signature
  over its `tbsResponseData` is pure ML-DSA with an empty context and an
  `id-ml-dsa-*` algorithm without parameters (RFC 9881).
  `ParseOCSPResponse` and `ParseOCSPResponseForCert` follow the rules of
  `ocsp.ParseResponse[ForCert]`, including the `ocsp.ParseError` for a bad
  signature, and also verify ML-DSA signatures, setting
  `Response.SignatureAlgorithm` to `x509.MLDSA44/65/87`.
- **authority**: ML-DSA issuers and roots (`NewRoot`, `CreateIssuer`,
  `Sign`, CRLs); `SignProof`/`VerifyProof` sign the message with ML-DSA
  keys and `VerifyProof` returns an error for unknown key types instead of
  panicking; `CertProfile.AllowedKeyAlgorithms` (`allowed_key_algorithms`:
  `rsa`, `ecdsa`, `ed25519`, `ml-dsa`) restricts the CSR public key
  algorithm per profile. `testdata/csrprofiles/mldsa_server.yaml` is a
  sample request.
- **authority**: `SignOCSP` signs with an ML-DSA CA key or responder.
  `aia.delegated_ocsp_key_algo` and `aia.delegated_ocsp_key_size` select the key
  of the delegated responder (`AIAConfig.DelegatedOCSPKey`); the default stays
  ECDSA P-256. `CreateIssuer` validates them.
- **authority**: RFC 9881 §5 is enforced on issuance (XPKI-127): a request for an
  ML-DSA certificate fails with `profile P: key usage not allowed for an ML-DSA
  key: ...` when the certificate would carry `key encipherment`, `data
  encipherment`, `key agreement`, `encipher only` or `decipher only`, whether
  from `usages` or a raw key usage extension of the profile or the `SignRequest`.
  It is rejected, not adjusted, as the validity rules are. `CreateIssuer` and
  each responder issuance apply the same rule to the `delegated_ocsp_profile`
  when the responder key is ML-DSA. Classical keys are not affected.
- **jwt**: `ML-DSA-44`, `ML-DSA-65` and `ML-DSA-87` (RFC 9964) from an ML-DSA
  signer of any provider, in `ProviderConfig.PrivateKey` and
  `NewProviderFromCryptoSigner`; `VerifySignature`; `AKP` keys in `StaticKeySet`,
  `RemoteKeySet` and the `jwk` header. The algorithm is matched to the key's
  parameter set, and a provider verifies only its own algorithm.
- **jwt/dpop**: the three algorithms are in the proof allow-list, so `NewSigner`
  takes an ML-DSA signer and `VerifyClaims` accepts its proofs; `SaveKey` and
  `LoadKey` handle `AKP` JWKs. `GenerateKey` still generates P-256.
- **testca**: `MLDSAKey(params)` option, `GenerateMLDSAKeyInPEM`;
  `PrivKeyToPEM`, `ToDER`, `ToPKCS8` and `ToPFX` handle ML-DSA keys.
- **hsm-tool**: `hsm generate --algo ML-DSA --size 65` (the size is the
  parameter set); CSR profiles accept `algo: ML-DSA`.
- **xpki-tool**: `ocsp info`, `ocsp fetch` and `cert validate --revocation` read
  ML-DSA signed responses and verify them, `ocsp info` only with `--issuer`.
- **x/print**: key and signature algorithm lines, so post-quantum
  certificates and requests are recognisable.
- **scripts**: `config-kryoptic.sh` and `make kryoptic-config test-kryoptic`
  provision Kryoptic as a PKCS#11 v3.2 token in `~/.xpki/kryoptic` (`KRYOPTIC_DIR`),
  and refuse a location with a directory another user can replace, since it holds
  a PIN and a module that gets loaded. `make hsmconfig` writes the SoftHSM
  configuration to `~/.xpki/softhsm_unittest.json` instead of `/tmp/xpki`, where
  another local user could replace the file that names the module the tests load
  (XPKI-128), and the tests read it through `testenv.SoftHSMConfig`.
  `TestLiveKMSMLDSA` in `awskmscrypto`
  and `gcpkmscrypto` runs against the real services when
  `XPKI_LIVE_AWS_KMS_REGION` or `XPKI_LIVE_GCP_KMS_KEYRING` is set.

## Constraints

- **OCSP clients**: `golang.org/x/crypto/ocsp` v0.58.0 cannot verify an ML-DSA
  response. `ocsp.ParseResponse(der, issuer)` fails, and with an embedded
  certificate it fails even with no issuer. Go clients use
  `certutil.ParseOCSPResponse`; OpenSSL 3.5 reads these responses. With the
  default P-256 delegated responder the response signature is classical, which
  x/crypto verifies, but under an ML-DSA CA the responder's certificate carries
  an ML-DSA signature, so a client with no ML-DSA at all cannot validate the
  response whichever key signs it.
- **OCSP responder authorization**: `certutil.ParseOCSPResponse`, like x/crypto,
  checks signatures only. Whether a responder is authorized (RFC 6960 §4.2.2.2)
  is left to the service that reads the response: any certificate the issuer
  signed can sign a response this function accepts, for classical and ML-DSA
  responses alike. `xpki-tool cert validate --revocation` does not check it
  either. See [roadmap item 11](../ROADMAP.md#11-ocsp-responder-authorization).
- **Token size**: an ML-DSA JWT or DPoP proof with the public key in its header
  is about 6 KB (ML-DSA-44), 8 KB (ML-DSA-65) or 11 KB (ML-DSA-87), which can
  exceed the header limit of an HTTP server or proxy.
- **PKCS#8**: only the seed form of an ML-DSA private key is accepted, as
  `x509.MarshalPKCS8PrivateKey` and
  `openssl genpkey -provparam ml-dsa.output_formats=seed-only` write it;
  OpenSSL's default seed-and-expanded form fails to parse.
- **FIPS 140-3 Go module v1.0.0**: `crypto/mldsa` returns errors there; the
  providers surface them as errors.
- Context strings (`*mldsa.Options.Context`) are accepted by the in-memory,
  AWS and GCP EXTERNAL_MU signers and rejected by `crypto11` and the GCP
  message algorithms; X.509, OCSP and JOSE use no context.
- **crypto11**: `CK_SIGN_ADDITIONAL_CONTEXT` is not built (decided): a context
  string and deterministic signing stay errors or unavailable there, since
  X.509, OCSP and JOSE need neither.

## Client changes

- Implementers of `cryptoprov.Provider` add `GenerateMLDSAKey`.
- Hash-then-sign callers that may receive an ML-DSA signer must branch on
  the key type (`certutil.IsPostQuantumKey`) and pass the message, as
  `authority.SignProof` does.
- Parsers of `x/print` output allow the two new algorithm lines.
- Callers of `oauth2client.Client.PublicKey` that used it as an
  `*rsa.PublicKey` add a type assertion; callers that pass it to
  `jwt.StaticKeySet.PublicKeys` change nothing.
- Go OCSP clients that may meet an ML-DSA issuer replace `ocsp.ParseResponse` and
  `ocsp.ParseResponseForCert` with the `certutil` functions, which behave the
  same for classical responses. A service that relies on a response checks the
  responder's authorization itself.
- A profile that issues to ML-DSA keys lists none of the forbidden key usages. A
  profile shared with RSA keys that needs `key encipherment` is split in two; a
  certificate already issued is not affected.
- An ML-DSA issuer on v1.1.320 or v1.1.321 that relied on the rejection to keep
  its CA key from signing OCSP sets `aia.delegated_ocsp_profile`, or removes
  `aia.ocsp_url`.
- A `delegated_ocsp_profile` with `allowed_key_algorithms` lists the responder
  key algorithm.
- A development checkout runs `make hsmconfig` again, and can remove
  `/tmp/xpki/softhsm_unittest.json`.

## Validation

Run on 2026-11-08 and 2026-11-09 with Go 1.27.3, SoftHSM 2.6.1, `local-kms`
3.11.7 and OpenSSL 3.5.5:

- Unit tests for every package above, including the KMS fakes with real
  ML-DSA keys and both message types (the GCP fake also enforces the
  `NIST_PQC` public key format), the in-memory concurrency test with
  ML-DSA keys, the OpenSSL 3.5.5 vectors and end-to-end issuance for the
  three parameter sets.
- `make lint` (0 issues); `make covtest` (92.3% total, the gate is
  above 90%); `make test RACE=true`; `make test-scripts`.
- OCSP interoperability in both directions: `openssl ocsp -respin R -issuer CA
  -CAfile CA -no_nonce` reports `Response verify OK` for responses from
  `authority.SignOCSP`, direct and through an ML-DSA delegated responder, for all
  three parameter sets; `certutil.ParseOCSPResponse` verifies the OpenSSL vectors
  in `certutil/testdata/pqc/`.
- JOSE interoperability in both directions with go-jose v4.1.9 as the independent
  RFC 9964 implementation, for all three parameter sets.
- AWS KMS (roadmap 3.2): `TestLiveKMSMLDSA` passed against the live service on
  2026-11-09 for all three parameter sets: key creation, signing a message, a μ
  and a message with a context, reading the key back, and a CSR and a certificate.
- `TestKmsProviderMLDSA` reaches `local-kms`, which rejects the `ML_DSA_*`
  key specs with a `ValidationException`, and skips with that reason.
- `crypto11` (roadmap 3.1): `TestMLDSAOnPKCS11v32Token` passed on a Kryoptic 1.5.4
  token on 2026-11-09 for all three parameter sets: generating a key, finding it
  by id and label, signing verified with `mldsa.Verify`, `KeyInfo` and `EnumKeys`
  with the parameter set, export and destruction. `make kryoptic-config
  test-kryoptic` repeats it; CI does not provision a v3.2 token, so it does not run
  there. The SoftHSM failure path (`CKM_ML_DSA_KEY_PAIR_GEN` rejected, no orphan
  key) and the pure helpers are tested.
- Independent code reviews of the change found the GCP public key format gap,
  the wider `oauth2client` key types, panics on uninitialized keys, a different
  error type for a bad ML-DSA signature, permission and working-directory
  problems in the fixture script, and weak tests, all fixed here, and no
  signature bypass or algorithm confusion. They also confirmed the key usage
  gap (XPKI-127, fixed here) and the responder authorization constraint above.

**Not run:**

- GCP KMS (roadmap 3.2): `TestLiveKMSMLDSA` has not completed against the live
  service, and stays open until there is GCP access. Its only attempt used a
  placeholder key ring and failed creating the first key, so it says nothing about
  the request shapes, which have run only against the in-process fake.
