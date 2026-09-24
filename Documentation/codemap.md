# Code map

Navigation index for agents and new contributors: concept → file → entry
points → invariants. Start here instead of grepping the tree. If you had to
grep for something that belongs in this map, add the row in the same change
(see [AGENTS.md](../AGENTS.md)).

- High level purpose and samples: [README.md](../README.md)
- Known defects and verified fixes, with IDs referenced from code comments: [FINDINGS.md](../FINDINGS.md)
- Larger planned work: [ROADMAP.md](../ROADMAP.md)
- Generated API reference (`make docs`, gomarkdoc, do not edit): [api](./api)

## Module layout

`github.com/effective-security/xpki`, Go 1.27. Library packages plus two CLIs.

| Path                                                             | Purpose                                                                 |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `cryptoprov/`                                                    | Provider abstraction, loader registry, token config, key URIs, PEM      |
| `crypto11/`                                                      | PKCS#11 provider (manufacturer `SoftHSM`), cgo, fork of Thales crypto11 |
| `cryptoprov/awskmscrypto/`                                       | AWS KMS provider (`AWSKMS`)                                             |
| `cryptoprov/gcpkmscrypto/`                                       | GCP KMS provider (`GCPKMS`)                                             |
| `cryptoprov/inmemcrypto/`                                        | In-memory provider (`inmem`), exportable keys                           |
| `cryptoprov/testprov/`                                           | Test provider, non-exportable keys, not self-registered                 |
| `csr/`                                                           | CSR types, key requests, CSR create/parse, SAN and CRL-DP encoding      |
| `authority/`                                                     | CA: config, profiles, issuers, `Sign`, OCSP, root bootstrap             |
| `certutil/`                                                      | PEM/cert/key helpers, chain bundler, hashes, OCSP request               |
| `jwt/`                                                           | JWT sign/verify, claims, JWKS key sets                                  |
| `jwt/dpop/`                                                      | DPoP proofs (RFC 9449)                                                  |
| `jwt/accesstoken/`                                               | Opaque encrypted `pat.` tokens over `jwt` + `dataprotection`            |
| `jwt/oauth2client/`                                              | OAuth2/OIDC client registry and token-request builder                   |
| `dataprotection/`                                                | AES-GCM `Provider` with HKDF key derivation                             |
| `armor/`, `oid/`, `x/print/`, `metricskey/`, `internal/version/` | Helpers (see below)                                                     |
| `testca/`                                                        | Test-only CA and certificate generator                                  |
| `cmd/hsm-tool/`, `cmd/xpki-tool/`                                | CLIs (kong)                                                             |

Dependency direction (non-test): `cryptoprov` ← `crypto11`, `awskmscrypto`,
`gcpkmscrypto`, `inmemcrypto`, `testprov`, `csr`, `authority`, `jwt`, `cmd/*`.
`certutil` is a leaf used by almost everything. `csr` ← `authority`, `jwt`,
`cmd/hsm-tool`. `jwt` ← `dpop`, `accesstoken`. `oid` ← `authority`, `csr`,
`x/print`. `metricskey` ← `authority`, KMS providers. `armor` has no in-repo
consumers. Nothing in the library imports `cmd/`.

## Concept index

| Concept                                    | File(s)                                                                      | Entry points                                                                                                                  |
| ------------------------------------------ | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Provider interfaces                        | `cryptoprov/provider.go`                                                     | `Provider`, `KeyGenerator`, `KeyManager`, `KeyInfo`, `TokenInfo`                                                              |
| Provider registry / loading                | `cryptoprov/loader.go`                                                       | `Register`, `LoadProvider`, `Load`, `Registered`                                                                              |
| Multi-provider registry                    | `cryptoprov/provider.go`                                                     | `Crypto`, `New`, `Add`, `ByManufacturer`, `Default`                                                                           |
| Token config file (JSON/YAML, `file:` PIN) | `cryptoprov/config.go`, `crypto11/config.go`                                 | `LoadTokenConfig`, `TokenConfig`                                                                                              |
| PKCS#11 key URI                            | `cryptoprov/uri.go`                                                          | `ParseTokenURI`, `ParsePrivateKeyURI`, `PrivateKeyURI`                                                                        |
| Load key from PEM or URI                   | `cryptoprov/utils.go`, `cryptoprov/signer.go`                                | `Crypto.LoadPrivateKey`, `NewSignerFromPEM`, `NewSignerFromFromFile`, `LoadTLSKeyPair`                                        |
| AES-GCM helpers                            | `cryptoprov/gcm.go`                                                          | `GcmEncrypt`, `GcmDecrypt`                                                                                                    |
| PKCS#11 init / token select / login        | `crypto11/config.go`                                                         | `Init`, `ConfigureFromFile`, `LoadTokenConfig`                                                                                |
| PKCS#11 session pool                       | `crypto11/sessions.go`                                                       | `withSession`, `setupSessions`                                                                                                |
| PKCS#11 key generation / lookup            | `crypto11/keys.go`, `rsa.go`, `ecdsa.go`                                     | `GenerateRSAKey`, `GenerateECDSAKey`, `FindKeyPair*`, `GetKey`, `ExportKey`                                                   |
| PKCS#11 signing / decryption               | `crypto11/rsa.go`, `crypto11/ecdsa.go`                                       | `PKCS11PrivateKeyRSA.Sign/Decrypt`, `PKCS11PrivateKeyECDSA.Sign`                                                              |
| PKCS#11 token / key enumeration            | `crypto11/provider.go`, `crypto11/util.go`                                   | `EnumTokens`, `EnumKeys`, `KeyInfo`, `DestroyKeyPairOnSlot`                                                                   |
| AWS KMS                                    | `cryptoprov/awskmscrypto/awskmsprov.go`, `signer.go`                         | `Init`, `KmsLoader`, `KmsClientFactory`, `Signer`                                                                             |
| GCP KMS                                    | `cryptoprov/gcpkmscrypto/gcpkmsprov.go`, `signer.go`                         | `Init`, `KmsLoader`, `KmsClientFactory`, `KeyLabelAndID`, `Crc32c`                                                            |
| In-memory keys                             | `cryptoprov/inmemcrypto/provider.go`, `concurrency_test.go`                   | `NewProvider`, `Loader`, `ProviderName`, `Provider.GetKey`, `GenerateRSAKey`, `GenerateECDSAKey`, `ExportKey`                   |
| Test-provider key registry                 | `cryptoprov/testprov/provider.go`, `concurrency_test.go`                     | `Init`, `Loader`, `Provider.GetKey`, `GenerateRSAKey`, `GenerateECDSAKey`, `ExportKey`                                        |
| CSR request types                          | `csr/csr.go`                                                                 | `CertificateRequest`, `SignRequest`, `X509Subject`, `X509Name`, `X509Extension`, `AllowedFields`                              |
| CSR create / sign / parse                  | `csr/csrprov.go`, `csr/csr.go`                                               | `NewProvider`, `GenerateKeyAndRequest`, `CreateRequestAndExportKey`, `SignRequest`, `Parse`, `ParsePEM`                       |
| Key request (algo/size/purpose)            | `csr/keyreq.go`                                                              | `KeyRequest`, `NewKeyRequest`, `KeyPurpose`, `SigAlgo`                                                                        |
| Subject merge, SAN classification          | `csr/csr.go`                                                                 | `PopulateName`, `SetSAN`, `FindAttr`                                                                                          |
| CRL distribution point extension           | `csr/csr.go`                                                                 | `EncodeCDP`, `EncodeCDPFull`, `DecodeCDP`, `DecodeCDPFull`, `GeneralName`                                                     |
| JSON/YAML OID and Duration                 | `csr/types.go`                                                               | `OID`, `Duration`, `ParseObjectIdentifier`                                                                                    |
| CA config and profiles                     | `authority/config.go`                                                        | `Config`, `IssuerConfig`, `AIAConfig`, `CertProfile`, `LoadConfig`, `Validate`, `Usages`                                      |
| CA issuer registry                         | `authority/authority.go`                                                     | `NewAuthority`, `GetIssuerBy{Label,Profile,KeyID,KeyHash,NameHash}`                                                           |
| Issuer construction / signing              | `authority/issuer.go`                                                        | `NewIssuer`, `NewIssuerWithBundles`, `CreateIssuer`, `Issuer.Sign`, `SignProof`, `VerifyProof`                                |
| OCSP signing, delegated responder          | `authority/ocsp.go`                                                          | `SignOCSP`, `OCSPSignRequest`, `CreateDelegatedOCSPSigner`, `OCSPReasonStringToCode`                                          |
| Certificate policies, SKI                  | `authority/extensions.go`                                                    | `addPolicies`, `CTPoisonOID`, `SCTListOID`                                                                                    |
| Root bootstrap / cert files                | `authority/root.go`, `authority/util.go`                                     | `NewRoot`, `Issuer.GenCert`                                                                                                   |
| PEM parse / encode                         | `certutil/pem.go`                                                            | `ParseFromPEM`, `ParseChainFromPEM`, `Load*FromPEM`, `EncodeToPEM*`, `ParsePrivateKeyPEM*`, `EncodePrivateKeyToPEM`           |
| Chain bundling / verification              | `certutil/bundler.go`, `certutil/bundle.go`                                  | `NewBundler*`, `LoadBundler`, `Bundler.Bundle`, `VerifyBundleFromPEM`, `LoadAndVerifyBundleFromPEM`, `Bundle`, `BundleStatus` |
| Hashes, thumbprints, IDs                   | `certutil/hash.go`, `certutil/cert_id.go`                                    | `Digest`, `SHA1*`, `SHA256*`, `NewHash`, `GetThumbprintStr`, `GetSubjectID`, `GetIssuerID`                                    |
| Key info (type, size, hash, JWK)           | `certutil/keyinfo.go`                                                        | `NewKeyInfo`, `KeyInfo`                                                                                                       |
| OCSP request, extensions                   | `certutil/ocsp.go`, `certutil/extensions.go`                                 | `CreateOCSPRequest`, `FindExtension`, `IsOCSPSigner`, `HasOCSPNoCheck`                                                        |
| Randomness                                 | `certutil/random.go`                                                         | `Random`, `RandomString`, `RandReader`                                                                                        |
| JWT provider (sign + verify)               | `jwt/jwt.go`                                                                 | `ProviderConfig`, `LoadProvider`, `NewProvider`, `NewProviderFromCryptoSigner`, `NewProviderWithSymmetricKey`, `WithHeaders`  |
| JWT signing internals                      | `jwt/sign.go`                                                                | `NewSignerInfo`, `VerifySignature`                                                                                            |
| JWT parsing (third-party tokens)           | `jwt/parser.go`                                                              | `ParserConfig`, `LoadParserConfig`, `NewParser`, `TokenParser`, `Keyfunc`                                                     |
| Claims                                     | `jwt/claims.go`                                                              | `Claims`, `MapClaims`, `NumericDate`, `Audience`, `CreateClaims`, `SetClaimsExpiration`, `TimeNowFn`                          |
| JWKS key sets                              | `jwt/jwks.go`                                                                | `KeySet`, `StaticKeySet`, `RemoteKeySet`, `NewRemoteKeySet`                                                                   |
| DPoP proof create / verify                 | `jwt/dpop/signer.go`, `jwt/dpop/verify.go`                                   | `NewSigner`, `ForRequest`, `VerifyRequestClaims`, `VerifyClaims`, `GetTokenInfo`                                              |
| DPoP keys                                  | `jwt/dpop/keys.go`                                                           | `GenerateKey`, `LoadKey`, `SaveKey`, `Thumbprint`                                                                             |
| Opaque access tokens                       | `jwt/accesstoken/accesstoken.go`                                             | `New`, `Provider`                                                                                                             |
| OAuth2 client registry                     | `jwt/oauth2client/*.go`                                                      | `LoadProvider`, `NewProvider`, `RegisterClient`, `ClientFor*`, `Client.CreateTokenRequest[WithContext]`                       |
| Data protection                            | `dataprotection/dp.go`, `symmetric.go`                                       | `Provider`, `NewSymmetric`, `ProtectObject`, `UnprotectObject`                                                                |
| Human-readable printing                    | `x/print/certutil.go`                                                        | `Certificate(s)`, `CertificateRequest`, `CertificateList`, `OCSPResponse`, `CertAndKey`, `JSON`                               |
| OID / usage names                          | `oid/oidinfo.go`                                                             | `KeyUsage*`, `ExtKeyUsage*`, `DisplayName`, `KeyUsages`, `ExtKeyUsages`, `Strings`                                            |
| ASCII armor decoding                       | `armor/armor.go`                                                             | `Decode`, `Block`                                                                                                             |
| Metrics descriptors                        | `metricskey/metricskey.go`                                                   | `PerfCryptoOperation`, `PerfCAOperation`, `PerfCASignRequest`, `Metrics`                                                      |
| Build version                              | `internal/version/*.go`                                                      | `Current`, `Info`, `PopulateFromBuild`                                                                                        |
| SoftHSM fixture setup                      | `scripts/config-softhsm.sh`, `scripts/config-softhsm_test.sh`                | `make hsmconfig`, `make test-scripts`, setup `--help`                                                                         |
| Test CA fixtures                           | `testca/entity.go`, `configuration.go`, `mkcert.go`, `testca.go`, `utils.go` | `NewEntity`, options, `MakeSelfCert*`, `MakeValidCertsChainTSA`, `ToPEM`                                                      |
| Concurrent test CA names / serials         | `testca/configuration.go`, `entity.go`, `concurrency_test.go`                | `NewEntity`, `Entity.Issue`, `Entity.IncrementSN`, `NextSerialNumber`                                                         |
| CLI: HSM/KMS key management                | `cmd/hsm-tool/cli/hsm.go`, `csr.go`, `cli.go`                                | `Cli`, `HsmListCmd`… , `CsrCreateCmd`…                                                                                        |
| CLI: PKI inspection                        | `cmd/xpki-tool/cli/certs.go`, `crl.go`, `ocsp.go`, `csr.go`                  | `CertInfoCmd`, `CertValidateCmd`, `CRL*Cmd`, `OCSP*Cmd`, `OCSPValidation`, `CRLValidation`                                    |

## Package cryptoprov

Provider-agnostic key abstraction: `Provider` (generate/lookup/export keys +
`Manufacturer`/`Model`), `KeyManager` (enumerate tokens and keys, key info,
destroy), the `Crypto` registry keyed by `manufacturer@model`, the process-global
loader registry, token config loading, PKCS#11 URI parsing, PEM/DER key
parsing, TLS key-pair loading and AES-GCM helpers.

### Files

| File          | Role                                                                                                                        |
| ------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `provider.go` | Interfaces, `KeyInfo`/`TokenInfo`, `Crypto` (`New`, `Add`, `ByManufacturer`)                                                |
| `loader.go`   | `loaders` map + `lockLoaders`; `Register`, `Unregister`, `Registered`, `LoadProvider`, `Load`                               |
| `config.go`   | `TokenConfig` interface, JSON/YAML struct, `LoadTokenConfig` with `file:` PIN resolution (absolute, cwd, config dir)        |
| `uri.go`      | `ParseTokenURI`, `ParsePrivateKeyURI`                                                                                       |
| `utils.go`    | `Crypto.LoadPrivateKey` (PEM or `pkcs11:` URI), `ParsePrivateKeyPEM*`, `ParsePrivateKeyDER`, `LoadTLSKeyPair`, `TLSKeyPair` |
| `signer.go`   | `NewSignerFromFromFile`, `NewSignerFromPEM`                                                                                 |
| `gcm.go`      | `GcmEncrypt`/`GcmDecrypt` (nonce prefixed)                                                                                  |

### Invariants

- Providers self-register in `init()`: `crypto11`→`SoftHSM`, `awskmscrypto`→`AWSKMS`,
  `gcpkmscrypto`→`GCPKMS`, `inmemcrypto`→`inmem`. `testprov` does not. Blank-import
  the provider packages before `Load`.
- Config location `""` or `"inmem"` maps to manufacturer `inmem`; `.json` suffix
  selects JSON, otherwise YAML. JSON keys: `Manufacturer, Model, Path, TokenSerial,
TokenLabel, Pin, Attributes`; YAML keys are snake_case.
- `Provider` does not embed `KeyManager` or `Close`; type-assert when needed.
- Key URI: `pkcs11:manufacturer=M;model=X;id=ID;serial=S;type=private`;
  `ParsePrivateKeyURI` requires `type=private`, `serial`, `id`. Query-form
  attributes are not parsed (XPKI-027).
- `Crypto` has no locking; `Add` after construction is not goroutine-safe and
  silently overwrites (XPKI-016). `New(nil, …)` panics (XPKI-026).
- `file:` PIN content has trailing `\r`/`\n` stripped; other whitespace is part of the PIN.
- `ParsePrivateKeyDER` accepts PKCS#8 (RSA, ECDSA, Ed25519), PKCS#1 and SEC1;
  the parse error from each attempt is preserved (`errors.Join`) under
  `failed to parse key`.
- `TLSKeyPair`/`LoadTLSKeyPair` set `Certificate.Leaf` and return an error
  when the private key's public half does not `Equal` the leaf's public key.
- Errors are `cockroachdb/errors`; sentinels `ErrInvalidURI`, `ErrInvalidPrivateKeyURI`.

### Test layout

`config_test.go`, `loader_test.go`, `provider_test.go` need SoftHSM at
`/tmp/xpki/softhsm_unittest.json` (`make hsmconfig`) and fail without it.
`loader_test.go` unregisters/re-registers `SoftHSM`. `testdata/` holds
`inmem_testprov.{json,yaml}`, `inmem_pin.txt`, `test-{cert,key}.pem`.
`Test_Aws`/`Test_Gcp` are empty (XPKI-099).

## Package crypto11

PKCS#11 wrapper over `github.com/miekg/pkcs11` exposing HSM-resident RSA and
ECDSA keys as `crypto.Signer`/`crypto.Decrypter`, with a per-slot session pool,
key generation/lookup/destroy, token enumeration and HSM randomness. Requires a
C toolchain (cgo) and dlopens the module named in the config.

### Files

| File          | Role                                                                                                                                               |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `doc.go`      | Package comment                                                                                                                                    |
| `crypto11.go` | Sentinel errors, `PKCS11Lib`, `PKCS11Object`, `PKCS11PrivateKey`, `Close`                                                                          |
| `config.go`   | `TokenConfig`, `Init` (load, select token by serial OR label, login), `ConfigureFromFile`, `LoadTokenConfig`, `maxSessionsChan`                    |
| `sessions.go` | `NewSession`, `withSession`, `setupSessions`                                                                                                       |
| `provider.go` | `cryptoprov` glue: `init()` registration, `LoadProvider`, `EnumTokens`, `EnumKeys`, `KeyInfo`                                                      |
| `keys.go`     | `KeyPurpose`, `findKey`, `ListKeys`, `FindKeyPair*`, `ConvertToPublic`, `GetKey`, `ExportKey`, `GenerateRSAKey`, `GenerateECDSAKey`, `IdentifyKey` |
| `rsa.go`      | `PKCS11PrivateKeyRSA`: generate, `Sign` (PKCS#1 v1.5, PSS), `Decrypt` (PKCS#1 v1.5, OAEP), `Validate`                                              |
| `ecdsa.go`    | `PKCS11PrivateKeyECDSA`: curve table (P-224/256/384/521), generate, `Sign` (DER r,s)                                                               |
| `common.go`   | Attribute/class/type name maps, `UlongToBytes`/`BytesToUlong` (unsafe), ECDSA signature DER helpers, label/ID generation                           |
| `util.go`     | `CurrentSlotID`, `TokensInfo`, `DestroyKeyPairOnSlot`, `getPublicKeyPEM`                                                                           |
| `rand.go`     | `GenRandom`                                                                                                                                        |

### Invariants

- One buffered channel of sessions per slot (cap 1024); `withSession` takes or
  opens a session and always returns it. Sessions are never closed and the
  count is unbounded (XPKI-005). Only the default slot pool is created in
  `Init`; `withSession` on a slot without a pool blocks (XPKI-003); map access
  is not fully locked (XPKI-002). Sign/Decrypt use the slot recorded on the
  key object (`PKCS11Object.Slot`), so keys found on other slots work.
- `Init` tolerates `CKR_CRYPTOKI_ALREADY_INITIALIZED`, so several `PKCS11Lib`
  may share one module; `Close` does not finalize correctly (XPKI-001).
- Token selection: serial OR label match, first wins; empty configured fields
  match empty token fields (XPKI-006). `Pin` may be `file:<path>` (trailing
  line endings stripped, other whitespace kept).
- RSA: exponent 65537; PSS accepts `PSSSaltLengthAuto` (largest salt that
  fits, as `crypto/rsa`), `PSSSaltLengthEqualsHash` or an explicit length;
  PKCS#1 v1.5 and OAEP support SHA-1/224/256/384/512 (SoftHSM2 only does SHA-1
  OAEP), any other hash is rejected with `errUnsupportedRSAOptions`.
  `Decrypt` accepts nil, `*rsa.PKCS1v15DecryptOptions` (SessionKeyLen 0 only)
  or `*rsa.OAEPOptions`. OAEP/PSS parameters use
  `pkcs11.NewOAEPParams`/`NewPSSParams`.
- Public key export needs a separate `CKO_PUBLIC_KEY` object with the same ID/label.
- `EnumKeys`/`ListKeys`/`FindKeys` drain `C_FindObjects` in batches of 100
  (`findAllObjects`), so large tokens are not truncated.
- `DestroyKeyPairOnSlot` returns `errKeyNotFound` when neither the private
  nor the public object exists; `ConvertToPublic` also accepts the wrapper
  returned by `GenerateRSAKey`/`GenerateECDSAKey`.
- Panics: `mustMarshal` at init, `BytesToUlong` on short input (XPKI-011),
  RSA `Sign(nil opts)` (same as stdlib). Everything else returns wrapped errors.

### Test layout

All tests are SoftHSM integration tests; `TestMain` panics if
`/tmp/xpki/softhsm_unittest.json` is missing. No `testdata/`. Keys generated by
tests persist in the token; only `Test_DestroyKey` cleans up.

## Packages cryptoprov/awskmscrypto, gcpkmscrypto, inmemcrypto, testprov

| Package        | Manufacturer | Key material                                        | `ExportKey` returns                | Config `Attributes`                                                                  |
| -------------- | ------------ | --------------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------ |
| `awskmscrypto` | `AWSKMS`     | KMS RSA 2048/3072/4096, P-256/384/521 sign keys     | `pkcs11:` URI (serial = ARN)       | `Endpoint=<url>,Region=<r>` (both optional)                                          |
| `gcpkmscrypto` | `GCPKMS`     | Cloud KMS HSM-level RSA 2048/3072/4096, P-256/384   | `pkcs11:` URI (serial = 1)         | `Keyring=projects/P/locations/L/keyRings/R` (required; `Endpoint` ignored, XPKI-021) |
| `inmemcrypto`  | `inmem`      | In-process RSA/ECDSA                                | PKCS#1 / SEC1 PEM bytes            | none                                                                                 |
| `testprov`     | `testprov`   | In-process RSA/ECDSA, implements `crypto.Decrypter` | `pkcs11:` URI with `token=<label>` | none                                                                                 |

Invariants: KMS providers call the SDKs with `context.Background()` (ROADMAP);
`KmsClientFactory` package vars are the test seams; AWS `EnumKeys` is a full
account scan with one `DescribeKey` per key (XPKI-032); GCP always uses
`cryptoKeyVersions/1` (XPKI-020) and `Close` must be called to release gRPC;
`Signer.Sign` with nil opts panics (XPKI-025); `inmemcrypto.NewProvider()` is
used at runtime by `authority/ocsp.go` for delegated responder keys. Both
`inmemcrypto` and `testprov` registries use an RWMutex for map publication
and lookup (XPKI-017, Fixed by IM1 and TP1). Key generation, signing,
decryption, and export serialization/formatting run outside the map lock.
Lookups retain signer identity. `inmemcrypto` exports caller-owned PKCS#1
(RSA) or SEC1 (ECDSA) PEM bytes with an empty URI; `testprov` exports a
PKCS#11 URI with nil key bytes. Token configuration passed to `Loader` must
remain unchanged during use. Metrics: `metricskey.PerfCryptoOperation`.

Tests: `awskmsprov_test.go` needs `local-kms` on `:14556`
(`make start-local-kms`, dummy `AWS_*` env). `gcpkmsprov_test.go` uses a
testify mock via `KmsClientFactory`. `gcpkmscrypto/coverage_test.go` additionally
uses a local gRPC KMS server for real SDK iterator pagination, disabled-key
filtering, and permission errors, and the existing mock for provider failures.
`inmemcrypto`, `testprov` are pure.
`inmemcrypto/concurrency_test.go` and `testprov/concurrency_test.go` overlap
generation with lookup/export on one provider and check generated key
identity, missing-key behavior, and signatures. The former also verifies
PKCS#1/SEC1 parsing, signing with exported keys, and independent PEM buffers;
the latter verifies URI-only export and RSA decryption. Each package's
`BenchmarkGetKey` measures serial hits/misses with key generation outside
the timed loop.

## Package csr

Request types shared by the CA and tooling, key generation through a
`cryptoprov.Provider`, PEM CSR creation and parsing into an `x509.Certificate`
template, subject merging, SAN classification, CRL-DP encoding, JSON/YAML
`OID`/`Duration`.

### Files

| File         | Role                                                                                                                                                                                          |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `csr.go`     | `CertificateRequest`, `SignRequest`, `X509Subject/Name/Extension`, `AllowedFields`, `Parse`/`ParsePEM` (verifies CSR signature), `PopulateName`, `SetSAN`, `Encode/DecodeCDP*`, `GeneralName` |
| `csrprov.go` | `Provider` over one `cryptoprov.Provider`: `GenerateKeyAndRequest`, `CreateRequestAndExportKey`, `SignRequest`, `DefaultSigAlgo`                                                              |
| `keyreq.go`  | `KeyRequest` (RSA 2048–4096, ECDSA 256/384/521, `KeyPurpose`), `Generate`, `SigAlgo`, `NewKeyRequest`                                                                                         |
| `types.go`   | `OID`, `Duration` (JSON number = seconds, string = Go duration; YAML string only), `BasicConstraints`, policy qualifier constants                                                             |

### Invariants

- SAN classification: contains `://` → URI (unparsable entries are skipped
  with an error log), `net.ParseIP` → IP, `mail.ParseAddress` → email, else DNS
  (unvalidated). `SetSAN(t, nil)` keeps CSR SANs; `SetSAN(t, []string{})`
  clears them (XPKI-059).
- `Parse` keeps every CSR extension except BasicConstraints in
  `ExtraExtensions`; `authority.Issuer.Sign` decides what to keep (XPKI-049,
  fixed: deny-by-default for CSR extensions).
- `KeyRequest.prov` is unexported; `GenerateKeyAndRequest` injects the
  provider for requests decoded from JSON/YAML.
- `X509Name` YAML/JSON keys are lowercase (`c`, `st`, `l`, `o`, `ou`, `email`);
  uppercase keys are silently ignored by the YAML decoder.
- `SigAlgo`/`DefaultSigAlgo` never return SHA-1: RSA below 2048 and unknown
  ECDSA curves fall back to SHA-256 (key size validation rejects them anyway).
- `ParseObjectIdentifier` requires the whole string to be dotted decimals
  (`^\d+(\.\d+)*$`).
- `Signer` and `KeyRequestGen` interfaces are unused.

Tests: `csrprov_test.go` and `TestCSR` need SoftHSM. No `testdata/`.

`csr/parsing_coverage_test.go` covers signed CSR BasicConstraints, tampered
signatures, GeneralName ASN.1 variants, invalid provider requests, and YAML
conversion errors with generated keys.

## Package authority

In-process CA. Config → `Authority` → `Issuer` → `Sign`.

### Files

| File            | Role                                                                                                                                             |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `authority.go`  | `Authority` registry (by label, profile, SKID, key hash, name hash), `NewAuthority`                                                              |
| `config.go`     | `Config`, `CAConfig`, `IssuerConfig`, `AIAConfig`, `CertProfile`, `CAConstraint`, `LoadConfig`, `Validate`, role/extension allow-lists, `Usages` |
| `issuer.go`     | `Issuer` construction, `Sign` pipeline, `fillTemplate`, serial generation (20 random bytes, top bit cleared), `SignProof`/`VerifyProof`          |
| `ocsp.go`       | `SignOCSP`, `CreateDelegatedOCSPSigner`, `OCSPResponder`, reason/status maps                                                                     |
| `extensions.go` | Certificate Policies ASN.1, SKI, CT OIDs                                                                                                         |
| `root.go`       | `NewRoot`: key + CSR + self-signed root                                                                                                          |
| `util.go`       | `Issuer.GenCert`: key, CSR, sign, write files (existing files renamed `.bak`)                                                                    |
| `README.md`     | Configuration and signing flow diagrams, per-extension source table (profile / SignRequest / CSR), validity envelope                            |

### Config

See README for a sample. Key rules: profile name = `SignRequest.Profile`
(`default` if empty); `issuer_label: "*"` profiles are wildcard. A populated
issuer `allowed_profiles` restricts the issuer to the listed profiles, named and
wildcard alike; empty keeps named profiles and no wildcard ones; a populated
list must include the issuer's `delegated_ocsp_profile` (`issuerHasProfile`,
XPKI-057). `expiry`/`backdate` are `csr.Duration`; `usages` names come
from `oid.KeyUsage`/`oid.ExtKeyUsage`; `allowed_extensions` empty allows every
`SignRequest` extension but no CSR extension (`IsAllowedExtention` vs.
`allowsCSRExtension`, XPKI-049); `allowed_fields` nil means copy the subject and
all SAN fields from the CSR (never its extensions); `extensions` values accept
`hex:`, `base64:` or bare, and `Validate` rejects repeated OIDs and OIDs that
collide with `policies`/`ocsp_no_check` (XPKI-050). `IssuerConfig.Type` has
no yaml tag (XPKI-058). AIA `crl_expiry`, `ocsp_expiry`, `crl_renewal` are
`time.Duration` with defaults applied through the `Get*` accessors.

### Field ownership in `Issuer.Sign`

- Profile: key usages, CA constraints, SKI, AIA/OCSP/CRL URLs (`${ISSUER_ID}`
  or `:ISSUER_ID` → issuer SKID), policies, OCSP no-check, `extensions`,
  expiry and backdate (NotBefore = now rounded to a minute minus backdate,
  default 5m; NotAfter = NotBefore + expiry, capped at the issuer NotAfter;
  `validityWindow`).
- `SignRequest` (trusted RA): `Subject` merge, `SAN` (non-nil replaces CSR
  SANs), `Extensions` (subject to `allowed_extensions`, empty = all, and may
  include profile-owned OIDs such as a critical EKU; with
  `omit_disabled_extensions` disallowed ones are dropped, otherwise rejected),
  `NotBefore`/`NotAfter` (bounded: NotBefore ≥ now − backdate, NotAfter >
  NotBefore, lifetime ≤ expiry; rejected otherwise, XPKI-054), `Profile`.
- CSR (untrusted): subject/SANs per `allowed_fields`, public key, and only
  extensions listed in `allowed_extensions` (empty = none; disallowed ones
  follow `omit_disabled_extensions`). `csrDeniedExtensions` (SKI, KU, SAN,
  BasicConstraints, AKI, EKU, OCSP no-check) are always dropped; an AIA or
  CRL DP is dropped when the issuer generates one (XPKI-049).
- One extension per OID (XPKI-050). Raw extensions are kept in the order
  profile `extensions` > `SignRequest` > CSR (first per OID wins); a repeated
  profile OID fails `Sign`. Profile `policies`/`ocsp_no_check` then replace
  any raw copy (`setExtension`). For KU, EKU, basic constraints, SKI/AKI, SAN,
  AIA and CRL DP, a kept raw profile or `SignRequest` extension overrides the
  template-built value in `x509.CreateCertificate`; the CSR cannot supply
  these, except an AIA/CRL DP the issuer does not generate.

### Invariants

- `Issuer.lock` guards profiles and the delegated responder only;
  `Authority` has no locks (XPKI-055). Delegated OCSP path deadlocks (XPKI-051).
- Profiles must be `Validate()`d before use (compiles regexes; `LoadConfig` does).
- `Copy()` methods are shallow for `*CertProfile`.
- Metrics: `metricskey.PerfCAOperation`, `PerfCASignRequest`.

Tests: `authority_test.go` (suite) generates a 3-level chain with `testca`
into `/tmp/xpki/certs/*` referenced by `testdata/ca-config.dev.yaml`, and
registers `crypto11` and `awskmscrypto` (needs SoftHSM + local-kms).
`testdata/invalid_*.json` drive validation errors; `testdata/csrprofiles/*.yaml`
are used by `cmd/hsm-tool` tests (lowercase `names` keys, see csr invariants).
`ocsp_coverage_test.go` verifies direct responses and cached delegated responders
with fresh `testca` certificates; fresh delegated creation remains blocked by
XPKI-051. `issuer_coverage_test.go` exercises proof signatures, extension
policies, and internal template validation. `issuer_policy_test.go` covers the
AU1 issuance policy with hostile signed CSRs (profile-owned OIDs, SAN bypass,
allow-list/omit matrix, issuer-generated CRL DP), extension precedence, and
`validityWindow` against a fixed clock. `config_test.go` has the
`allowed_profiles` named/wildcard × nil/empty/populated matrix.

## Package certutil

Certificate, PEM, key and chain helpers plus a CFSSL-derived bundler.

### Files

| File            | Role                                                                                                                                                            |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pem.go`        | Parse/encode certificates, public and private keys (PKCS#8 → PKCS#1 → SEC1; RSA/ECDSA/Ed25519 parse, RSA/ECDSA encode; legacy `Proc-Type: 4,ENCRYPTED` decrypt) |
| `bundler.go`    | `Bundler`, options (`WithKeyUsages`, `WithBundleFlavor`, `WithAIA`, `WithHTTPClient`), `Chain`, `Bundle()`, AIA fetch, expiry checks, `IntermediateStash`       |
| `bundle.go`     | `Bundle`/`BundleStatus`, `VerifyBundleFromPEM`, `LoadAndVerifyBundleFromPEM`, `BuildBundle`, `FindIssuer`, `SortBundlesByExpiration`                            |
| `hash.go`       | Hash name maps, `Digest`, `SHA1*`, `SHA256*`, `HashToHex/Base64URL`, `ParseHexDigestWithPrefix`                                                                 |
| `cert_id.go`    | `GetThumbprintStr` (SHA-1 of DER), `GetSubjectKeyID`, `GetAuthorityKeyID`, `GetSubjectID`, `GetIssuerID`                                                        |
| `keyinfo.go`    | `KeyInfo`, `NewKeyInfo` (RSA/ECDSA from signer, decrypter or JWK)                                                                                               |
| `name.go`       | `NameToString` (OpenSSL-style DN)                                                                                                                               |
| `ocsp.go`       | `CreateOCSPRequest`                                                                                                                                             |
| `extensions.go` | `FindExtension*`, `IsOCSPSigner`, `HasOCSPNoCheck`                                                                                                              |
| `random.go`     | `RandReader`, `Random`, `RandomString` (panic on RNG failure)                                                                                                   |

### Invariants

- Chain building: `certs[0]` is the leaf; `Force` only checks each cert is
  signed by the next; `Optimal` runs `x509.Verify` against `RootPool` and
  `IntermediatePool`, fetches AIA intermediates on unknown authority when
  `WithAIA(true)`, ranks chains shortest-then-longest-expiring, and strips the
  root unless the leaf has OCSP servers and the chain is ≤ 2. "Expiring" is
  less than 720h left. Nil roots make `NewBundler` force the `Force` flavor.
- `Bundler` is not goroutine-safe (XPKI-035). `Bundle` of an empty list returns
  `(nil, nil)` (XPKI-036). Only RSA/ECDSA leaf keys accepted.
- Process-global: `IntermediateStash` (fetched intermediates written `0644`),
  `HTTPClient` (unused, XPKI-044), `RandReader`. Default AIA client timeout 3s.
- `ParseChainFromPEM` returns the parsed prefix and an error on trailing garbage.

Tests: `testdata/` holds a Mozilla root bundle, 229 intermediates, test server
chain and hash fixtures; `TestKeyInfoKMS` needs local-kms.
`bundler_coverage_test.go` uses fresh `testca` chains, temporary files and local
HTTP servers for AIA fetching, caching, validation, and expiry behavior; it
restores `IntermediateStash` and runs serially. `bundler_ranking_test.go` tests
internal chain selection. `pem_coverage_test.go` covers malformed encodings
and file errors without adding private-key fixtures.

## Package jwt

Self-contained JWS/JWT: HS256/384/512, RS256/384/512, ES256/384/512.

### Files

| File        | Role                                                                                                                                                                                    |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `token.go`  | `Token`, `VerifyConfig`, `ValidClaims`, `DecodeSegment`/`EncodeSegment`                                                                                                                 |
| `jwt.go`    | Interfaces, `ProviderConfig`, `LoadProvider`, `NewProvider`, `MustNewProvider`, `NewProviderFromCryptoSigner`, `NewProviderWithSymmetricKey`, `WithHeaders`, `provider.Sign/ParseToken` |
| `sign.go`   | `SignerInfo`, alg selection from key, HMAC signer (constant-time verify), `VerifySignature`                                                                                             |
| `parser.go` | `TokenParser` (`Parse`, `ParseWithClaims`, `ParseUnverified`), `ParserConfig`, `NewParser` (JWKS-backed)                                                                                |
| `claims.go` | `Claims`, `MapClaims` getters/validation, `NumericDate`, `Audience`, `CreateClaims`, `TimeNowFn`, `DefaultTimeSkew`                                                                     |
| `jwks.go`   | `KeySet`, `StaticKeySet`, `RemoteKeySet` (lazy fetch, inflight coalescing)                                                                                                              |

### Invariants

- Alg from key: RSA ≥4096 → RS512, ≥3072 → RS384, else RS256; P-521 → ES512,
  P-384 → ES384, else ES256. HS256 key ring: seeds are SHA-256'd, `kid` header
  set; `NewProvider` errors if `kid` is not in `keys`.
- Default expiry 60m, `DefaultNotBefore` −2m, `DefaultTimeSkew` 5m on
  `iat`/`nbf` only. `ExpectedAudience` means all listed values present.
  Issuer/subject compared case-insensitively.
- `provider.ParseToken` requires `kid` for HS tokens; `parser.ParseToken`
  refuses HS. `alg: none` is rejected. Numeric `kid` headers are stringified.
- `RemoteKeySet` refreshes only on unknown `kid`, uses `http.DefaultClient`
  without timeout (XPKI-070). `ParseWithClaims` verifies the signature before
  validating claims. `MapClaims.Int/Int64/UInt64` return 0 (DEBUG log) on
  overflow, negative-to-unsigned, or parse failure. `NumericDate` and
  `MapClaims.Time` accept fractional seconds and truncate to whole seconds
  with exact arithmetic (`parseNumericDate`), so a fractional `exp` is
  still validated.
- `MustNewProvider` panics; `TimeNowFn` is a mutable global used by tests.
- go-jose v4 is used only for `JSONWebKey`/`JSONWebKeySet` types.

Tests: `testdata/jwtprov*`, `oidc_parser*` (Google/Cognito JWKS snapshots),
embedded real ID tokens; `Test_SignPrivateKMS` needs local-kms on `:14555`.
`parser_coverage_test.go` covers configuration files, malformed tokens, real
symmetric/asymmetric signing, key-ID types, and claim conversions. It
characterizes XPKI-066 and the `WithHeaders` panic in XPKI-104.

## Packages jwt/dpop, jwt/accesstoken, jwt/oauth2client, dataprotection

- **dpop**: `dpop.go` constants (`HTTPHeader`, `DefaultExpiration` 10m,
  `CnfThumbprint`), `keys.go` P-256 JWK generate/load/save (`<folder>/<thumbprint>.jwk`,
  0600), `signer.go` proof signer (`typ: dpop+jwt`, `jwk` header), `verify.go`
  rules: compact proofs decode the protected header first (so a private `jwk`
  or HMAC `alg` is a DPoP error, not a go-jose parse error); JSON JWS is
  parsed so more than one signature is `token contains multiple headers`;
  then `typ`, public `jwk`, alg in the asymmetric allow-list, `jti`/`htm`/`htu`/`iat`
  present, `iat` within 10m, signature verified with the embedded JWK,
  optional iss/sub/aud/nonce. No replay cache or `ath` (XPKI-075); PS\*/EdDSA
  in the allow-list do not verify (XPKI-074). Binding to the access token:
  compare `Result.Thumbprint` with the `cnf.jkt` claim.
- **accesstoken**: `pat.<base64url(AES-GCM(json claims))>`; non-`pat.` tokens
  delegate to the inner `jwt.Provider`. No `exp` is added (XPKI-078);
  `SetRevocation` is forwarded to the inner provider.
- **oauth2client**: `config.go` `Config`/`ClientConfig` (`env://` values via
  `x/configloader`), `client.go` `Client`, `CreateTokenRequest[WithContext]`,
  `provider.go` registry lookups by provider id, email, domain
  (`ClientForEmail` returns nil unless the value is `local@domain`). Registry
  mutation is not goroutine-safe (XPKI-081).
- **dataprotection**: `Provider` interface; `NewSymmetric(secret)` = HKDF-SHA256
  → AES-256-GCM, blob `nonce(12) || ciphertext || tag`, no key id (XPKI-083).

Tests are pure except `keys_test.go` writing under `os.TempDir()`.
`oauth2client/request_coverage_test.go` checks token-request authentication,
context cancellation, preservation of caller-owned form values, and registry
conflicts/overrides; it makes no network requests.

## Helper packages

- **armor**: `Decode` only; CRC24 required (XPKI-047); returns nil on malformed input, never panics. `testdata/` GPG keys incl. corrupted variants.
- **oid**: exported maps are process-global; `KeyUsages` returns canonical names in RFC 5280 bit order, each bit once.
- **x/print**: writes to an `io.Writer`, ignores write errors, local time; a zero `NextUpdate` prints `Expires: not set`; `JSON` swallows marshal errors by design. Tests in `certutil_test.go` load `testdata/*.pem` and append synthetic `*x509.Certificate` values to cover SAN, AIA, CRL, and extension formatting.
- **metricskey**: descriptors only; registered by consumers.
- **internal/version**: `current.go` is generated by `make version` but tracked (XPKI-097); `PopulateFromBuild` strips a leading `v`.
- **testca**: everything panics on failure (test-only). Defaults RSA-2048,
  NotBefore = epoch, NotAfter = +10y, subject `[TEST]`. `Chain()` includes
  leaf and root. `PFX`/`ToPKCS8` need `openssl` (XPKI-063).
  Default common-name allocation uses an atomic counter; a per-entity mutex
  protects `IncrementSN`'s return-and-increment of `NextSN` (XPKI-062, fixed).
  Key generation and signing run outside that mutex. `Issue` copies the
  caller's options before adding its issuer, which retains precedence over
  supplied `Issuer` options (XPKI-107, fixed). Concurrent calls require
  immutable package defaults, entity fields and option data, plus a signer
  that supports concurrent use. Direct `NextSN` access requires no issuance
  or `IncrementSN` calls in flight; do not copy an `Entity` after first use.
  `concurrency_test.go` uses synchronized workers to verify unique default
  names, complete serial sequences from zero and configured starting values,
  signed certificates from a shared issuer, and option-slice preservation.

## CLIs

- **hsm-tool** (`cmd/hsm-tool`): `--cfg` provider config (or `inmem`/`plain`),
  `--crypto` extra providers, `--plain-key`, `-D`, `-l`. Commands: `hsm list`,
  `hsm info <id>`, `hsm generate`, `hsm remove <id>`, `csr create`,
  `csr gen-cert`, `csr sign <csr>`. `hsm list/info/remove` select a token by
  `--serial` or `--token` label (`tokenFilter`); `info` and `remove` fail with
  `token not found` when a filter matches nothing. Output is JSON on stdout (`print.CertAndKey`);
  `--output PREFIX` writes `.pem/.csr/.key` (`.key` is 0600). Providers are
  blank-imported in `cli/cli.go` and loaded lazily by `CryptoProv()`.
- **xpki-tool** (`cmd/xpki-tool`): `--timeout` seconds for HTTP. Commands:
  `csr-info`, `cert info`, `cert validate` (`--ca`, `--root`, `--revocation`,
  `--with-aia`), `crl info`, `crl fetch` (needs `--output` or `--print`;
  errors when no selected certificate has a CRL distribution point),
  `ocsp info` (`--issuer` PEM verifies the response signature), `ocsp fetch`
  (error when the certificate has no OCSP URL). HTTP helpers take the CLI
  context; output paths use `filepath.Join`.
- Exit codes: kong parse error → 80; `Run` error → 1; panic → 2. `-` as a
  file name reads stdin.
- Tests: `cmd/hsm-tool/cli` uses testify mocks for providers, plus `csr_test.go`
  which needs local-kms and `authority/testdata`; `cmd/xpki-tool/cli` uses
  `x/print/testdata` and `cli/testdata/ocsp1.res`, no network.
- Both READMEs are generated from `--help` output; regenerate them when flags change.

## Test layout summary

| Fixture                                                                                          | Provided by                                    | Needed by                                                                                             |
| ------------------------------------------------------------------------------------------------ | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `/tmp/xpki/softhsm_unittest.json`, token `xpki_unittest`, PIN `~/softhsm2/xpki_pin_unittest.txt` | `make hsmconfig` (`scripts/config-softhsm.sh`) | `crypto11`, `cryptoprov`, `csr`, `authority`                                                          |
| `local-kms` on `:14555` and `:14556`                                                             | `make start-local-kms` (`docker-compose.yml`)  | `awskmscrypto`, `authority`, `jwt`, `certutil` (`TestKeyInfoKMS`), `cmd/hsm-tool/cli` (`csr_test.go`) |
| `AWS_ACCESS_KEY_ID` etc. dummy values                                                            | `Makefile` exports                             | AWS SDK                                                                                               |
| `/tmp/xpki/certs/*`                                                                              | `authority_test.go` via `testca`               | `authority/testdata/ca-config.dev.yaml`                                                               |

No integration test skips when its fixture is missing (XPKI-100).

`cmd/xpki-tool/cli/coverage_test.go` uses generated certificates and local HTTP
servers to cover certificate filters, trust validation, concurrent revocation
checks, CRL/OCSP fetch and inspection, and input/transport errors. It
characterizes OCSP fetch success after endpoint failures (XPKI-102) and nil
issuer panics (XPKI-103). Fixtures use `t.TempDir()`. In
`cmd/xpki-tool/cli/suite_test.go`, `testSuite.SetupSuite` allocates a unique
directory on the suite's parent test; Go removes it after all suite subtests
finish. Overlapping CLI test processes cannot overwrite or remove one
another's fixtures (XPKI-105, fixed); give each process separate coverage
and log output paths.

## SoftHSM setup scripts

- `scripts/config-softhsm.sh` validates flags and tools and propagates command
  failures. `softhsm2-util` is required; `pkcs11-tool` is required only for
  `--list-slots`/`--list-object`. `--module` overrides discovery; Linux probes
  standard library directories, and macOS uses `brew --prefix softhsm`.
- New configs use the selected `--tokens-dir`; `--cfg-dir` selects the exported
  `SOFTHSM2_CONF` for all child tools. Existing `softhsm2.conf` files are kept;
  `--force` resets token storage and this config file, preserving other files
  in the config directory. Token labels are matched literally, not as regexps.
- Explicit `--pin` takes precedence over `--pin-file`. PIN files have trailing
  CR/LF stripped; other whitespace is preserved. `--generate-pin` uses
  `openssl rand -hex 16` only if no nonempty PIN is available, and requires
  `--pin-file` or `--out-cfg` so the PIN is retained. PIN files and output JSON
  are mode 0600, including pre-existing files; neither PINs nor JSON contents
  are printed. JSON strings are escaped.
- `scripts/config-softhsm_test.sh` runs isolated temporary-directory/stub-tool
  regression checks via `make test-scripts`. `make hsmconfig` runs them before
  creating the standard integration fixture, so the CI Prepare step executes
  them. The shell tests need Bash and ordinary Unix utilities, with no HSM,
  OpenSC, Homebrew, Python, or network dependency.
- `make hsmconfig` builds `bin/hsm-tool` before changing the fixture, uses
  `softhsm2-util` for token deletion/initialization, then runs `hsm list` with
  the generated JSON and the same `SOFTHSM2_CONF` as the setup script. This
  verifies provider loading, PIN login and token/key enumeration through our
  CLI; it requires Go/cgo but no OpenSC. The CLI manages keys, not token
  initialization or deletion. The script's OpenSC listing flags remain opt-in.

## Build and CI

- `make tools` installs golangci-lint v2, cov-report, govulncheck (`@latest`,
  XPKI-096). `make build` → `bin/hsm-tool`, `bin/xpki-tool`. `make test`,
  `make testshort`, `make test RACE=true`, `make covtest coverage`
  (per-package `-coverpkg=./...` merged by cov-report; exclusions in
  `.project/gomod-project.mk`). `make lint` = gofmt + vet + `golangci-lint run`.
  `make version` regenerates `internal/version/current.go` (not wired into
  `build`, XPKI-097). `make docs` runs gomarkdoc for `crypto11`, `cryptoprov`,
  `testca` into `Documentation/` and dumps `bin/*-tool --help` into
  `Documentation/cli/` (run `make build` first; the `cli/` directory must exist). `make all` = clean, tools, generate, change_log,
  start-local-kms, hsmconfig, covtest.
- `.golangci.yaml`: v2, default linters plus `revive` `exported`; `_test.go`
  excluded. `golangci-lint run` must stay clean (staticcheck SA1019 catches
  deprecated calls).
- CI `.github/workflows/unittest.yml`: on push to `main`/`release-*`/tags and
  PRs: `make tools`, `apt-get install softhsm2`, `make vars generate
hsmconfig start-local-kms`, `make covtest`; PR status "code cov" against
  `MIN_TESTCOV=80`. Lint and vulns are not run (XPKI-095). On push to `main`
  with a changed `.VERSION`, a tag `$(cat .VERSION).$(git rev-list --count HEAD)`
  is created (`settag.yml` does the same on demand).
