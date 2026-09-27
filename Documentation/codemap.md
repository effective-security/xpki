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
| `internal/testenv/`                                              | Test-only gate for external fixtures (`XPKI_INTEGRATION`)               |
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
| Multi-provider registry                    | `cryptoprov/provider.go`, `crypto_concurrency_test.go`                       | `Crypto`, `New`, `Add`, `ByManufacturer`, `Default`, `ErrNilProvider`, `ErrDuplicateProvider`                                 |
| Token config file (JSON/YAML, `file:` PIN) | `cryptoprov/config.go`, `crypto11/config.go`                                 | `LoadTokenConfig`, `TokenConfig`                                                                                              |
| PKCS#11 key URI                            | `cryptoprov/uri.go`                                                          | `ParseTokenURI`, `ParsePrivateKeyURI`, `PrivateKeyURI`                                                                        |
| Load key from PEM or URI                   | `cryptoprov/utils.go`, `cryptoprov/signer.go`                                | `Crypto.LoadPrivateKey`, `NewSignerFromPEM`, `NewSignerFromFromFile`, `LoadTLSKeyPair`                                        |
| AES-GCM helpers                            | `cryptoprov/gcm.go`                                                          | `GcmEncrypt`, `GcmDecrypt`                                                                                                    |
| PKCS#11 init / token select / login        | `crypto11/config.go`                                                         | `Init`, `selectToken`, `ConfigureFromFile`, `LoadTokenConfig`, `WithMaxSessions`, `DefaultMaxSessions`                        |
| PKCS#11 module sharing / finalize          | `crypto11/module.go`, `crypto11/crypto11.go`                                 | `openModule`, `module.release`, `PKCS11Lib.Close`                                                                             |
| PKCS#11 session pool                       | `crypto11/sessions.go`                                                       | `withSession`, `sessionPool`, `sessionUnusable`, `NewSession`                                                                 |
| PKCS#11 key generation / lookup            | `crypto11/keys.go`, `rsa.go`, `ecdsa.go`                                     | `GenerateRSAKey`, `GenerateECDSAKey`, `FindKeyPair*`, `GetKey`, `ExportKey`                                                   |
| PKCS#11 signing / decryption               | `crypto11/rsa.go`, `crypto11/ecdsa.go`                                       | `PKCS11PrivateKeyRSA.Sign/Decrypt`, `PKCS11PrivateKeyECDSA.Sign`                                                              |
| PKCS#11 token / key enumeration            | `crypto11/provider.go`, `crypto11/util.go`                                   | `EnumTokens`, `EnumKeys`, `KeyInfo`, `DestroyKeyPairOnSlot`                                                                   |
| AWS KMS                                    | `cryptoprov/awskmscrypto/awskmsprov.go`, `signer.go`                         | `Init`, `KmsLoader`, `KmsClientFactory`, `KmsClient`, `NewSigner`, `Signer.SigningAlgorithms`, `Provider.EnumKeys`           |
| GCP KMS                                    | `cryptoprov/gcpkmscrypto/gcpkmsprov.go`, `signer.go`                         | `Init`, `KmsLoader`, `KmsClientFactory` (takes the endpoint), `KmsClient`, `KeyLabelAndID`, `NewSigner`, `Signer.Algorithm`, `Crc32c`, `Provider.Close`, `ErrClosed` |
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
| OCSP responder renewal / locking           | `authority/ocsp.go` (`delegatedResponder`), `authority/issuer.go` (`Issuer`) | `caResponder`, `delegated`, `renewal` (`ocspRenewal`), `renewLock`, `renewWaitHook`, `validateDelegatedOCSPProfile`, `signWithProfile` |
| Certificate policies, SKI                  | `authority/extensions.go`                                                    | `addPolicies`, `CTPoisonOID`, `SCTListOID`                                                                                    |
| Root bootstrap / cert files                | `authority/root.go`, `authority/util.go`                                     | `NewRoot`, `Issuer.GenCert`                                                                                                   |
| PEM parse / encode                         | `certutil/pem.go`                                                            | `ParseFromPEM`, `ParseChainFromPEM`, `Load*FromPEM`, `EncodeToPEM*`, `ParsePrivateKeyPEM*`, `EncodePrivateKeyToPEM`           |
| Chain bundling / verification              | `certutil/bundler.go`, `certutil/bundle.go`                                  | `NewBundler*`, `LoadBundler`, `Bundler.Bundle`/`BundleContext`, `VerifyBundleFromPEM`, `LoadAndVerifyBundleFromPEM`, `Bundle`, `BundleStatus` |
| Hashes, thumbprints, IDs                   | `certutil/hash.go`, `certutil/cert_id.go`                                    | `Digest`, `SHA1*`, `SHA256*`, `NewHash`, `GetThumbprintStr`, `GetSubjectID`, `GetIssuerID`                                    |
| Key info (type, size, hash, JWK)           | `certutil/keyinfo.go`                                                        | `NewKeyInfo`, `KeyInfo`                                                                                                       |
| OCSP request, extensions                   | `certutil/ocsp.go`, `certutil/extensions.go`                                 | `CreateOCSPRequest`, `FindExtension`, `IsOCSPSigner`, `HasOCSPNoCheck`                                                        |
| Randomness                                 | `certutil/random.go`                                                         | `Random`, `RandomString`, `RandReader`                                                                                        |
| JWT provider (sign + verify)               | `jwt/jwt.go`                                                                 | `ProviderConfig`, `LoadProvider`, `NewProvider`, `NewProviderFromCryptoSigner`, `NewProviderWithSymmetricKey`, `WithHeaders`  |
| JWT signing internals                      | `jwt/sign.go`                                                                | `NewSignerInfo`, `VerifySignature`                                                                                            |
| JWT parsing (third-party tokens)           | `jwt/parser.go`                                                              | `ParserConfig`, `LoadParserConfig`, `NewParser`, `TokenParser`, `Keyfunc`                                                     |
| Claims                                     | `jwt/claims.go`                                                              | `Claims`, `MapClaims`, `NumericDate`, `Audience`, `CreateClaims`, `SetClaimsExpiration`, `TimeNowFn`                          |
| JWKS key sets                              | `jwt/jwks.go`                                                                | `KeySet`, `AlgorithmKeySet`, `StaticKeySet`, `RemoteKeySet`, `NewRemoteKeySet`, `WithHTTPClient`, `WithRefreshCooldown`       |
| DPoP proof create / verify                 | `jwt/dpop/signer.go`, `jwt/dpop/verify.go`                                   | `NewSigner`, `ForRequest`, `VerifyRequestClaims`, `VerifyClaims`, `VerifyClaimsContext`, `AccessTokenHash`, `GetTokenInfo` |
| DPoP replay cache (`jti`)                  | `jwt/dpop/replay.go`                                                         | `ReplayCache`, `NewMemoryReplayCache`, `ErrReplay`, `ErrReplayCacheFull`                                                      |
| DPoP `htu` request URI / normalization     | `jwt/dpop/htu.go`                                                            | `VerifyConfig.ExternalURL`, `requestURI`, `normalizeHTU`                                                                      |
| DPoP keys                                  | `jwt/dpop/keys.go`                                                           | `GenerateKey`, `LoadKey`, `SaveKey`, `Thumbprint`                                                                             |
| Opaque access tokens                       | `jwt/accesstoken/accesstoken.go`                                             | `New`, `Provider`, `WithTokenExpiry`, `WithAllowNoExpiry`, `TokenPrefix`                                                      |
| OAuth2 client registry                     | `jwt/oauth2client/*.go`                                                      | `LoadProvider`, `NewProvider`, `RegisterClient`, `ClientFor*`, `Client.CreateTokenRequest[WithContext]`                       |
| Data protection                            | `dataprotection/dp.go`, `symmetric.go`                                       | `Provider`, `NewSymmetric`, `ProtectObject`, `UnprotectObject`                                                                |
| Human-readable printing                    | `x/print/certutil.go`                                                        | `Certificate(s)`, `CertificateRequest`, `CertificateList`, `OCSPResponse`, `CertAndKey`, `JSON`                               |
| OID / usage names                          | `oid/oidinfo.go`                                                             | `KeyUsage*`, `ExtKeyUsage*`, `DisplayName`, `KeyUsages`, `ExtKeyUsages`, `Strings`                                            |
| ASCII armor decoding                       | `armor/armor.go`                                                             | `Decode`, `Block`                                                                                                             |
| Metrics descriptors                        | `metricskey/metricskey.go`                                                   | `PerfCryptoOperation`, `PerfCAOperation`, `PerfCASignRequest`, `Metrics`                                                      |
| Build version                              | `internal/version/*.go`                                                      | `Current`, `Info`, `PopulateFromBuild`                                                                                        |
| Integration fixture gating (tests)         | `internal/testenv/testenv.go`                                                | `RequireTCP`, `RequireFile`, `IntegrationRequired`, `IntegrationEnv`, `Required`                                              |
| SoftHSM fixture setup                      | `scripts/config-softhsm.sh`, `scripts/config-softhsm_test.sh`                | `make hsmconfig`, `make test-scripts`, setup `--help`                                                                         |
| Test CA fixtures                           | `testca/entity.go`, `configuration.go`, `mkcert.go`, `testca.go`, `utils.go` | `NewEntity`, options, `MakeSelfCert*`, `MakeValidCertsChainTSA`, `ToPEM`                                                      |
| Concurrent test CA names / serials         | `testca/configuration.go`, `entity.go`, `concurrency_test.go`                | `NewEntity`, `Entity.Issue`, `Entity.IncrementSN`, `NextSerialNumber`                                                         |
| CLI: HSM/KMS key management                | `cmd/hsm-tool/cli/hsm.go`, `csr.go`, `cli.go`                                | `Cli`, `HsmListCmd`… , `CsrCreateCmd`…                                                                                        |
| CLI: PKI inspection                        | `cmd/xpki-tool/cli/certs.go`, `crl.go`, `ocsp.go`, `csr.go`                  | `CertInfoCmd`, `CertValidateCmd`, `CRL*Cmd`, `OCSP*Cmd`, `OCSPValidation`, `CRLValidation`                                    |

## Package cryptoprov

Provider-agnostic key abstraction: `Provider` (generate/lookup/export keys +
`Manufacturer`/`Model`), `KeyManager` (enumerate tokens and keys, key info,
destroy), the `Crypto` registry keyed by manufacturer and model, the process-global
loader registry, token config loading, PKCS#11 URI parsing, PEM/DER key
parsing, TLS key-pair loading and AES-GCM helpers.

### Files

| File          | Role                                                                                                                        |
| ------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `provider.go` | Interfaces, `KeyInfo`/`TokenInfo`, `Crypto` (`New`, `Add`, `ByManufacturer`), `ErrNilProvider`, `ErrDuplicateProvider`      |
| `loader.go`   | `loaders` map + `lockLoaders`; `Register`, `Unregister`, `Registered`, `LoadProvider`, `Load` (closes loaded providers on error) |
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
- `Crypto` is safe for concurrent use (XPKI-016): `Add` is serialized by a
  mutex and publishes a new copy of the `providerKey{manufacturer, model}`
  map through an `atomic.Pointer`; `ByManufacturer` does not lock. The
  default provider's key is memoized in `New` and checked first. The zero
  value works (no default).
- Duplicates: re-adding the same instance, including the default, is a
  no-op when its dynamic value is comparable (pointers; every provider in
  this module). Instances are compared with `reflect`, never panicking; a
  non-comparable value (a struct holding a map/slice/func) can not be
  matched, so re-adding it is `ErrDuplicateProvider`. A different instance with a registered or the default key returns wrapped
  `ErrDuplicateProvider`, so `Load` fails when two configs share
  manufacturer and model. `New(nil, …)`, a nil entry in `New`'s list and
  `Add(nil)` return wrapped `ErrNilProvider`; typed nils (nil pointer, map,
  func, …) count as nil (XPKI-026). Sentinels are wrapped with
  `errors.Wrap(f)`, so stdlib and cockroachdb `errors.Is` both match.
- `Load` does not add the default provider to the map (`ByManufacturer`
  checks the default first), so a non-comparable default loads (XPKI-113).
  It closes the providers it already loaded (those with `Close() error`)
  when it returns an error.
- `file:` PIN content has trailing `\r`/`\n` stripped; other whitespace is part of the PIN.
- `ParsePrivateKeyDER` accepts PKCS#8 (RSA, ECDSA, Ed25519), PKCS#1 and SEC1;
  the parse error from each attempt is preserved (`errors.Join`) under
  `failed to parse key`.
- `TLSKeyPair`/`LoadTLSKeyPair` set `Certificate.Leaf` and return an error
  when the private key's public half does not `Equal` the leaf's public key.
- Errors are `cockroachdb/errors`; sentinels `ErrInvalidURI`, `ErrInvalidPrivateKeyURI`.

### Test layout

Only `Test_LoadConfig`, `Test_Load`, `Test_P11` and `Test_LoadSigner_P11`
need SoftHSM at `/tmp/xpki/softhsm_unittest.json` (`make hsmconfig`); they
call `requireSoftHSM` (`testenv.RequireFile`, XPKI-100), and
`loadP11Provider` closes the library at cleanup. Everything else is
fixture-free with `inmemcrypto`/`testprov`. `crypto_test.go` covers the
`Crypto` nil/duplicate contract, and registers a throwaway loader
(`cryptoprov-test-closer`, unregistered at cleanup) for `LoadProvider` and
`Load` close-on-error tests; no test unregisters a built-in loader.
`TestLoad_KMSProviders` loads the self-registered AWS (lazy client) and GCP
(stubbed `KmsClientFactory`, restored at cleanup) loaders without KMS
(XPKI-099). `crypto_concurrency_test.go` has the Add/lookup race test and
`BenchmarkByManufacturer`/`BenchmarkByManufacturerWithAdd`. `testdata/`
holds `inmem_testprov.{json,yaml}`, `inmem_pin.txt`, `test-{cert,key}.pem`.

## Package crypto11

PKCS#11 wrapper over `github.com/miekg/pkcs11` exposing HSM-resident RSA and
ECDSA keys as `crypto.Signer`/`crypto.Decrypter`, with a per-slot session pool,
key generation/lookup/destroy, token enumeration and HSM randomness. Requires a
C toolchain (cgo) and dlopens the module named in the config.

### Files

| File          | Role                                                                                                                                               |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `doc.go`      | Package comment                                                                                                                                    |
| `crypto11.go` | Sentinel errors (`errClosed` after Close), `PKCS11Lib`, `PKCS11Object`, `PKCS11PrivateKey`, `Close() error`                                        |
| `config.go`   | `TokenConfig`, `Init` (module ref, `selectToken` by every configured serial/label, login session, unwind on error), `Option`/`WithMaxSessions`, `ConfigureFromFile`, `LoadTokenConfig` |
| `module.go`   | Process-wide module registry matched by loader handle, else `moduleID`: `openModule`, `module.release` (last ref finalizes and unloads)          |
| `module_dl_unix.go`, `module_dl_other.go` | `loadedHandle` (cgo `dlopen`/`dlclose`, `-ldl` on Linux); 0 on non-unix                                                   |
| `sessions.go` | `sessionPool` (bounded per slot), `withSession`, `NewSession`, lifecycle guard (`acquirePool`/`enter`/`exit`), `sessionOps` test seam              |
| `provider.go` | `cryptoprov` glue: `init()` registration, `LoadProvider`, `EnumTokens`, `EnumKeys`, `KeyInfo`                                                      |
| `keys.go`     | `KeyPurpose`, `findKey`, `ListKeys`, `FindKeyPair*`, `ConvertToPublic`, `GetKey`, `ExportKey`, `GenerateRSAKey`, `GenerateECDSAKey`, `IdentifyKey` |
| `rsa.go`      | `PKCS11PrivateKeyRSA`: generate, `Sign` (PKCS#1 v1.5, PSS), `Decrypt` (PKCS#1 v1.5, OAEP), `Validate`                                              |
| `ecdsa.go`    | `PKCS11PrivateKeyECDSA`: curve table (P-224/256/384/521), generate, `Sign` (DER r,s)                                                               |
| `common.go`   | Attribute/class/type name maps, CK_ULONG codec (`ulongSize`, checked `bytesToUlong`, `keyTypeAndClass`, deprecated `BytesToUlong`, `UlongToBytes`), ECDSA signature DER helpers, label/ID generation on the held session |
| `util.go`     | `CurrentSlotID`, `TokensInfo`, `DestroyKeyPairOnSlot`, `getPublicKeyPEM` (on a given session)                                                      |
| `rand.go`     | `GenRandom`                                                                                                                                        |

### Invariants

- Module ownership (XPKI-001/007): every `PKCS11Lib` on one library file
  shares one `*pkcs11.Ctx` from the `modules` registry (`modulesMu`). On unix
  a module is identified by the dynamic loader handle (`loadedHandle` in
  `module_dl_unix.go`, `dlopen(RTLD_NOLOAD)` after `pkcs11.New`), so a bare
  name found on the search path, a path, a symlink and a hardlink to one
  loaded library share it; a duplicate load only drops its extra loader
  reference. Elsewhere (`module_dl_other.go`) `moduleID` matches paths by
  `os.SameFile` and bare names by name. The first reference runs `C_Initialize`; the last `Close`
  runs `C_Finalize` and then `Destroy`. If `C_Initialize` returned
  `CKR_CRYPTOKI_ALREADY_INITIALIZED` (initialized outside this package), the
  module is shared but never finalized here. `Init` releases its reference and
  sessions on every error after the load.
- Each `PKCS11Lib` owns a login session (`Session`, opened and logged in by
  `Init`) that keeps the token logged in while pooled sessions come and go; it
  is closed by `Close` and not counted in the pool limit. No `C_Logout`; it is
  not reopened after a device/token error (XPKI-110).
- Session pools (XPKI-002/003/005): one `sessionPool` per slot, created on
  first use under `PKCS11Lib.mu`. At most `maxSessions` live sessions per slot
  (default `DefaultMaxSessions` = 1024, `WithMaxSessions`); a borrower waits
  (`sync.Cond`, no FIFO) for a returned session. Returns never block. A
  session whose callback failed with `sessionUnusable` codes
  (`CKR_SESSION_HANDLE_INVALID`, `CKR_SESSION_CLOSED`, `CKR_OPERATION_ACTIVE`,
  device/token removed or error) or panicked is closed, not reused; it keeps
  its capacity until `CloseSession` returns (a failed close releases it).
  `Init` rejects a nil `Option`.
  `withSession` callbacks must not borrow again (key-label/ID randomness uses
  the held session). Sign/Decrypt use the slot recorded on the key object
  (`PKCS11Object.Slot`), so keys found on other slots work.
- `Close() error` runs once (`closeOnce`); every call, concurrent or later,
  waits for it and returns the same result. New and queued operations get
  `errClosed`; it waits for borrowed sessions (in-flight operations) to
  return, closes all sessions of this `PKCS11Lib` (joining close errors,
  including sessions returned during `Close`), releases the module and sets
  `Ctx` to nil. Every method that touches `Ctx` goes through `withSession` or
  `enter`/`exit`, including `ExportKey` (lookup and token info in one pooled
  operation, never a nested guarded call), `EnumTokens(true)` and the public
  caller-session methods (`ListKeys`, `FindKeys`, `FindKeyPairOnSession`,
  `Generate{RSA,ECDSA}KeyPairOnSession`), which wrap unexported versions used
  inside pooled operations. `EnumKeys` keeps its own read-only session, so
  write-protected tokens list. Direct use of the exported `Ctx` and caller
  sessions from `NewSession` are untracked; close them before `Close`, and do
  not call `Close` from inside an operation.
- Token selection (XPKI-006, `selectToken`): a token must match every
  nonempty configured field (serial AND label when both are set); empty fields
  are ignored, never matched against empty token fields. `Init` returns
  `errNoTokenSelector` before loading the module when both are empty, and
  `errTokenNotFound` when nothing matches; among several matches the first
  slot wins. `Pin` may be `file:<path>` (trailing line endings stripped,
  other whitespace kept).
- CK_ULONG attributes (XPKI-011): values are exactly `ulongSize` bytes
  (`C.sizeof_ulong`: 8 on LP64 unix, 4 on Windows/32-bit) in host byte order,
  decoded with `encoding/binary.NativeEndian`, no `unsafe`. Internal readers
  (`EnumKeys`, `KeyInfo`, `FindKeyPair`/`FindKeyPairOnSession`)
  use `bytesToUlong` and return `errMalformedUlong` for any other length. The
  deprecated exported `BytesToUlong` returns `CK_UNAVAILABLE_INFORMATION`
  (`^uint(0)`) instead of panicking.
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
- Panics: `mustMarshal` at init,
  RSA `Sign(nil opts)` (same as stdlib). Everything else returns wrapped errors.

### Test layout

`TestMain` loads `/tmp/xpki/softhsm_unittest.json` only when the file exists
and closes `p11lib` (checking the error) before `os.Exit`. SoftHSM tests call
`requireP11`, which uses `testenv.RequireFile` (missing config skips, or fails
with `XPKI_INTEGRATION=required`) and fails when a present config did not load.
Fixture-free: `sessions_test.go` (pool bounds, disposal, panic, open errors,
Close waiting/wakeups, concurrent pool creation vs Close) through the
`sessionOps` seam, config/DSA tests; `close_test.go` (errClosed from the
caller-session methods, concurrent `Close` sharing its result, errors from
sessions returned during `Close`, `moduleID` matching, and `ExportKey` with a
`Close` injected through the `exportKeyAdmitted` hook; symlinked module sharing
on SoftHSM). `TestLifecycle_BareNameAlias` re-executes a child with
`LD_LIBRARY_PATH`/`DYLD_LIBRARY_PATH` so a bare name and a path share a module. `lifecycle_test.go` covers shared-module
refs, closing with live and active sessions (SoftHSM handle probes via
`GetSessionInfo`), Init failure unwinding, and re-executes the test binary
(`XPKI_CRYPTO11_CHILD`) to prove `C_Finalize` ran (a fresh `C_Initialize`
succeeds) after failed Inits and the last Close, and that an externally
initialized module is not finalized. `sessions_bench_test.go` holds the
session/lifecycle benchmarks (`BenchmarkSession_Saturation` with
`-benchtime=1x`). No `testdata/`. Keys generated by tests persist in the
token unless the test destroys them.

## Packages cryptoprov/awskmscrypto, gcpkmscrypto, inmemcrypto, testprov

| Package        | Manufacturer | Key material                                        | `ExportKey` returns                | Config `Attributes`                                                                  |
| -------------- | ------------ | --------------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------ |
| `awskmscrypto` | `AWSKMS`     | KMS RSA 2048/3072/4096, P-256/384/521 sign keys     | `pkcs11:` URI (serial = ARN)       | `Endpoint=<url>,Region=<r>` (both optional)                                          |
| `gcpkmscrypto` | `GCPKMS`     | Cloud KMS HSM-level RSA 2048/3072/4096, P-256/384 signing keys | `pkcs11:` URI (`id` = `K/cryptoKeyVersions/N`, serial = 1) | `Keyring=projects/P/locations/L/keyRings/R` (required), `Endpoint=host:port` (optional) |
| `inmemcrypto`  | `inmem`      | In-process RSA/ECDSA                                | PKCS#1 / SEC1 PEM bytes            | none                                                                                 |
| `testprov`     | `testprov`   | In-process RSA/ECDSA, implements `crypto.Decrypter` | `pkcs11:` URI with `token=<label>` | none                                                                                 |

Invariants: KMS providers call the SDKs with `context.Background()` (ROADMAP);
`KmsClientFactory` package vars are the test seams (the GCP one takes the
`Endpoint` attribute, applied with `option.WithEndpoint`, XPKI-021); GCP
`Close` must be called to release gRPC.
AWS credentials, the default region and retries come from the SDK default
chain (`config.LoadDefaultConfig`), which reads `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` before the shared config;
`Init` no longer copies them into a static provider (XPKI-034: it was
redundant, and static environment credentials are not refreshable either
way). The `Region` attribute overrides the SDK region; `Endpoint` sets
`BaseEndpoint`. AWS keys are signing keys only: `GenerateRSAKey` rejects
purpose 2 and a key size other than 2048/3072/4096 before any RPC, and
`GetKey` returns an error for a key whose usage is not `SIGN_VERIFY` or
that is `PendingDeletion` (XPKI-031; a `Disabled` key gets a signer, since
it can be enabled again); a label becomes the key description and,
sanitized to `[a-zA-Z0-9:/_-]` with `aws/` stripped, its alias (an alias
failure is logged, not returned). A created key whose public key can not
be fetched or parsed is scheduled for deletion (`discardKey`, best effort,
logged) before the error is returned. `NewSigner` needs the algorithms
KMS reports for the key; with none, every `Sign` fails. AWS `Signer.Sign` (XPKI-025) requires non-nil opts:
the hash selects the KMS algorithm (`RSASSA_PKCS1_V1_5_*`, `RSASSA_PSS_*`
with `*rsa.PSSOptions`, `ECDSA_*`), which must be in the `SigningAlgorithms`
KMS reported for the key (an ECDSA key has only its curve's), the digest
must have the hash length, PSS options are rejected for an ECDSA key and
the PSS salt must be `PSSSaltLengthEqualsHash` or the hash size (KMS signs
with the hash-length salt; local-kms uses a maximal salt); all checked
before any RPC, and a nil or empty response is an `empty response` error.
AWS `EnumKeys` (XPKI-032, XPKI-033) lists `SIGN_VERIFY` keys that are not
`PendingDeletion` whose label (the description, also `KeyInfo.Label`)
starts with `prefix`, in `ListKeys` order: KMS lists ids only, so every key
of the account is described (pages of 1000, `DescribeKey` at most 8 at a
time, the unexported `describeConcurrency`), which needs `kms:DescribeKey`
on every key. A key the caller may not describe (`AccessDeniedException`)
is left out and logged at WARNING; any other `ListKeys` or `DescribeKey`
failure cancels the calls in flight and is returned wrapped (`errors.As`
finds the `smithy.APIError`), and a truncated page without a marker is
also an error; there is no partial result.
GCP key identity (XPKI-020): a key ID is `K` or `K/cryptoKeyVersions/N`;
`GetKey`, `KeyInfo` and `DestroyKeyPairOnSlot` use the named version. A bare
`K` is resolved at each call from `ListCryptoKeyVersions`: `GetKey` signs
with the newest `ENABLED` version (none is an error); `KeyInfo` describes
the newest `ENABLED`, else the newest not `DESTROYED`, else the key alone
without version fields (`includePublic` is then an error, XPKI-117);
`DestroyKeyPairOnSlot` schedules every `ENABLED` or `DISABLED` version,
newest first, stopping at the first error (none is an error, XPKI-116), and
an explicit version is destroyed with one RPC. Signers from `GenerateRSAKey`,
`GenerateECDSAKey` and `GetKey` carry `K/cryptoKeyVersions/N` as their key ID
and resolve their version resource name once in `NewSigner`, so
`ExportKey`'s URI pins the version; `ExportKey` makes no RPC and copies the
id as given (`serial` is always `1`). `EnumKeys` does not list versions
(`CurrentVersionID` only from a primary version). GCP keys are signing keys
only (XPKI-019): `GenerateRSAKey` rejects purpose 2 before any RPC and treats
every other purpose as signing, like the other providers (XPKI-118); the
algorithm is PKCS#1 v1.5 SHA-256 (2048/3072) or SHA-512 (4096), P-256/SHA-256,
P-384/SHA-384 (XPKI-114: `csr` signs 3072-bit keys with SHA-384); `GetKey`
rejects a version that is not `ENABLED` or whose algorithm is not in
`signSchemes` (PKCS#1/PSS RSA and P-256/P-384 digest signing; secp256k1 is
excluded because `crypto/x509` cannot parse its key, XPKI-119). `Init`
requires the `Keyring` attribute (XPKI-120). `KeyLabelAndID`
(XPKI-022) lower-cases the name, maps characters outside `[a-z0-9_-]` to `-`,
cuts the label to 63 and the id to 54 characters plus `-` and 8 `crypto/rand`
characters; `genKey` retries a new id up to 3 times on `ALREADY_EXISTS`. Key
generation (XPKI-024) polls `GetCryptoKeyVersion` (state, not error text) at
most 60 times, 1 s apart, stops at once on an RPC error or a state other than
`PENDING_GENERATION`, and the wait between polls ends on `Close` (`ErrClosed`)
or context cancellation; the interval, attempt count and wait are unexported
fields set by `export_test.go`.
GCP lifecycle (XPKI-018): every client-using `Provider` method and
`Signer.Sign` registers with `enter`/`exit` (not nested); `Close` (once, via
`sync.Once`) rejects new calls with wrapped `ErrClosed`, ends the wait for key
generation, waits for in-flight ones, then closes the client and returns its
error; concurrent/later `Close` wait and return nil. The `KmsClient` field is
never cleared; calling its methods directly bypasses the guard. GCP
`Signer.Sign` (XPKI-025, XPKI-019) requires non-nil opts whose hash is the
key algorithm's, a digest of that hash's length, and `*rsa.PSSOptions` (salt
`PSSSaltLengthEqualsHash` or the hash size; `PSSSaltLengthAuto` is rejected
because KMS cannot produce a maximal salt, XPKI-124) exactly for PSS algorithms,
checked before any RPC; (XPKI-023) it accepts a response only with
`VerifiedDigestCrc32C` and a present, matching `SignatureCrc32C`. Nil KMS
responses are `empty response` errors; missing optional metadata
(`VersionTemplate`, `CreateTime`) is omitted from `KeyInfo` (no
`protection`/`algo` Meta, nil `CreationTime`), the selected version supplies
`CurrentVersionID`, `state` and, when set, `algo`/`protection`, and GCP key
labels are sorted by name. `inmemcrypto.NewProvider()` is
used at runtime by `authority/ocsp.go` for delegated responder keys. Both
`inmemcrypto` and `testprov` registries use an RWMutex for map publication
and lookup (XPKI-017, Fixed by IM1 and TP1). Key generation, signing,
decryption, and export serialization/formatting run outside the map lock.
Lookups retain signer identity. `inmemcrypto` exports caller-owned PKCS#1
(RSA) or SEC1 (ECDSA) PEM bytes with an empty URI; `testprov` exports a
PKCS#11 URI with nil key bytes. Token configuration passed to `Loader` must
remain unchanged during use. Metrics: `metricskey.PerfCryptoOperation`.

Tests: AWS `awskmsprov_test.go` (`Test_KmsProvider`) needs `local-kms` on
`:14556` (`make start-local-kms`, dummy `AWS_*` env) and is gated with
`testenv.RequireTCP` (XPKI-100); it verifies every signature locally and
lists the keys of its run by a unique prefix. The other AWS tests use
`fake_test.go`'s `fakeKMS`, an in-memory `KmsClient` with real local key
pairs (one cached per spec), KMS-shaped errors (`types.*Exception`,
`smithy.GenericAPIError`), paging, call counts, per-method overrides and
`DescribeKey` latency/failure hooks with peak-concurrency tracking;
`export_test.go` has `NewTestProvider` and `SetDescribeConcurrency`.
`signer_test.go` covers local option rejection without RPC and signature
verification per algorithm; `generate_test.go` purpose/size rejection,
aliases, `GetKey` usage and empty responses; `enum_test.go` prefix
contents, paging, failures at every position with no partial result and
kept error identity, and bounded concurrency; `enum_bench_test.go`
`BenchmarkEnumKeys` (calls, listed keys and peak concurrency per listing);
`init_test.go` the SDK credential chain, region/endpoint attributes and
`Init` errors (it swaps the global factory and the environment, so it is not
parallel). GCP tests need no fixture and no
testify mock. `gcpkmscrypto/kmsserver_test.go` is an in-process gRPC KMS
(`fakeKMSServer`: keys and versions with real local keys, id/label/state/digest
checks, paged version listing, injectable pending polls and creation errors)
reached through the real SDK client (`grpcProvider`, `export_test.go`
`NewKmsClient`); `gcpkmsprov_test.go` loads it through `KmsLoader` and the
`Endpoint` attribute end to end. `fake_test.go` has `fakeKMS` (func-field
client that records calls; unexpected calls return an error; its listing
methods return nil) and `newProvider`, built on `NewTestProvider`, so tests
need not swap the global factory and can run in parallel. `versions_test.go`
covers version selection, rotation, pinned/legacy URIs, disabled/missing
versions, paging, KeyInfo and destruction; `signer_test.go` option/padding
rejection without RPC, request digests, response integrity and local
verification of every algorithm; `generate_test.go` label/id rules, purpose
rejection, `ALREADY_EXISTS` retries, poll/wait counts, exhaustion, permanent
states and cancellation by `Close`/context; `gen_bench_test.go` the wait and
Close-latency benchmarks; `endpoint_test.go` `Init`-to-factory endpoint wiring
and the SDK path against the local server; `coverage_test.go` real SDK
pagination (`listingKMSServer`) and failure propagation; `lifecycle_test.go`
overlaps blocked signs with concurrent `Close`; `metadata_test.go` missing
metadata and nil responses.
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
| `ocsp.go`       | `SignOCSP`, `CreateDelegatedOCSPSigner`, `OCSPResponder`, delegated responder issuance/renewal (`delegatedResponder`), reason/status maps        |
| `extensions.go` | Certificate Policies ASN.1, SKI, CT OIDs, effective OCSP-signing EKU (`ekuHasOCSPSigning`, `isOCSPSigningTemplate`)                              |
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
collide with `policies`/`ocsp_no_check` (XPKI-050). `IssuerConfig.Type` is the
`type` key in YAML and JSON (XPKI-058). AIA `crl_expiry`, `ocsp_expiry`, `crl_renewal` are
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

- `Issuer.lock` guards `cfg.Profiles` only; `Issuer.Profiles` returns a
  copy. `Authority` keeps its issuer and profile maps in an immutable
  `registry` snapshot (`atomic.Pointer`); `AddIssuer` and `AddProfile`
  copy-on-write under `mu`, and a rejected `AddIssuer` (duplicate label,
  profile served by another issuer, nil profile) publishes nothing.
  Lookups are lock-free; `Profiles` and `Issuers` (sorted by label) return
  copies. A registered `*CertProfile` is shared with every reader and must
  not be modified; register a `Copy` instead (XPKI-055). OCSP responders (XPKI-051/052/053): `caResponder` is immutable
  after `CreateIssuer`; the delegated responder is an `atomic.Pointer`
  snapshot issued under `renewLock`. Lock order is `renewLock` → `lock`
  (`Sign` → `Profile`); never acquire `renewLock` while holding `lock`.
  Renewal starts when the responder expires within `ocsp_expiry`. A
  `SignOCSP` caller with a still-valid responder never waits: within the
  retry window (`renewal.retryAt`, an atomic snapshot) it takes no lock,
  otherwise it uses `TryLock`. On renewal failure `SignOCSP` uses a
  still-valid cached responder (retry after `ocspRenewRetryInterval`, 1
  minute) and otherwise returns an error, never the CA key; callers that
  queued during a failed attempt share its error. `CreateDelegatedOCSPSigner`
  blocks on `renewLock` and returns the last error while renewal is overdue.
  `CreateIssuer`, and each issuance on the exact profile snapshot it signs
  with (`signWithProfile`), rejects a missing or CA delegated profile, one
  whose effective EKU lacks OCSP signing (a raw profile EKU extension is
  decoded and overrides `usages`), or one whose expiry does not exceed
  `ocsp_expiry` + `effectiveBackdate` + `delegatedValidityMargin` (1m)
  (`validateDelegatedOCSPProfile`). After a failed attempt the cached
  responder's validity and the retry interval are measured from when the
  attempt ended, not when it started. `fillTemplate` detects a
  responder from the effective EKU too (`isOCSPSigningTemplate`), so raw-EKU
  responders get no OCSP/CRL URLs. `renewWaitHook` is a test-only seam.
  Delegated responses cap `NextUpdate` at the responder's `NotAfter`.
- Profiles must be `Validate()`d before use (compiles regexes; `LoadConfig` does).
- `Copy()` methods are shallow for `*CertProfile`.
- Metrics: `metricskey.PerfCAOperation`, `PerfCASignRequest`.

Tests: `authority_test.go` (suite) generates a 3-level chain with `testca`
into `/tmp/xpki/certs/*` referenced by `testdata/ca-config.dev.yaml`, and
loads the local-kms provider (loading does not connect). Only
`TestNewRoot` generates a key in local-kms and is gated by `requireKMS`
(`internal/testenv`); `TestShakenRoot`/`TestIssuerSign` use `inmemcrypto`,
so the rest of the package runs without fixtures (XPKI-100). SoftHSM is not
used.
`testdata/invalid_*.json` drive validation errors; `testdata/csrprofiles/*.yaml`
are used by `cmd/hsm-tool` tests (lowercase `names` keys, see csr invariants).
`ocsp_coverage_test.go` verifies direct responses and cached delegated responders
with fresh `testca` certificates. `ocsp_responder_test.go` covers fresh
delegated creation (with a deadline), renewal, renewal failure with and without
a valid cache (a failing or gated `countingSigner`), the retry interval,
waiters sharing a failure, a CA expiring within `ocsp_expiry`, profile
validation, `NextUpdate` capping, and synchronized concurrent cold
start/renewal; `issuer_test.go`
`TestNewIssuerDelegatedOCSP` builds one from files. `ocsp_bench_test.go` has
`BenchmarkSignOCSP` (warm sign/lookup), `BenchmarkDelegatedOCSPRetryWindow`
and `BenchmarkDelegatedOCSPCreate`. `issuer_coverage_test.go` exercises proof signatures, extension
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
| `pkcs8.go`      | `decryptPKCS8`: `ENCRYPTED PRIVATE KEY` with PBES2 + PBKDF2 (HMAC-SHA1/224/256/384/512) + AES-128/192/256-CBC, used by `GetKeyDERFromPEM`                        |
| `bundler.go`    | `Bundler`, options (`WithKeyUsages`, `WithBundleFlavor`, `WithAIA`, `WithHTTPClient`, `WithSystemRoots`), `Chain`, `Bundle`/`BundleContext`, `ChainFromPEM[Context]`, AIA fetch, expiry checks, `IntermediateStash` |
| `bundle.go`     | `Bundle`/`BundleStatus`, `VerifyBundleFromPEM`, `LoadAndVerifyBundleFromPEM`, `BuildBundle`, `FindIssuer`, `SortBundlesByExpiration`                            |
| `hash.go`       | Hash name maps, `Digest`, `SHA1*`, `SHA256*`, `HashToHex/Base64URL`, `ParseHexDigestWithPrefix`                                                                 |
| `cert_id.go`    | `GetThumbprintStr` (SHA-1 of DER), `GetSubjectKeyID`, `GetAuthorityKeyID`, `GetSubjectID`, `GetIssuerID`                                                        |
| `keyinfo.go`    | `KeyInfo`, `NewKeyInfo` (RSA/ECDSA from signer, decrypter or JWK)                                                                                               |
| `name.go`       | `NameToString` (OpenSSL-style DN)                                                                                                                               |
| `ocsp.go`       | `CreateOCSPRequest` (nil certificate/issuer or unavailable hash is an error; the issuer must carry crt's issuer name and its key must verify crt's signature, SHA-1 allowed, XPKI-121) |
| `extensions.go` | `FindExtension*`, `IsOCSPSigner`, `HasOCSPNoCheck`                                                                                                              |
| `random.go`     | `RandReader`, `Random`, `RandomString` (panic on RNG failure)                                                                                                   |

### Invariants

- Chain building: `certs[0]` is the leaf; `Force` only checks each cert is
  signed by the next; `Optimal` runs `x509.Verify` against `RootPool` and
  `IntermediatePool`, fetches AIA intermediates on unknown authority when
  `WithAIA(true)`, ranks chains shortest-then-longest-expiring, and strips the
  root unless the leaf has OCSP servers and the chain is ≤ 2. "Expiring" is
  less than 720h left.
- Trust roots (XPKI-041): the flavor defaults to `Optimal` with trust roots
  (explicit roots or `WithSystemRoots(true)`) and `Force` without them; the
  last `WithBundleFlavor` wins. `NewBundler` rejects `Optimal` without trust
  roots and unknown flavors. System roots are trusted only through
  `WithSystemRoots`, which adds explicit roots to `x509.SystemCertPool()`.
  `VerifyOptions().Roots` is never nil, and an `Optimal` `Bundle` with a nil
  `RootPool` fails, so no path verifies against ambient system trust.
- AIA fetch (XPKI-037, XPKI-039): each request uses `NewRequestWithContext`
  with the `BundleContext` context and a deadline of the client `Timeout`, or
  3s when it is zero. Only a 200 response of at most 1 MiB is parsed, and the
  body is never logged. Each URL is requested at most once per `Bundle` call,
  including failures; the next call retries. A done context stops the
  traversal and the returned error matches `ctx.Err()`.
- Concurrency (XPKI-035): a `Bundler` is safe for concurrent `Bundle`,
  `ChainFromPEM` and `VerifyOptions` calls. `mu` (RWMutex) guards `RootPool`,
  `IntermediatePool` and `KnownIssuers` once in use. Each call reads a
  `snapshot` and verifies without the lock. `verifyChain` adds intermediates it
  verified to a private clone and publishes them once with `learn`, which
  copies the map and installs the clone, or merges into a copy of the current
  pool when another call published first. A pool or map once read is never
  modified, so `VerifyOptions` returns a snapshot. The exported fields are
  set-up state: set them before first use, then read the pools through
  `VerifyOptions`. Learning costs one pool clone per newly learned
  intermediate (O(pool)); warm calls take only the read lock. Concurrent
  misses on one issuer each fetch its URL, at most once per call, with no
  cross-call coalescing. Only RSA/ECDSA leaf keys accepted.
- Input (XPKI-036, XPKI-042): `Bundle`/`BundleContext` of a nil or empty list
  returns an error matching `ErrNoCertificates`, and a nil entry is an error.
  `BuildBundle` rejects a nil `Chain` or `Cert` (the latter wraps
  `ErrNoCertificates`), treats a nil `Status` as empty, and accepts a rootless
  `Force` chain (empty `RootCert`/`RootCertPEM`).
- `SortBundlesByExpiration` (XPKI-038) returns a new slice, stably sorted by
  `Expires` descending with nil bundles last; the input slice is not
  reordered and the bundles are shared. `ExpiresInHours` truncates toward
  zero (XPKI-045).
- Encrypted keys (XPKI-043): `GetKeyDERFromPEM` decrypts legacy RFC 1423 PEM
  and PKCS#8 PBES2 with PBKDF2 (HMAC-SHA1 default, SHA-224/256/384/512, at
  most 10,000,000 iterations, `keyLength` must match) and AES-CBC. PBES1,
  PKCS#12 PBE, scrypt, DES/3DES and other ciphers return
  `unsupported PKCS#8 encryption: …`. A nil password fails with `encrypted
  private key`; a wrong password (bad padding, or plaintext that is not one
  RFC 5958 `PrivateKeyInfo` structure, XPKI-115) matches
  `x509.IncorrectPasswordError`; the key inside is parsed afterwards by
  `ParsePrivateKeyDER`.
- Process-global: `IntermediateStash` (fetched intermediates written `0644`),
  `RandReader`. `HTTPClient` is deprecated and never read (XPKI-044); use
  `WithHTTPClient`. Default AIA client timeout 3s.
- `ParseChainFromPEM` returns the parsed prefix and an error on trailing garbage.

Tests: `testdata/` holds a Mozilla root bundle, 229 intermediates, test server
chain and hash fixtures; `testdata/pkcs8/` holds OpenSSL-generated
plain and encrypted (password `xpki-test`) RSA/EC/Ed25519 PKCS#8 keys,
including unsupported des3/scrypt/PKCS#12 samples. `pkcs8_test.go` also
builds PBES2 structures in Go for the PRF × AES matrix, malformed
parameters and DER plaintexts that are not a `PrivateKeyInfo`. `TestKeyInfoKMS` is the only fixture test: it is gated with
`testenv.RequireTCP` on local-kms `:14556`; `TestKeyInfoOpaqueKeys` covers
opaque signers without KMS. `bundle_input_test.go` covers the nil/empty
input contracts of `Bundle`, `BuildBundle`, `SortBundlesByExpiration` and
`CreateOCSPRequest`.
`bundler_coverage_test.go` uses fresh `testca` chains, temporary files and local
HTTP servers for AIA fetching, caching, validation, and expiry behavior; it
restores `IntermediateStash` and runs serially. `bundler_aia_test.go` uses a
per-path counting AIA server for response limits, stalls, cancellation,
per-traversal request counts (`BenchmarkBundlerAIAFailingURL`) and log
content; `export_test.go` exposes the body limit and `learn` (`Learn`).
`bundler_concurrency_test.go` shares one Bundler across goroutines released
together (warm hits plus two AIA chains, run with `-race`), covers `learn`
merging with a stale snapshot and nil set-up fields, and holds
`BenchmarkBundle` (warm serial/parallel and learning cost at pool sizes
0/100/1000). Its tests leave `IntermediateStash` empty and run in parallel. `bundler_roots_test.go`
covers flavor/root resolution and re-runs itself in a subprocess with
`SSL_CERT_FILE`/`SSL_CERT_DIR` set to a generated root to test system trust
(skipped on darwin/windows). `bundler_ranking_test.go` tests
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
| `jwks.go`   | `KeySet`, `AlgorithmKeySet`, `StaticKeySet`, `RemoteKeySet` (lazy fetch, inflight coalescing, refresh cooldown), `RemoteKeySetOption`s, `ErrKeyNotFound`, `ErrAmbiguousKey`              |

### Invariants

- Alg from key: RSA ≥4096 → RS512, ≥3072 → RS384, else RS256; P-521 → ES512,
  P-384 → ES384, else ES256. HS256 key ring: seeds are SHA-256'd, `kid` header
  set; `NewProvider` errors if `kid` is not in `keys`.
- Default expiry 60m, `DefaultNotBefore` −2m, `DefaultTimeSkew` 5m on
  `iat`/`nbf` only. `ExpectedAudience` means all listed values present.
  Issuer/subject compared case-insensitively.
- Every provider's `ParseToken` accepts only tokens whose `alg` is its own
  signing algorithm (`ValidMethods`, XPKI-112): the HS256 key ring rejects
  HS384/HS512 tokens signed with a ring key, and an RS256 provider rejects
  RS384/RS512 tokens signed with its private key. `provider.ParseToken`
  requires `kid` for HS tokens, except for
  `NewProviderWithSymmetricKey` (XPKI-066): it signs without a `kid` unless
  `WithHeaders` sets a nonempty string one, and verifies with its single key
  only tokens with no `kid` or that `kid`
  (`allowNoKid`); any other `kid`, including an empty or non-string one, is
  `unexpected kid`. `parser.ParseToken` refuses HS. `alg: none` is rejected.
  Numeric `kid` headers are stringified.
- The protected header is `typ`, `alg` and the `WithHeaders` entries (`kid`
  for the key ring, `jwk` for asymmetric keys); no header `jti` is generated
  (XPKI-073). A token identifier is the payload `jti` claim, set by the
  caller (`CreateClaims` takes it); `Sign` never adds one, so identical
  claims sign to identical HS/RS tokens.
- `Sign` writes `exp`, `iat` and `nbf` as NumericDate whatever their Go
  type (`time.Time`, `*time.Time`, `NumericDate`, RFC 3339 or numeric
  strings, numbers) with `MapClaims.NormalizeTimeClaims` on a copy of the
  claims (`accesstoken.Sign` uses the same method); a value `MapClaims.Time`
  cannot parse, or a zero time, is a `Sign` error that leaves the map
  unchanged. `MapClaims.Time` reads
  NumericDate, `time.Time`, `*time.Time`, `NumericDate`/`*NumericDate`,
  numeric strings, RFC 3339 strings (what `json.Marshal` writes for a
  `time.Time`) and the legacy `2006-01-02T15:04:05.000-0700` layout, so a
  string time claim is validated rather than skipped (XPKI-109). A `uint64`
  above `MaxInt64`, a float outside int64, or a numeric string or
  `json.Number` outside int64 is nil (DEBUG log), never a wrapped negative
  time, so `NormalizeTimeClaims` rejects it too. The unexported `timeClaim`
  distinguishes an absent claim from a present one that is not a time;
  `VerifyExpiresAt`/`VerifyIssuedAt`/`VerifyNotBefore`, and so `Valid`,
  reject the latter (`invalid exp claim: ...`) instead of skipping the check
  (XPKI-125).
- Headers (XPKI-104): every constructor creates `headers` before applying
  options, and `validateHeaders` runs after them. An `alg` header other than
  the signing algorithm is a constructor error. With HS keys (`NewProvider`
  key ring, `NewProviderWithSymmetricKey`) a `kid` header must be the signing
  key's ID. Asymmetric providers accept any `kid`, and `typ`, `jwk` and other
  headers stay overridable (dpop sets `typ`). `NewProviderWithSymmetricKey`
  rejects an empty key and copies it.
- Key selection (XPKI-071/072, `selectKey`): a key is eligible when its JWK
  `use` is empty or `sig` and, when the alg is known, its type/curve and JWK
  `alg` fit it (RS* → RSA, ES256/384/512 → P-256/384/521; other algs have no
  eligible key). A `kid` selects `KeySet` entries with that `KeyID`, else
  `StaticKeySet.PublicKeys` by RFC 7638 SHA-256 thumbprint (base64url); an
  empty `kid` considers all entries of both lists. Exactly one eligible key
  must remain, otherwise `ErrKeyNotFound` / `ErrAmbiguousKey` (wrapped).
  `PublicKeys` accepts only `*rsa.PublicKey`/`*ecdsa.PublicKey`; anything
  else fails every lookup. `parser.ParseToken` passes the token alg through
  `AlgorithmKeySet.GetKeyForAlgorithm`; plain `GetKey` checks only `use`.
- `RemoteKeySet` (XPKI-070) refetches when no cached key fits the lookup, at
  most once per `WithRefreshCooldown` (default 10s, measured from the end of
  the previous fetch, successful or not; 0 disables). Inside the cooldown a
  miss fails from the cache, or with the last fetch error when nothing is
  cached. Each fetch is bounded by `WithFetchTimeout` (default 10s, applied
  as a context deadline even with an injected `WithHTTPClient`) and
  `WithMaxResponseSize` (default 1 MiB, larger bodies rejected); response
  bodies are never echoed in errors. The shared fetch runs on the set's
  lifetime context, so cancelling one waiter does not cancel it. `refresh`
  publishes cache/`lastFetch`, bumps the `fetches` counter and clears
  `inflight` before waking waiters. A lookup whose cache snapshot predates a
  completed fetch (`keysFromCache` returns the counter) shares that fetch's
  result instead of starting another, so coalescing holds with cooldown 0.
  The read limit is `maxResponseSize+1` except at `math.MaxInt64`.
  `NewParser` uses the defaults. `ParseWithClaims` verifies the signature before
  validating claims. `MapClaims.Int/Int64/UInt64` return 0 (DEBUG log) on
  overflow, negative-to-unsigned, or parse failure. `NumericDate` and
  `MapClaims.Time` accept fractional seconds and truncate to whole seconds
  with exact arithmetic (`parseNumericDate`), so a fractional `exp` is
  still validated.
- `MustNewProvider` panics; `TimeNowFn` is a mutable global used by tests.
- go-jose v4 is used only for `JSONWebKey`/`JSONWebKeySet` types.

Tests: `testdata/jwtprov*`, `oidc_parser*` (Google/Cognito JWKS snapshots),
embedded real ID tokens; `Test_SignPrivateKMS` needs local-kms on `:14555`
(`kmsConfig`, `localKMSAddr`) and is gated by `testenv.RequireTCP`; every
other jwt test is fixture-free. `parser_coverage_test.go` covers
configuration files, malformed tokens, real symmetric/asymmetric signing, the
standalone symmetric provider (round trip, wrong key, tampering, kid policy,
header options), key-ID types, and claim conversions.
`TestProviderHeaderValidation` (`jwt_test.go`) covers the header checks of the
config and crypto-signer constructors. `sign_policy_test.go` covers the
header without `jti`, the algorithm pin of every constructor (hand-signed
HS384/HS512 and RS384/RS512 tokens with the provider's own key) and time
claim normalization; `TestValid_RFC3339TimeClaims` (`claims_test.go`) covers
string time claims in `Valid`.
`jwks_test.go` has table tests for key selection, parser round trips with
kid-less tokens and `PublicKeys`, and `RemoteKeySet` behavior against a
local `httptest` JWKS server (`jwksServer`: mutable body/status and a request
gate for stalled fetches). `jwks_internal_test.go` drives the cooldown with
the unexported `RemoteKeySet.now` clock and calls `keysFromRemote` with a stale
snapshot count. `jwks_bench_test.go`
(`BenchmarkRemoteKeySet`) reports `fetches/op` for known, repeated-unknown
and parallel unique-unknown kids.

## Packages jwt/dpop, jwt/accesstoken, jwt/oauth2client, dataprotection

- **dpop**: `dpop.go` constants (`HTTPHeader`, `DefaultExpiration` 10m,
  `CnfThumbprint`, `ClaimAccessTokenHash`) and `AccessTokenHash` (ath =
  base64url SHA-256), `keys.go` P-256 JWK generate/load/save
  (`<folder>/<thumbprint>.jwk`, 0600), `signer.go` proof signer (`typ:
  dpop+jwt`, `jwk` header, 22-character jti, htu keeps `RawPath`),
  `verify.go` rules in order: compact proofs decode the protected header
  first with go-jose's case-sensitive `json` fork (so a private `jwk` or
  HMAC `alg` is a DPoP error, not a go-jose parse error, and `TYP` is not
  `typ`); JSON JWS is parsed so more than one signature is `token
  contains multiple headers`; then `typ`, public `jwk`, alg in the
  asymmetric allow-list (RS\*, PS\*, ES\*, EdDSA); the signature is verified
  by go-jose with the embedded JWK **before** any claim is read (go-jose
  rejects a key type/curve that does not fit the alg), and claims are
  decoded case-sensitively like `GetTokenInfo`; then
  `jti`/`htm`/`htu`/`iat` present, `htu` equal after `htu.go`
  normalization, `iat` within 10m, exp/nbf, optional iss/sub/aud/nonce,
  `ath` when `VerifyConfig.AccessToken` is set (which requires
  `ExpectedThumbprint`: `ath` alone is computable by a token thief), proof
  thumbprint equal to `ExpectedThumbprint` (constant time), and last `ReplayCache.Add`, so only a
  fully valid proof consumes its jti. `ReplayCache` is opt-in (nil = no
  replay detection). The key is base64url SHA-256 of thumbprint + jti
  (fixed 43 bytes), retained through `iat + DefaultExpiration` or `exp` if
  earlier, inclusive. `replay.go` `MemoryReplayCache`: one mutex, map plus
  expiry min-heap, evicts entries whose expiry is before now on every `Add`, fails closed with
  `ErrReplayCacheFull` at capacity (default 100000), clock `TimeNowFn`.
  `htu.go`: `VerifyRequestClaims` builds the request URI from
  `ExternalURL` (trusted `scheme://host[:port]`, validated per call), else
  URL scheme/host, then `req.Host`, with https for an empty scheme; query and
  fragment dropped. `normalizeHTU` lowercases scheme and host, drops the
  default port, decodes unreserved escapes, uppercases other escapes, keeps
  path case and dot segments (a router may dispatch `/admin/../x` elsewhere);
  `htm` must equal the request method exactly, since HTTP methods are
  case-sensitive (RFC 9110 §9.1, XPKI-108). Binding to the access token:
  `ExpectedThumbprint`, or compare `Result.Thumbprint` with the `cnf.jkt`
  claim.
- **accesstoken**: `pat.<base64url(AES-GCM(json claims))>`; non-`pat.` tokens
  delegate to the inner `jwt.Provider`. `Sign` copies the claims (the caller
  map is never modified), keeps caller `exp`/`iat`/`nbf` normalized to
  NumericDate (rejecting unparsable ones), and without `exp` adds `exp` =
  now + `TokenExpiry()` plus `iat`/`nbf` when absent, using `jwt.TimeNowFn`.
  `TokenExpiry()` = `WithTokenExpiry` if non-zero (negative → 0), else the
  inner provider's, else 0; a non-positive value makes `Sign` fail.
  `ParseToken` requires `exp` unless `WithAllowNoExpiry` (legacy migration;
  an unparsable `exp` is always rejected, and an RFC 3339 one from an old
  `time.Time` is parsed and checked) (XPKI-078, 109). A nil `dp` is allowed:
  `PublicKey` returns nil and `pat.` `Sign`/`ParseToken` return an error
  (XPKI-079). `SetRevocation` is forwarded to the inner provider. Tests that
  pin `jwt.TimeNowFn` (`setClock`) must not call `t.Parallel`.
- **oauth2client**: `config.go` `Config`/`ClientConfig` (`env://` values via
  `x/configloader`), `client.go` `Client`, `CreateTokenRequest[WithContext]`,
  `provider.go` registry lookups by provider id, email, domain
  (`ClientForEmail` returns nil unless the value is `local@domain`). A
  `Client` owns a deep copy of its `ClientConfig` (`clone`): `Config()`
  returns a copy, `SetClientSecret`/`SetPubKey` are the only mutations, under
  the client's RWMutex, and `CreateTokenRequestWithContext` snapshots the id,
  secret and URL under it; `PublicKey()` returns the key parsed from `PubKey`
  (`JwksURL` and `PubKey` are configuration for a caller's verifier, this
  package verifies nothing) (XPKI-080). The `Provider` registry is an
  immutable `registry` snapshot in an `atomic.Pointer`, replaced under a
  writer mutex by `RegisterClient`, so a registration is published to the
  three indexes at once and a rejected one changes nothing; `override`
  removes the previous client of that provider id from every index before
  publishing (XPKI-081). Lookups are lock-free (one atomic load); `Config()`
  costs one deep copy (an allocation for the struct and one per non-nil
  slice and `IDPParam`). `provider_bench_test.go` has the lookup,
  enumeration, token-request and `Config()` benchmarks.
- **dataprotection**: `Provider` interface; `NewSymmetric(secret)` = HKDF-SHA256
  → AES-256-GCM, blob `nonce(12) || ciphertext || tag`, no key id (XPKI-083).

Tests are pure except `keys_test.go` writing under `os.TempDir()`.
`dpop/verify_policy_test.go` covers replay (sequential, 32 simultaneous
duplicates, store error, retention), ath/cnf.jkt binding, server-style
requests for htu, and a real-signature matrix for every allowed alg;
`htu_internal_test.go` tables the normalizer; `example_test.go` compiles the
`doc.go` sample; `verify_bench_test.go` has `BenchmarkVerifyClaims`,
`BenchmarkVerifyClaimsReplayCache` and `BenchmarkMemoryReplayCache`. Only
the non-parallel `TestMemoryReplayCache_Expiry` replaces `dpop.TimeNowFn`.
`oauth2client/request_coverage_test.go` checks token-request authentication,
context cancellation, preservation of caller-owned form values, and registry
conflicts/overrides; it makes no network requests.

## Helper packages

- **armor**: `Decode` only; CRC24 required (XPKI-047); returns nil on malformed input, never panics. `testdata/` GPG keys incl. corrupted variants.
- **oid**: exported maps are process-global; `KeyUsages` returns canonical names in RFC 5280 bit order, each bit once.
- **x/print**: writes to an `io.Writer`, ignores write errors, local time; a zero `NextUpdate` prints `Expires: not set`; `JSON` swallows marshal errors by design. Tests in `certutil_test.go` load `testdata/*.pem` and append synthetic `*x509.Certificate` values to cover SAN, AIA, CRL, and extension formatting.
- **metricskey**: descriptors only; registered by consumers.
- **internal/version**: `build` is set by the linker (`make build` passes `-X ...internal/version.build=$(GIT_VERSION)`); otherwise `buildVersion` reads the module version from `debug.ReadBuildInfo`, else `devel-<revision>[-dirty]`, else `devel` (XPKI-097). `PopulateFromBuild` strips a leading `v`.
- **internal/testenv**: test-only; imports `testing`. `RequireTCP` dials with a 1s timeout and skips or fails (`XPKI_INTEGRATION=required`) only when the fixture is unreachable; `RequireFile` does the same for a missing fixture file and always fails on other stat errors (XPKI-100).
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
  blank-imported in `cli/cli.go` and loaded lazily by `CryptoProv()`, whose
  error (empty or bad `--cfg`) fails the command with exit status 1 (XPKI-084).
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
| `/tmp/xpki/softhsm_unittest.json`, token `xpki_unittest`, PIN `~/softhsm2/xpki_pin_unittest.txt` | `make hsmconfig` (`scripts/config-softhsm.sh`) | `crypto11`, `cryptoprov` (four gated tests), `csr`                                                    |
| `local-kms` on `:14555` and `:14556`                                                             | `make start-local-kms` (`docker-compose.yml`)  | `awskmscrypto` (`Test_KmsProvider` only, gated), `authority` (`TestNewRoot` only), `jwt` (`Test_SignPrivateKMS` only), `certutil` (`TestKeyInfoKMS` only, gated), `cmd/hsm-tool/cli` (`csr_test.go`) |
| `AWS_ACCESS_KEY_ID` etc. dummy values                                                            | `Makefile` exports                             | AWS SDK                                                                                               |
| `/tmp/xpki/certs/*`                                                                              | `authority_test.go` via `testca`               | `authority/testdata/ca-config.dev.yaml`                                                               |

`internal/testenv.RequireTCP` gates a fixture-dependent test: an unreachable
fixture skips it unless `XPKI_INTEGRATION=required`, which the Makefile
exports (so `make test`/`covtest` and CI fail); a reachable fixture always
runs it. `internal/testenv.RequireFile` does the same for a fixture file
(`crypto11` and `cryptoprov` gate on the SoftHSM config). `authority`,
`crypto11`, `jwt`, `cryptoprov` and `certutil` use them so far; the other packages still
fail hard when a fixture is missing (XPKI-100, remaining portions).

`cmd/xpki-tool/cli/coverage_test.go` uses generated certificates and local HTTP
servers to cover certificate filters, trust validation, concurrent revocation
checks, CRL/OCSP fetch and inspection, and input/transport errors. It
characterizes OCSP fetch success after endpoint failures (XPKI-102), and
asserts that a nil certificate or issuer returns the `CreateOCSPRequest` error
with `ocsp.Unknown` and no HTTP request (XPKI-103). Fixtures use `t.TempDir()`. In
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
  `make version` prints `GIT_VERSION`, which `make build` and `make hsmconfig`
  link into the CLIs through `LDFLAGS` (XPKI-097). `make docs` runs gomarkdoc for `crypto11`, `cryptoprov`,
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
