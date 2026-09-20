# FINDINGS

Active, actionable bugs, security issues, and correctness problems.
Completed work and deprecation decisions are omitted.

Use the **ID** when commenting or assigning work. Update **Status** in the
same change as the code or decision, and remove the item when it is complete.
IDs are never reused, so a gap in the numbering only means the item was
resolved and removed.

## Status

| Status         | Meaning                                                |
| -------------- | ------------------------------------------------------ |
| Open           | Not started                                            |
| In Progress    | Being fixed                                            |
| Needs Approval | Behavior or compatibility change that needs a decision |

Severity: **security** > **bug** > **race** > **correctness** > **performance** > **docs**.

Line numbers refer to the tree at the time of the audit (2026-09-20) and may
drift; the symbol name is the stable reference.

## Index

| ID       | Package                   | Location                                             | Title                                                                                     | Severity    | Status         |
| -------- | ------------------------- | ---------------------------------------------------- | ----------------------------------------------------------------------------------------- | ----------- | -------------- |
| XPKI-001 | crypto11                  | `crypto11.go` `PKCS11Lib.Close`                      | `Destroy()` runs before `Finalize()`, so C_Finalize never runs and pool sessions leak      | bug         | Open           |
| XPKI-002 | crypto11                  | `sessions.go` `withSession`                          | `sessionPools` map read without `sessionPoolMutex` while `setupSessions` writes            | race        | Open           |
| XPKI-003 | crypto11                  | `sessions.go` `withSession`                          | Slot without a pool blocks forever on the nil channel (doc says "panic")                   | bug         | Open           |
| XPKI-004 | crypto11                  | `ecdsa.go` `Sign`, `rsa.go` `Sign`/`Decrypt`         | Operations use `lib.Slot.id` instead of `priv.key.Slot`; keys found on other slots fail    | correctness | Open           |
| XPKI-005 | crypto11                  | `sessions.go` `withSession`                          | Unbounded session opening; sessions never closed; return blocks once pool (1024) is full  | performance | Open           |
| XPKI-006 | crypto11                  | `config.go` `Init` token match                       | Empty configured `TokenSerial`/`TokenLabel` matches any token with the empty field         | correctness | Open           |
| XPKI-007 | crypto11                  | `config.go` `Init`                                   | Loaded module (`pkcs11.New`) leaks on every error path after load                          | bug         | Open           |
| XPKI-008 | crypto11                  | `keys.go` `ListKeys`/`FindKeys`                      | Single `FindObjects(session, 100)`; tokens with >100 objects are silently truncated        | correctness | Open           |
| XPKI-009 | crypto11                  | `rsa.go` `PKCS11PrivateKeyRSA.Decrypt`               | `*rsa.PKCS1v15DecryptOptions` rejected although documented as supported                    | correctness | Open           |
| XPKI-010 | crypto11                  | `rsa.go` `signPKCS1v15`                              | Hash not in `pkcs1Prefix` signs the raw digest without DigestInfo instead of erroring      | correctness | Open           |
| XPKI-011 | crypto11                  | `common.go` `BytesToUlong`                           | Panics on empty input and reads out of bounds on short attribute values                    | bug         | Open           |
| XPKI-012 | crypto11                  | `util.go` `DestroyKeyPairOnSlot`                     | Returns nil when neither key handle exists; deleting a missing key reports success         | correctness | Open           |
| XPKI-013 | crypto11                  | `common.go` `dsaGeneric`                             | `unmarshalBytes` error ignored; malformed signature yields an opaque ASN.1 error           | correctness | Open           |
| XPKI-014 | crypto11                  | `keys.go` `ConvertToPublic`                          | `*privateKeyGen` (returned by `GenerateRSAKey`/`GenerateECDSAKey`) is not handled          | correctness | Open           |
| XPKI-015 | crypto11                  | `rsa.go` `signPSS`                                   | `rsa.PSSSaltLengthAuto` (crypto/tls default) is rejected                                   | correctness | Open           |
| XPKI-016 | cryptoprov                | `provider.go` `Crypto.Add`/`ByManufacturer`          | No synchronization; duplicate check in `Add` is unreachable (key already includes model)   | race        | Open           |
| XPKI-017 | cryptoprov/inmemcrypto, testprov | `provider.go` `keyIDToPvk`                    | Key map written by `Generate*` and read by `GetKey` without a lock (used by `authority/ocsp.go`) | race   | Open           |
| XPKI-018 | cryptoprov/gcpkmscrypto   | `gcpkmsprov.go` `Close`                              | Sets embedded `KmsClient` to nil unsynchronized; later `Sign` panics                       | race        | Open           |
| XPKI-019 | cryptoprov/gcpkmscrypto   | `gcpkmsprov.go` `GenerateRSAKey`                     | `purpose==2` sets ASYMMETRIC_DECRYPT with a SIGN algorithm; 4096-bit forces SHA512 while `Sign` picks digest from opts | correctness | Open |
| XPKI-020 | cryptoprov/gcpkmscrypto   | `gcpkmsprov.go` `GetKey`, `keyVersionName`, `ExportKey` | `cryptoKeyVersions/1` hard-coded; rotated keys sign/destroy the wrong version            | correctness | Open           |
| XPKI-021 | cryptoprov/gcpkmscrypto   | `gcpkmsprov.go` `Init`                               | `Endpoint` attribute parsed but never applied to the client                                | correctness | Open           |
| XPKI-022 | cryptoprov/gcpkmscrypto   | `gcpkmsprov.go` `KeyLabelAndID`                      | 4 hex chars of entropy (65k) and no label sanitisation; ALREADY_EXISTS / INVALID_ARGUMENT | correctness | Open           |
| XPKI-023 | cryptoprov/gcpkmscrypto   | `gcpkmsprov.go` `keyInfo`, `signer.go` `Sign`        | Direct proto field access (`VersionTemplate`, `SignatureCrc32C`) may nil-deref             | bug         | Open           |
| XPKI-024 | cryptoprov/gcpkmscrypto   | `gcpkmsprov.go` `genKey`                             | Up to 60 s blocking `time.Sleep` poll ignoring ctx; matches error by substring             | performance | Open           |
| XPKI-025 | cryptoprov/awskmscrypto, gcpkmscrypto | `signer.go` `Sign`                       | `opts == nil` → nil interface method call panic (`inmemcrypto` defaults to SHA256)         | bug         | Open           |
| XPKI-026 | cryptoprov                | `provider.go` `New`                                  | `New(nil, ...)` panics on `defaultProvider.Manufacturer()`                                 | bug         | Open           |
| XPKI-027 | cryptoprov                | `uri.go` `ParseTokenURI`/`ParsePrivateKeyURI`        | RFC 7512 `?pin-value=`/`?module-path=` query attributes are dropped                        | correctness | Open           |
| XPKI-028 | cryptoprov                | `config.go` `LoadTokenConfig`                        | `file:` PIN content not trimmed; trailing newline breaks `C_Login` (crypto11 loader trims) | correctness | Open           |
| XPKI-029 | cryptoprov                | `utils.go` `ParsePrivateKeyDER`                      | Real parse error discarded; PKCS#8 Ed25519 parses then is rejected as "failed to parse key" | correctness | Open          |
| XPKI-030 | cryptoprov                | `utils.go` `TLSKeyPair`                              | Comment claims key/cert match check; none is performed; doc says `Leaf` nil but it is set  | correctness | Open           |
| XPKI-031 | cryptoprov/awskmscrypto   | `awskmsprov.go` `GenerateRSAKey`                     | `purpose==2` creates ENCRYPT_DECRYPT key but returns a `Signer`; no `crypto.Decrypter`     | correctness | Open           |
| XPKI-032 | cryptoprov/awskmscrypto   | `awskmsprov.go` `EnumKeys`                           | Lists every key in the account then one `DescribeKey` per key (N+1); `prefix` ignored      | performance | Open           |
| XPKI-033 | cryptoprov/awskmscrypto   | `awskmsprov.go` `EnumKeys`                           | `DescribeKey` errors logged and skipped; throttled keys vanish from listings               | correctness | Open           |
| XPKI-034 | cryptoprov/awskmscrypto   | `awskmsprov.go` `Init`                               | Env credentials forced into a static provider; redundant with SDK chain, non-refreshable   | correctness | Open           |
| XPKI-035 | certutil                  | `bundler.go` `verifyChain`/`fetchIntermediates`      | `Bundler` mutates `KnownIssuers` and `IntermediatePool` per call; concurrent `Bundle` panics | race      | Open           |
| XPKI-036 | certutil                  | `bundler.go` `Bundler.Bundle`                        | Empty cert list returns `(nil, nil)`                                                       | bug         | Needs Approval |
| XPKI-037 | certutil                  | `bundler.go` `fetchRemoteCertificate`                | AIA fetch: no status check, unbounded `io.ReadAll`, no context, body logged in full        | security    | Open           |
| XPKI-038 | certutil                  | `bundle.go` `SortBundlesByExpiration`                | Sorts the caller's slice in place with unstable `sort.Slice`                               | correctness | Needs Approval |
| XPKI-039 | certutil                  | `bundler.go` `fetchIntermediates`                    | `seen[url]` set only on success; failing AIA URLs re-fetched each iteration                | performance | Open           |
| XPKI-040 | certutil                  | `bundler.go` `Bundle` key match                      | RSA key match compares only `N`, ignores `E`; use `Equal`                                  | correctness | Open           |
| XPKI-041 | certutil                  | `bundler.go` `NewBundler`                            | No roots + `WithBundleFlavor(Optimal)` leaves `RootPool` nil, so `x509.Verify` trusts system roots | security | Open        |
| XPKI-042 | certutil                  | `bundle.go` `BuildBundle`                            | Dereferences `c.Status`/`c.Cert` without nil checks                                        | bug         | Open           |
| XPKI-043 | certutil                  | `pem.go` `ParsePrivateKeyPEMWithPassword`            | PKCS#8 `ENCRYPTED PRIVATE KEY` unsupported; falls through to an opaque error; doc claims support | correctness | Open       |
| XPKI-044 | certutil                  | `bundler.go` `HTTPClient`                            | Exported global documented as used for all HTTP requests but never read                    | docs        | Open           |
| XPKI-045 | certutil                  | `bundle.go` `ExpiresInHours`                         | Doc says "rounded up"; integer division truncates                                          | docs        | Open           |
| XPKI-046 | oid                       | `oidinfo.go` `KeyUsages`                             | Iterates a map: nondeterministic order and both aliases (`signing`, `digital signature`) emitted | correctness | Open       |
| XPKI-047 | armor                     | `armor.go` `Decode`                                  | CRC24 trailer mandatory; RFC 9580 requires accepting armor without it                      | correctness | Open           |
| XPKI-048 | x/print                   | `certutil.go` `CertificateList`/`OCSPResponse`       | Zero `NextUpdate` prints `0001-01-01 (in -2000000h)`                                       | correctness | Open           |
| XPKI-049 | authority                 | `issuer.go` `Sign` (`safeTemplate = *requesterCsrTemplate`) | All CSR `ExtraExtensions` (KU/EKU/SAN/…) copied into the template; empty `AllowedExtensions` allows every OID | security | Needs Approval |
| XPKI-050 | authority                 | `issuer.go` `Sign` profile extensions                | Profile `Extensions` appended without dedupe against CSR extensions; `CreateCertificate` output then fails to parse | correctness | Open |
| XPKI-051 | authority                 | `ocsp.go` `CreateDelegatedOCSPSigner`                | Holds `ca.lock` then calls `ca.Sign` → `ca.Profile` → `RLock`: deadlock when `delegated_ocsp_profile` is set | bug | Open        |
| XPKI-052 | authority                 | `ocsp.go` `SignOCSP` non-delegated branch            | `ca.responder` read/written without the lock                                               | race        | Open           |
| XPKI-053 | authority                 | `ocsp.go` `SignOCSP`                                 | Fallback `responder = ca.responder` may be nil → `responder.Cert` panics                   | bug         | Open           |
| XPKI-054 | authority                 | `issuer.go` `Sign`/`fillTemplate`                    | `SignRequest.NotBefore/NotAfter` not bounded by profile expiry; inverted range not rejected | correctness | Needs Approval |
| XPKI-055 | authority                 | `authority.go` maps                                  | `Authority` maps and `Issuer.Profiles()` live map have no synchronization                  | race        | Open           |
| XPKI-056 | authority                 | `issuer.go` `fillTemplate`                           | `certutil.HasOCSPNoCheck(template)` inspects `Extensions`, never populated on a template   | correctness | Open           |
| XPKI-057 | authority                 | `config.go` `AllowedProfiles`                        | Only filters wildcard (`issuer_label: "*"`) profiles, contrary to the field doc            | correctness | Needs Approval |
| XPKI-058 | authority                 | `config.go` `IssuerConfig.Type`                      | No json/yaml tag; `type:` in YAML is silently dropped                                      | bug         | Open           |
| XPKI-059 | csr                       | `csr.go` `SetSAN`, `csrprov.go` `SignRequest`        | No SAN dedupe or DNS validation; `nil` keeps CSR SANs but empty slice clears them (undocumented) | correctness | Open       |
| XPKI-060 | csr                       | `types.go` `ParseObjectIdentifier`                   | Unanchored regex recompiled per call                                                       | correctness | Open           |
| XPKI-061 | csr                       | `csrprov.go` `DefaultSigAlgo`, `keyreq.go` `SigAlgo` | Fall back to `SHA1WithRSA`/`ECDSAWithSHA1`, which `x509.CreateCertificate` rejects         | correctness | Open           |
| XPKI-062 | testca                    | `configuration.go` `cnCounter`, `entity.go` `NextSN` | Package-global counters incremented without synchronization                                | race        | Open           |
| XPKI-063 | testca                    | `utils.go` `ToPFX`/`ToPKCS8`                         | Shell out to `openssl` and panic; stdlib `x509.MarshalPKCS8PrivateKey` covers PKCS#8       | correctness | Open           |
| XPKI-064 | testca                    | `mkcert.go` `MakeSelfCertRSA`                        | 1024-bit RSA depends on the `rsa1024min` GODEBUG default                                   | correctness | Open           |
| XPKI-065 | authority (testdata)      | `testdata/csrprofiles/*.yaml`                        | Uppercase `C:`/`L:`/`O:` keys do not match lowercase `csr.X509Name` yaml tags; subject silently dropped | correctness | Open |
| XPKI-066 | jwt                       | `jwt.go` `NewProviderWithSymmetricKey`               | Provider signs without `kid` and has empty `keys`, so it cannot verify its own tokens      | bug         | Open           |
| XPKI-067 | jwt                       | `claims.go` `MapClaims.Int`/`UInt64`/`Int64`         | Silent overflow/sign wrap; `json.Number` errors ignored                                    | correctness | Open           |
| XPKI-068 | jwt                       | `claims.go` `NumericDate.UnmarshalJSON`              | Rejects fractional seconds allowed by RFC 7519; doc says values are rounded                | correctness | Open           |
| XPKI-069 | jwt                       | `parser.go` `ParseWithClaims`                        | Claims validated before the signature is verified                                          | correctness | Open           |
| XPKI-070 | jwt                       | `jwks.go` `RemoteKeySet.updateKeys`/`GetKey`         | `http.DefaultClient` without timeout, unbounded body, refresh on every unknown `kid`; a stalled JWKS endpoint blocks all cache misses | security | Open |
| XPKI-071 | jwt                       | `jwks.go` `StaticKeySet.GetKey`/`RemoteKeySet.GetKey`| Empty `kid` returns the first JWK regardless of `kty`/`use`                                | correctness | Open           |
| XPKI-072 | jwt                       | `jwks.go` `StaticKeySet.PublicKeys`                  | Field documented but never read                                                            | bug         | Open           |
| XPKI-073 | jwt                       | `sign.go` `signJWT`                                  | `jti` placed in the JOSE header (non-standard)                                             | correctness | Open           |
| XPKI-074 | jwt/dpop                  | `verify.go` `supportedSignatureAlgorithm`            | PS256/384/512 and EdDSA allowed but `jwt.VerifySignature` cannot verify them               | correctness | Open           |
| XPKI-075 | jwt/dpop                  | `verify.go` `VerifyClaims`                           | No `jti` replay protection and no `ath` binding although the doc lists both as MUST        | security    | Needs Approval |
| XPKI-076 | jwt/dpop                  | `verify.go` `VerifyRequestClaims`                    | Scheme always defaults to `https`; `htu` compared with `EqualFold` (path is case-sensitive) | correctness | Open          |
| XPKI-077 | jwt/accesstoken           | `accesstoken.go` `SetRevocation`                     | Not forwarded to the wrapped `jwt.Provider`; revoked plain JWTs are accepted               | correctness | Open           |
| XPKI-078 | jwt/accesstoken           | `accesstoken.go` `Sign`                              | `pat.` tokens get no `exp`; they never expire and `TokenExpiry()` is ignored               | security    | Needs Approval |
| XPKI-079 | jwt/accesstoken           | `accesstoken.go` `PublicKey`                         | Dereferences `p.dp` without nil check                                                      | bug         | Open           |
| XPKI-080 | jwt/oauth2client          | `client.go`, `config.go`                             | `verifyKey` written but never read; `JwksURL` unused; setters mutate shared state unsynchronized | correctness | Open       |
| XPKI-081 | jwt/oauth2client          | `provider.go` `RegisterClient`                       | Mutates registry maps without a lock                                                       | race        | Open           |
| XPKI-082 | jwt/oauth2client          | `provider.go` `ClientForEmail`                       | Address without `@` is looked up as a domain                                               | correctness | Open           |
| XPKI-083 | dataprotection            | `symmetric.go` `NewSymmetric`/`Protect`              | AES-GCM 96-bit random nonce with no rotation hook; HKDF over possibly low-entropy secret; limits undocumented | docs | Open   |
| XPKI-084 | cmd/hsm-tool              | `cli/cli.go` `CryptoProv`                            | Uses `logger.Panicf` on config errors; bad `--cfg` produces a stack trace and rc=2         | bug         | Open           |
| XPKI-085 | cmd/hsm-tool              | `cli/hsm.go` `HsmInfoCmd`/`HsmRmCmd`                 | `--token` flag declared but never read; only `--serial` filters                            | correctness | Open           |
| XPKI-086 | cmd/hsm-tool              | `cli/hsm.go` `HsmInfoCmd`/`HsmRmCmd`                 | No matching token → silent no-op with rc=0                                                 | correctness | Open           |
| XPKI-087 | cmd/hsm-tool              | `cli/csr.go` `GenCert`/`Sign`                        | `ParseFromPEM`/`EncodeToPEMString` errors discarded; corrupted output with rc=0            | correctness | Open           |
| XPKI-088 | cmd/xpki-tool             | `cli/ocsp.go` `OCSPInfoCmd`                          | `--issuer` flag never used; response signature is not verified                             | correctness | Open           |
| XPKI-089 | cmd/xpki-tool             | `cli/crl.go` `CRLFetchCmd`                           | `--output` is `required` yet the code has a print-only mode                                | correctness | Open           |
| XPKI-090 | cmd/xpki-tool             | `cli/certs.go` `CertInfoCmd`                         | `EncodeToPEM` and `Close` errors swallowed for `--out`                                     | correctness | Open           |
| XPKI-091 | cmd/xpki-tool             | `cli/ocsp.go` `OCSPFetchCmd`                         | Certificate without OCSP URL: no output, rc=0 (log level is forced to ERROR)               | correctness | Open           |
| XPKI-092 | cmd/xpki-tool             | `cli/crl.go`, `cli/ocsp.go`                          | `path.Join` used for filesystem paths                                                      | correctness | Open           |
| XPKI-093 | scripts                   | `config-softhsm.sh`                                  | Unreachable second `*)` arm; duplicate spy-module path; hard-coded macOS Cellar paths; no `set -euo pipefail`; PIN file written with default umask | bug | Open |
| XPKI-094 | CI                        | `.github/workflows/unittest.yml` `UnitTest`          | Job not gated on `detect-noop` output; the skip step never skips anything                  | bug         | Needs Approval |
| XPKI-095 | CI                        | `.github/workflows/unittest.yml`, `Makefile`         | Lint and govulncheck installed but never run; `make fmt` mutates the checkout instead of `fmt-check` | correctness | Needs Approval |
| XPKI-096 | build                     | `Makefile` `tools`                                   | Tools installed `@latest`; a golangci-lint major bump can break `.golangci.yaml`           | correctness | Open           |
| XPKI-097 | build                     | `internal/version/current.go`, `Makefile` `version`  | Tracked generated file is stale (`v0.2.76`); `make version` not wired into `build`/`all`/CI | bug        | Open           |
| XPKI-098 | build                     | `docker-compose.yml`                                 | Obsolete `version:`; fixed subnet is a public range; `local-kms` image untagged            | correctness | Open           |
| XPKI-099 | tests                     | `cryptoprov/provider_test.go` `Test_Aws`/`Test_Gcp`  | Empty stubs; `gcpkmscrypto.EnumKeys` untested; `certutil.TestKeyInfoKMS` needs live KMS   | docs        | Open           |
| XPKI-100 | tests                     | crypto11, cryptoprov, csr, authority, jwt, cmd suites | Integration tests fail hard (some via `TestMain` panic) instead of skipping when SoftHSM or local-kms is absent | docs | Open |
| XPKI-101 | tests                     | `cmd/hsm-tool/cli/hsm_cli_test.go`                    | Shared kong parser across `Parse` calls masks the `--cfg` required check                    | docs        | Open           |

## Notes on items needing approval

- **XPKI-036 / XPKI-038** change exported return values (`Bundle` returning an
  error for empty input; `SortBundlesByExpiration` returning a copy).
- **XPKI-049** is the most important open item. The safe rule is to build
  `safeTemplate` from an explicit field list and treat an empty
  `allowed_extensions` as deny-all, but that rejects CSRs that today issue
  successfully; profiles in deployed configs must be checked first.
- **XPKI-054 / XPKI-057** tighten policy in ways that may reject requests
  from existing RA integrations.
- **XPKI-075 / XPKI-078** require new API surface (`ath`/replay cache in
  `dpop.VerifyConfig`; expiry policy for `pat.` tokens).
- **XPKI-094 / XPKI-095** change what CI runs; enabling lint in CI will fail
  until the remaining `gosec`/`gocritic` style findings are triaged.
