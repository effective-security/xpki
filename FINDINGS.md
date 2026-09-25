# FINDINGS

Actionable bugs, security issues, correctness problems, and verified fixes.

Use the **ID** when commenting or assigning work. Update **Status** in the
same change as the code or decision. Retain completed items with status
**Fixed** and record the completion date, batch, change summary, and actual
validation under **Fixed items**. Update `PLAN.md` at the same time when it is
present, including when it is ignored by Git. Mark a finding Fixed only when
all linked package portions are implemented and verified.
IDs are never reused; existing gaps reflect historical removals.

## Status

| Status         | Meaning                                                |
| -------------- | ------------------------------------------------------ |
| Open           | Not started                                            |
| In Progress    | Being fixed                                            |
| Needs Approval | Behavior or compatibility change that needs a decision |
| Fixed          | All finding portions implemented and verified          |

Type: **security** > **bug** > **race** > **correctness** > **performance** > **docs**.

Severity: **CRITICAL** > **HIGH** > **MEDIUM** > **LOW**.

Line numbers refer to the tree at the time of the audit (2026-09-20) and may
drift; the symbol name is the stable reference.

## Index

| ID       | Package                               | Location                                                       | Title                                                                                                                                              | Severity    | Status         |
| -------- | ------------------------------------- | -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | -------------- |
| XPKI-001 | crypto11                              | `crypto11.go` `PKCS11Lib.Close`                                | `Destroy()` runs before `Finalize()`, so C_Finalize never runs and pool sessions leak                                                              | bug         | Open           |
| XPKI-002 | crypto11                              | `sessions.go` `withSession`                                    | `sessionPools` map read without `sessionPoolMutex` while `setupSessions` writes                                                                    | race        | Open           |
| XPKI-003 | crypto11                              | `sessions.go` `withSession`                                    | Slot without a pool blocks forever on the nil channel (doc says "panic")                                                                           | bug         | Open           |
| XPKI-005 | crypto11                              | `sessions.go` `withSession`                                    | Unbounded session opening; sessions never closed; return blocks once pool (1024) is full                                                           | performance | Open           |
| XPKI-006 | crypto11                              | `config.go` `Init` token match                                 | Empty configured `TokenSerial`/`TokenLabel` matches any token with the empty field                                                                 | correctness | Open           |
| XPKI-007 | crypto11                              | `config.go` `Init`                                             | Loaded module (`pkcs11.New`) leaks on every error path after load                                                                                  | bug         | Open           |
| XPKI-011 | crypto11                              | `common.go` `BytesToUlong`                                     | Panics on empty input and reads out of bounds on short attribute values                                                                            | bug         | Open           |
| XPKI-016 | cryptoprov                            | `provider.go` `Crypto.Add`/`ByManufacturer`                    | No synchronization; duplicate check in `Add` is unreachable (key already includes model)                                                           | race        | Open           |
| XPKI-017 | cryptoprov/inmemcrypto, testprov      | `provider.go` `keyIDToPvk`                                     | Key map written by `Generate*` and read by `GetKey` without a lock (used by `authority/ocsp.go`)                                                   | race        | **Fixed** ([details](#xpki-017--im1)) |
| XPKI-018 | cryptoprov/gcpkmscrypto               | `gcpkmsprov.go` `Close`                                        | Sets embedded `KmsClient` to nil unsynchronized; later `Sign` panics                                                                               | race        | Open           |
| XPKI-019 | cryptoprov/gcpkmscrypto               | `gcpkmsprov.go` `GenerateRSAKey`                               | `purpose==2` sets ASYMMETRIC_DECRYPT with a SIGN algorithm; 4096-bit forces SHA512 while `Sign` picks digest from opts                             | correctness | Open           |
| XPKI-020 | cryptoprov/gcpkmscrypto               | `gcpkmsprov.go` `GetKey`, `keyVersionName`, `ExportKey`        | `cryptoKeyVersions/1` hard-coded; rotated keys sign/destroy the wrong version                                                                      | correctness | Open           |
| XPKI-021 | cryptoprov/gcpkmscrypto               | `gcpkmsprov.go` `Init`                                         | `Endpoint` attribute parsed but never applied to the client                                                                                        | correctness | Open           |
| XPKI-022 | cryptoprov/gcpkmscrypto               | `gcpkmsprov.go` `KeyLabelAndID`                                | 4 hex chars of entropy (65k) and no label sanitisation; ALREADY_EXISTS / INVALID_ARGUMENT                                                          | correctness | Open           |
| XPKI-023 | cryptoprov/gcpkmscrypto               | `gcpkmsprov.go` `keyInfo`, `signer.go` `Sign`                  | Direct proto field access (`VersionTemplate`, `SignatureCrc32C`) may nil-deref                                                                     | bug         | Open           |
| XPKI-024 | cryptoprov/gcpkmscrypto               | `gcpkmsprov.go` `genKey`                                       | Up to 60 s blocking `time.Sleep` poll ignoring ctx; matches error by substring                                                                     | performance | Open           |
| XPKI-025 | cryptoprov/awskmscrypto, gcpkmscrypto | `signer.go` `Sign`                                             | `opts == nil` → nil interface method call panic (`inmemcrypto` defaults to SHA256)                                                                 | bug         | Open           |
| XPKI-026 | cryptoprov                            | `provider.go` `New`                                            | `New(nil, ...)` panics on `defaultProvider.Manufacturer()`                                                                                         | bug         | Open           |
| XPKI-027 | cryptoprov                            | `uri.go` `ParseTokenURI`/`ParsePrivateKeyURI`                  | RFC 7512 `?pin-value=`/`?module-path=` query attributes are dropped                                                                                | correctness | Open           |
| XPKI-031 | cryptoprov/awskmscrypto               | `awskmsprov.go` `GenerateRSAKey`                               | `purpose==2` creates ENCRYPT_DECRYPT key but returns a `Signer`; no `crypto.Decrypter`                                                             | correctness | Open           |
| XPKI-032 | cryptoprov/awskmscrypto               | `awskmsprov.go` `EnumKeys`                                     | Lists every key in the account then one `DescribeKey` per key (N+1); `prefix` ignored                                                              | performance | Open           |
| XPKI-033 | cryptoprov/awskmscrypto               | `awskmsprov.go` `EnumKeys`                                     | `DescribeKey` errors logged and skipped; throttled keys vanish from listings                                                                       | correctness | Open           |
| XPKI-034 | cryptoprov/awskmscrypto               | `awskmsprov.go` `Init`                                         | Env credentials forced into a static provider; redundant with SDK chain, non-refreshable                                                           | correctness | Open           |
| XPKI-035 | certutil                              | `bundler.go` `verifyChain`/`fetchIntermediates`                | `Bundler` mutates `KnownIssuers` and `IntermediatePool` per call; concurrent `Bundle` panics                                                       | race        | Open           |
| XPKI-036 | certutil                              | `bundler.go` `Bundler.Bundle`                                  | Empty cert list returns `(nil, nil)`                                                                                                               | bug         | Needs Approval |
| XPKI-037 | certutil                              | `bundler.go` `fetchRemoteCertificate`                          | AIA fetch: no status check, unbounded `io.ReadAll`, no context, body logged in full                                                                | security    | **Fixed** ([details](#xpki-037--cu1)) |
| XPKI-038 | certutil                              | `bundle.go` `SortBundlesByExpiration`                          | Sorts the caller's slice in place with unstable `sort.Slice`                                                                                       | correctness | Needs Approval |
| XPKI-039 | certutil                              | `bundler.go` `fetchIntermediates`                              | `seen[url]` set only on success; failing AIA URLs re-fetched each iteration                                                                        | performance | **Fixed** ([details](#xpki-039--cu1)) |
| XPKI-041 | certutil                              | `bundler.go` `NewBundler`                                      | No roots + `WithBundleFlavor(Optimal)` leaves `RootPool` nil, so `x509.Verify` trusts system roots                                                 | security    | **Fixed** ([details](#xpki-041--cu1)) |
| XPKI-042 | certutil                              | `bundle.go` `BuildBundle`                                      | Dereferences `c.Status`/`c.Cert` without nil checks                                                                                                | bug         | Open           |
| XPKI-043 | certutil                              | `pem.go` `ParsePrivateKeyPEMWithPassword`                      | PKCS#8 `ENCRYPTED PRIVATE KEY` unsupported; falls through to an opaque error; doc claims support                                                   | correctness | Open           |
| XPKI-044 | certutil                              | `bundler.go` `HTTPClient`                                      | Exported global documented as used for all HTTP requests but never read                                                                            | docs        | **Fixed** ([details](#xpki-044--cu1)) |
| XPKI-045 | certutil                              | `bundle.go` `ExpiresInHours`                                   | Doc says "rounded up"; integer division truncates                                                                                                  | docs        | Open           |
| XPKI-047 | armor                                 | `armor.go` `Decode`                                            | CRC24 trailer mandatory; RFC 9580 requires accepting armor without it                                                                              | correctness | Open           |
| XPKI-049 | authority                             | `issuer.go` `Sign` (`safeTemplate = *requesterCsrTemplate`)    | All CSR `ExtraExtensions` (KU/EKU/SAN/…) copied into the template; empty `AllowedExtensions` allows every OID                                      | security    | **Fixed** ([details](#xpki-049--au1)) |
| XPKI-050 | authority                             | `issuer.go` `Sign` profile extensions                          | Profile `Extensions` appended without dedupe against CSR extensions; `CreateCertificate` output then fails to parse                                | correctness | **Fixed** ([details](#xpki-050--au1)) |
| XPKI-051 | authority                             | `ocsp.go` `CreateDelegatedOCSPSigner`                          | Holds `ca.lock` then calls `ca.Sign` → `ca.Profile` → `RLock`: deadlock when `delegated_ocsp_profile` is set                                       | bug         | **Fixed** ([details](#xpki-051--au2)) |
| XPKI-052 | authority                             | `ocsp.go` `SignOCSP` non-delegated branch                      | `ca.responder` read/written without the lock                                                                                                       | race        | **Fixed** ([details](#xpki-052--au2)) |
| XPKI-053 | authority                             | `ocsp.go` `SignOCSP`                                           | Fallback `responder = ca.responder` may be nil → `responder.Cert` panics                                                                           | bug         | **Fixed** ([details](#xpki-053--au2)) |
| XPKI-054 | authority                             | `issuer.go` `Sign`/`fillTemplate`                              | `SignRequest.NotBefore/NotAfter` not bounded by profile expiry; inverted range not rejected                                                        | correctness | **Fixed** ([details](#xpki-054--au1)) |
| XPKI-055 | authority                             | `authority.go` maps                                            | `Authority` maps and `Issuer.Profiles()` live map have no synchronization                                                                          | race        | Open           |
| XPKI-057 | authority                             | `config.go` `AllowedProfiles`                                  | Only filters wildcard (`issuer_label: "*"`) profiles, contrary to the field doc                                                                    | correctness | **Fixed** ([details](#xpki-057--au1)) |
| XPKI-058 | authority                             | `config.go` `IssuerConfig.Type`                                | No json/yaml tag; `type:` in YAML is silently dropped                                                                                              | bug         | Open           |
| XPKI-059 | csr                                   | `csr.go` `SetSAN`, `csrprov.go` `SignRequest`                  | No SAN dedupe or DNS validation; `nil` keeps CSR SANs but empty slice clears them (undocumented)                                                   | correctness | Open           |
| XPKI-062 | testca                                | `configuration.go` `cnCounter`, `entity.go` `NextSN`           | Global common-name and per-issuer serial counters incremented without synchronization                                                               | race        | **Fixed** ([details](#xpki-062--tc1)) |
| XPKI-063 | testca                                | `utils.go` `ToPFX`/`ToPKCS8`                                   | Shell out to `openssl` and panic; stdlib `x509.MarshalPKCS8PrivateKey` covers PKCS#8                                                               | correctness | Open           |
| XPKI-066 | jwt                                   | `jwt.go` `NewProviderWithSymmetricKey`                         | Provider signs without `kid` and has empty `keys`, so it cannot verify its own tokens                                                              | bug         | Open           |
| XPKI-070 | jwt                                   | `jwks.go` `RemoteKeySet.updateKeys`/`GetKey`                   | `http.DefaultClient` without timeout, unbounded body, refresh on every unknown `kid`; a stalled JWKS endpoint blocks all cache misses              | security    | **Fixed** ([details](#xpki-070--jw1)) |
| XPKI-071 | jwt                                   | `jwks.go` `StaticKeySet.GetKey`/`RemoteKeySet.GetKey`          | Empty `kid` returns the first JWK regardless of `kty`/`use`                                                                                        | correctness | **Fixed** ([details](#xpki-071--jw1)) |
| XPKI-072 | jwt                                   | `jwks.go` `StaticKeySet.PublicKeys`                            | Field documented but never read                                                                                                                    | bug         | **Fixed** ([details](#xpki-072--jw1)) |
| XPKI-073 | jwt                                   | `sign.go` `signJWT`                                            | `jti` placed in the JOSE header (non-standard)                                                                                                     | correctness | Open           |
| XPKI-074 | jwt/dpop                              | `verify.go` `supportedSignatureAlgorithm`                      | PS256/384/512 and EdDSA allowed but `jwt.VerifySignature` cannot verify them                                                                       | correctness | **Fixed** ([details](#xpki-074--dp1)) |
| XPKI-075 | jwt/dpop                              | `verify.go` `VerifyClaims`                                     | No `jti` replay protection and no `ath` binding although the doc lists both as MUST                                                                | security    | **Fixed** ([details](#xpki-075--dp1)) |
| XPKI-076 | jwt/dpop                              | `verify.go` `VerifyRequestClaims`                              | Scheme always defaults to `https`; `htu` compared with `EqualFold` (path is case-sensitive)                                                        | correctness | **Fixed** ([details](#xpki-076--dp1)) |
| XPKI-078 | jwt/accesstoken                       | `accesstoken.go` `Sign`                                        | `pat.` tokens get no `exp`; they never expire and `TokenExpiry()` is ignored                                                                       | security    | **Fixed** ([details](#xpki-078--at1)) |
| XPKI-079 | jwt/accesstoken                       | `accesstoken.go` `PublicKey`                                   | Dereferences `p.dp` without nil check                                                                                                              | bug         | **Fixed** ([details](#xpki-079--at1)) |
| XPKI-080 | jwt/oauth2client                      | `client.go`, `config.go`                                       | `verifyKey` written but never read; `JwksURL` unused; setters mutate shared state unsynchronized                                                   | correctness | Open           |
| XPKI-081 | jwt/oauth2client                      | `provider.go` `RegisterClient`                                 | Mutates registry maps without a lock                                                                                                               | race        | Open           |
| XPKI-083 | dataprotection                        | `symmetric.go` `NewSymmetric`/`Protect`                        | AES-GCM 96-bit random nonce with no rotation hook; HKDF over possibly low-entropy secret; limits undocumented                                      | docs        | Open           |
| XPKI-084 | cmd/hsm-tool                          | `cli/cli.go` `CryptoProv`                                      | Uses `logger.Panicf` on config errors; bad `--cfg` produces a stack trace and rc=2                                                                 | bug         | Open           |
| XPKI-093 | scripts                               | `scripts/config-softhsm.sh`, `Makefile`                        | SoftHSM setup: flag/module handling, failure propagation, PIN security, and verification without required OpenSC                                  | bug         | **Fixed** ([details](#xpki-093--sc1)) |
| XPKI-094 | CI                                    | `.github/workflows/unittest.yml` `UnitTest`                    | Job not gated on `detect-noop` output; the skip step never skips anything                                                                          | bug         | Needs Approval |
| XPKI-095 | CI                                    | `.github/workflows/unittest.yml`, `Makefile`                   | Lint and govulncheck installed but never run; `make fmt` mutates the checkout instead of `fmt-check`                                               | correctness | Needs Approval |
| XPKI-096 | build                                 | `Makefile` `tools`                                             | Tools installed `@latest`; a golangci-lint major bump can break `.golangci.yaml`                                                                   | correctness | Open           |
| XPKI-097 | build                                 | `internal/version/current.go`, `Makefile` `version`            | Tracked generated file is stale (`v0.2.76`); `make version` not wired into `build`/`all`/CI                                                        | bug         | Open           |
| XPKI-098 | build                                 | `docker-compose.yml`                                           | Obsolete `version:`; fixed subnet is a public range; `local-kms` image untagged                                                                    | correctness | Open           |
| XPKI-099 | tests                                 | `cryptoprov/provider_test.go` `Test_Aws`/`Test_Gcp`            | Empty stubs; `certutil.TestKeyInfoKMS` needs live KMS                                                                                              | docs        | Open           |
| XPKI-100 | tests                                 | crypto11, cryptoprov, csr, authority, jwt, cmd suites          | Integration tests fail hard (some via `TestMain` panic) instead of skipping when SoftHSM or local-kms is absent                                    | docs        | In Progress ([authority portion](#xpki-100-authority--au2)) |
| XPKI-101 | tests                                 | `cmd/hsm-tool/cli/hsm_cli_test.go`                             | Shared kong parser across `Parse` calls masks the `--cfg` required check                                                                           | docs        | Open           |
| XPKI-102 | cmd/xpki-tool/cli                     | `ocsp.go` `OCSPFetchCmd.Run`                                   | All OCSP endpoint failures are printed but the command returns success                                                                             | correctness | Open           |
| XPKI-103 | certutil, cmd/xpki-tool/cli           | `ocsp.go` `CreateOCSPRequest`, `certs.go` `OCSPValidation`     | Nil issuer certificate panics instead of returning an input error                                                                                  | bug         | Open           |
| XPKI-104 | jwt                                   | `jwt.go` `NewProviderWithSymmetricKey`                         | Applying nonempty `WithHeaders` panics because the constructor leaves `headers` nil                                                                | bug         | Open           |
| XPKI-105 | tests                                 | `cmd/xpki-tool/cli/suite_test.go` `SetupSuite`               | Fixed temporary directory is removed by concurrent coverage/race runs, causing missing fixture files                                               | bug         | **Fixed** ([details](#xpki-105--xc2)) |
| XPKI-106 | dataprotection                        | `symmetric_test.go` `TestNewSymmetric`                         | Tamper test copies one random nonce byte over another; equal bytes leave the ciphertext unchanged and make the authentication-failure assertion flaky | bug         | Open           |
| XPKI-107 | testca                                | `entity.go` `Issue`                                           | Appending the issuer overwrites caller option-slice storage when capacity remains and races when the slice is reused concurrently                      | race        | **Fixed** ([details](#xpki-107--tc1)) |
| XPKI-108 | jwt/dpop                              | `verify.go` `VerifyClaimsContext`                              | `htm` is compared with `strings.EqualFold`, although HTTP methods are case-sensitive (RFC 9110 §9.1), so a proof for `get` is accepted for `GET` | correctness | Open           |
| XPKI-109 | jwt                                   | `claims.go` `MapClaims.Time`; `jwt.go` `Sign`                  | A `time.Time` `iat`/`nbf`/`exp` passed to `Sign` marshals to an RFC 3339 string that `Time` cannot parse, so `Valid` silently skips that check (a `nbf` tomorrow is accepted now) | correctness | Needs Approval |

## Fixed items

### XPKI-051 — AU2

**Fixed on 2026-09-25.** `CreateDelegatedOCSPSigner` held `ca.lock` while
`Sign` → `Profile` took the same lock for reading. As a result, `NewIssuer`
deadlocked for every issuer with `aia.delegated_ocsp_profile`, and a
delegated responder was never issued. Responder coordination now has its own
`Issuer.renewLock`, and `ca.lock` guards only `cfg.Profiles`. The lock order,
documented on `Issuer` and in the codemap, is `renewLock` → `lock`; nothing
acquires `renewLock` while holding `lock`. Issuance moved to
`newDelegatedResponder`, with the key, profile and CSR unchanged.

Validation:

- Before the fix, a temporary test (fresh `CreateIssuer` with a delegated
  profile, `CreateDelegatedOCSPSigner` in a goroutine with a 3s deadline)
  failed with `CreateDelegatedOCSPSigner deadlocked`.
- `TestDelegatedOCSPFreshCreation`, `TestDelegatedOCSPFreshSignOCSP`
  (deadline-bounded) and `TestNewIssuerDelegatedOCSP` (from files, through
  `NewIssuer`) now pass. They check the responder's EKU, OCSP no-check, the
  absence of AIA/CRL URLs, the CA signature, key identity and reuse, and parse
  and verify the resulting OCSP response. `TestDelegatedOCSPConcurrentRenewal`
  overlaps `AddProfile` with renewal.

### XPKI-052 — AU2

**Fixed on 2026-09-25.** `ca.responder` was written lazily without a lock
in the non-delegated branch and read by `SignOCSP`. Now `caResponder`
(the CA key and certificate) is built once in `CreateIssuer` and never
written again. The delegated responder is an immutable snapshot published
through `atomic.Pointer`. A lookup with a fresh responder takes no lock. A
responder that expires within `ocsp_expiry` is renewed by one caller: others
holding a still-valid responder keep using it (`TryLock`), and callers
without one wait and then re-check. The per-lookup DEBUG log was removed.

Validation:

- Before the fix, 8 goroutines calling `SignOCSP` on a cold non-delegated
  issuer in a HEAD worktree failed under `go test -race` with data races at
  `ocsp.go:162-165` (the `ca.responder` initialization).
- `go test ./authority -race -count=20 -run 'OCSP|Responder'` passed.
  `TestDelegatedOCSPConcurrentColdStart` (32 goroutines released together)
  and `TestDelegatedOCSPConcurrentRenewal` (32 goroutines plus `AddProfile`)
  assert exactly one CA signature, a verified response for every caller, and
  a responder that is the old or the new one. `TestCAResponderConcurrent`
  covers the CA-key path.
- Benchmark (`BenchmarkSignOCSP`, `-count=6 -cpu=1,4`, benchstat, HEAD
  worktree baseline, same host): delegated warm lookup 264 → 37 ns serial and
  258 → 9.7 ns on 4 CPUs (p=0.002), 152 B / 4 allocs → 0. Delegated
  `SignOCSP` 885.6 → 875.0 µs serial (−1.2%, p=0.004), 235 → 231 µs on 4
  CPUs (not significant), 208 → 204 allocs. CA-key sign unchanged (p≥0.07),
  CA lookup 2.5 → 1.7 ns. Cold start and renewal have no baseline, because
  that path deadlocked. `BenchmarkDelegatedOCSPCreate` (issuance, i.e. the
  cost of a cold start or renewal) measures 318 µs, 46 KiB and 660 allocs.

### XPKI-053 — AU2

**Fixed on 2026-09-25.** Approved policy: keep serving from a still-valid
cached responder, otherwise return an error. `SignOCSP` never dereferences a
missing responder and never falls back to the CA key when delegation is
configured.

- When renewal fails and the cached delegated responder is valid at signing
  time, `SignOCSP` logs the error (`delegated_ocsp_renewal`) and uses it. No
  new attempt is made for `ocspRenewRetryInterval` (1 minute).
- With no valid responder (none cached, or expired), `SignOCSP` returns
  `delegated OCSP responder is not available: …` wrapping the cause, and no
  response. Every such request retries issuance.
- `CreateDelegatedOCSPSigner` waits for a renewal in progress and, while
  renewal is overdue, returns the last renewal error, even while a cached
  responder is still valid. It retries at most once per interval.
- Callers that queued for the renewal lock while an attempt failed share that
  error instead of each retrying (N queued requests used to mean N CA
  signatures back to back). With no valid responder, a new request after
  the failure retries.
- Within the retry interval, `SignOCSP` with a valid cached responder takes
  no lock: the last outcome (`ocspRenewal`) is an atomic snapshot.
- `CreateIssuer` rejects a `delegated_ocsp_profile` that is missing, lacks
  the `ocsp signing` usage (or an explicit EKU extension), or whose expiry is
  not longer than `ocsp_expiry`. Such a profile would otherwise issue a
  responder that is due for renewal the moment it is issued.
- Delegated responses cap `NextUpdate` at the responder's `NotAfter`. A
  `ThisUpdate` at or after `NotAfter` fails with `delegated OCSP responder
  expires at …`.
- When the CA expires within `ocsp_expiry`, `Sign` caps the responder at the
  CA's `NotAfter`, so it is due for renewal as soon as it is issued. It logs
  `delegated_ocsp_short_lived` and is not re-issued within the retry
  interval. Without this, every request would issue a new certificate.

Before the fix, the nil dereference could only be reached through a CSR
generation failure. Any `Sign` failure first hit the XPKI-051 deadlock, so no
separate pre-fix panic reproduction was possible.

Validation: `TestDelegatedOCSPRenewalFailureUsesValidCache` (a failing
`countingSigner` as the CA key; exact error, `errors.Is`, attempt counts
across the retry interval, capped `NextUpdate`, recovery),
`TestDelegatedOCSPFailureWithoutValidResponder` (none cached and expired
cache: error, nil response, no panic), `TestDelegatedOCSPResponderClipsNextUpdate`,
`TestDelegatedOCSPShortLivedResponderIsNotReissued` (a CA expiring within
`ocsp_expiry`), `TestDelegatedOCSPWaitersShareFailure` (a gated failing
signer with 32 queued requests: one CA signature, every request gets the
error) and `TestCreateIssuerDelegatedOCSPProfile`.

A `/code-review` pass found the fixes above: no failure sharing for queued
callers, short-lived profiles re-issued every minute, `TryLock` taken on every
request during the retry window, and an inconsistent
`CreateDelegatedOCSPSigner` error. It also found duplicated checks, now
`validAt`/`validFor`, and the delegated `NextUpdate` cap sitting outside the
delegation branch. With the shared-failure case disabled,
`TestDelegatedOCSPWaitersShareFailure` saw 33 CA signatures instead of 1.
`BenchmarkDelegatedOCSPRetryWindow` compared the lock-free retry window with
`TryLock` on every call (`-count=6`, benchstat, p=0.002): 52.6 → 40.3 ns
serial and 47.8 → 10.5 ns on 4 CPUs, 0 allocs. One review item was not
applied: rejecting a caller `ThisUpdate` earlier than the responder's
`NotBefore`. RFC 6960 does not require it, `x/crypto/ocsp` does not check it,
and it would add failures after every renewal for callers re-signing with an
earlier `ThisUpdate`. `ocsp.go` statement coverage: `SignOCSP`,
`CreateDelegatedOCSPSigner`, `validateDelegatedOCSPProfile` 100%;
`delegatedResponder` 97.7%, missing only the timing-dependent
valid-cache-after-shared-failure return; `newDelegatedResponder` 90.5%,
missing only the CSR-generation and signer-conversion errors.

PR #537 review follow-ups:

- A raw EKU extension in the profile overrides `usages`, so the validator now
  decodes it and requires `id-kp-OCSPSigning`. Before, the extension merely
  had to be present, so a raw `serverAuth` EKU or malformed bytes passed.
  `fillTemplate` also detects a responder from the effective EKU
  (`isOCSPSigningTemplate`), so a raw-EKU responder gets no OCSP/CRL URLs. A
  malformed raw EKU now fails `Sign` for any non-CA profile.
- `AddProfile` could replace the delegated profile after `CreateIssuer`
  validated it. `newDelegatedResponder` now validates the exact snapshot it
  signs with (`signWithProfile`) and fails before any CA signature. In-place
  mutation of a shared `*CertProfile` is still XPKI-055 (AU3).
- `TestDelegatedOCSPWaitersShareFailure` no longer relies on a 50 ms sleep:
  the test-only `renewWaitHook` counts every caller that has read the
  pre-failure state before the failure is released.
- Each fix was reverted in turn: `TestDelegatedOCSPRawEKUProfile`, the
  `EKU extension without ocsp signing`/`malformed EKU extension` cases of
  `TestCreateIssuerDelegatedOCSPProfile`, and
  `TestDelegatedOCSPReplacedProfileIsRevalidated` fail without their fix.
  The sleep-based waiter test did not flake in 900 local runs
  (`-race -count=300 -cpu=1,2,8`, 49 s); the hook-based one passed 900 runs
  in 3.5 s.

Second PR #537 review round:

- A failed attempt can block on the CA signer. The cached responder is now
  judged valid, and the retry interval started, at `now` plus the attempt's
  measured duration. Before, a responder that expired during a slow failure
  was still returned. `TestDelegatedOCSPSlowFailureAfterExpiry` (a 100 ms
  gated failure straddling `NotAfter`) fails when judged at the start.
- The validator rejects CA profiles (`CAConstraint.IsCA`), so a typo cannot
  give the in-memory responder key a subordinate-CA certificate.
- `validityWindow` backdates NotBefore from the current minute, rounded, so a
  fresh responder lives expiry − backdate − up to 30s. At `expiry =
  ocsp_expiry + 1s` a scratch check found 55m15s left against a 1h interval,
  so the responder was due for renewal when issued. The bound is now `expiry
  > ocsp_expiry + backdate + 1m` (`effectiveBackdate`,
  `delegatedValidityMargin`). The shortest accepted expiry issues a
  responder that is not due for renewal. The duration-only bound fails the
  `expiry just above ocsp_expiry`, `expiry at the backdate bound` and
  `explicit backdate` cases.

Batch validation (AU2, all three findings plus the XPKI-100 authority
portion):

- `make lint` passed (fmt, vet, govulncheck, golangci-lint: 0 issues).
- `make test RACE=true TEST_FLAGS=-count=1` passed across the repository
  with SoftHSM and local-kms fixtures.
- `make build docs` regenerated `Documentation/api/authority.md` and the new
  `Documentation/api/internal_testenv.md`. `make covtest` passed at
  **91.2%** aggregate.

### XPKI-100-authority — AU2

**authority portion Fixed on 2026-09-25; XPKI-100 stays In Progress.**
Approved convention: the new test-only `internal/testenv` package.
`RequireTCP(t, name, addr)` runs the test when the fixture accepts a TCP
connection. When it does not, the test fails if `XPKI_INTEGRATION=required`
and is skipped otherwise. The Makefile exports `XPKI_INTEGRATION=required`,
so `make test`, `make covtest` and CI fail on a missing fixture. In
`authority`, only `TestNewRoot` generates a key in local-kms and is gated.
`TestShakenRoot` and `TestIssuerSign` now use `inmemcrypto`. Loading the
local-kms provider in `SetupSuite` does not connect, and SoftHSM was never
used (the codemap claim was stale).

Validation, with the `kms2` container (`:14556`) stopped and then restarted:

- `go test ./authority -count=1 -v` without the variable: only
  `TestAuthority/TestNewRoot` skipped (`local-kms is not reachable at
  localhost:14556 …`), and the package passed.
- With `XPKI_INTEGRATION=required`, `TestNewRoot` failed with `local-kms is
  required (XPKI_INTEGRATION=required) but not reachable …`.
- With a dummy HTTP server on the port (reachable but broken), `TestNewRoot`
  ran and failed. After the restart it passed in required mode.
- `go test ./internal/testenv -cover`: 100% (table over reachable/unreachable
  × unset/other/required, exact skip and fail messages).

Remaining XPKI-100 portions: PK1 (crypto11), CP1 (cryptoprov), AW1
(awskmscrypto), CS1 (csr), JW2 (jwt), CU4 (certutil) and HC1
(cmd/hsm-tool/cli). Use `internal/testenv`.

### XPKI-078 — AT1

**Fixed on 2026-09-25.** Approved policy: every new `pat.` token expires; a
caller-supplied `exp` is kept; lifetime is explicit, with no built-in
default; legacy perpetual tokens are rejected unless the caller opts in. New
API in `jwt/accesstoken`: variadic `New(dp, provider, opts ...Option)`,
`WithTokenExpiry(d)`, `WithAllowNoExpiry()` and the `TokenPrefix` constant.

- `Sign` works on a copy, so the caller's map is never modified. Present
  `exp`, `iat` and `nbf` claims are kept and normalized to a NumericDate, so
  `time.Time` values survive the JSON round trip (otherwise a future `nbf`
  was silently not enforced, XPKI-109); an unparsable or nil one fails with
  `invalid <claim> claim`. Without `exp`, it adds `exp = now +
  TokenExpiry()` and `iat`/`nbf` (`now + jwt.DefaultNotBefore`) when absent,
  using `jwt.TimeNowFn`.
- `TokenExpiry()` is now the effective lifetime: `WithTokenExpiry` if
  non-zero (a negative value is reported as 0), else the inner provider's
  `TokenExpiry`, else 0. If the result is not positive, `Sign` fails with
  `token expiry not configured` instead of issuing a perpetual token.
- `ParseToken` rejects a `pat.` token without `exp` with `exp claim not
  found`, and one with an unparsable `exp` with `invalid exp claim`.
  `WithAllowNoExpiry` accepts a token with no `exp` for migration, but still
  rejects an unparsable `exp` (such as a `time.Time` the old `Sign`
  marshaled to an RFC 3339 string), and revocation still applies. Plain JWTs
  still go to the inner provider unchanged.

Compatibility: `New(dp, nil).Sign` of claims without `exp` now fails until
`WithTokenExpiry` is set, and parsed claims now include the added
`exp`/`iat`/`nbf`. Tokens issued by older versions without `exp` are rejected
unless `WithAllowNoExpiry` is set. The existing `New(dp, provider)` calls
still compile.

Validation passed:

- Before the fix, on a HEAD worktree: with the 8h `jwtprov.json` inner
  provider, a token signed from `{"sub":"s"}` was still accepted by
  `ParseToken` with the clock set 100 years ahead (`err=<nil>
  claims=map[sub:s]`).
- After the fix: `TestSign_Expiry` covers option, inner provider, option over
  inner, zero option, not configured and negative expiry.
  `TestSign_CallerClaims` covers caller `exp` as int64, int, float64,
  `json.Number`, `time.Time`, `*time.Time` and a numeric string (kept, even a
  year past the lifetime, and no `iat`/`nbf` added), kept caller `iat`/`nbf`,
  invalid `exp`/`iat`/`nbf` values, a future `time.Time` `nbf` rejected on
  parse, and caller-map non-mutation.
  `TestParse_ExpiryBoundary` accepts the token at the `exp` instant and
  rejects it one second later. `TestParse_LegacyNoExpiry` covers default
  rejection, opt-in acceptance, revocation under the opt-in and unparsable
  `exp`, including a legacy RFC 3339 `exp`. `TestAT`/`TestATWithProvider` assert the exact added claims, and
  `ExampleNew` compiles the `doc.go` sample.
- `go test ./jwt/accesstoken -race -count=5`, `make test RACE=true`
  (SoftHSM and local-kms) and `make lint` (0 issues) passed. `make build
  docs` passed, and `make covtest` passed at **90.8%** aggregate
  (`jwt/accesstoken` 94.0%).
- A `/code-review` pass found that `Sign` normalized only `exp`: a
  `time.Time` `nbf` a day ahead was accepted at once. `iat`/`nbf` are now
  normalized too; with normalization limited to `exp`, the new
  `TestSign_CallerClaims` cases fail. The review also led to the accurate
  `invalid exp claim` error, the clamped negative `TokenExpiry()` and
  multi-line test tables. It found that the inner `jwt` provider has the same
  `time.Time` problem, recorded as XPKI-109. Review items contradicting the
  approved policy (capping a caller `exp`, rejecting an already-expired
  `exp`) were not applied.

### XPKI-079 — AT1

**Fixed on 2026-09-25.** A nil data protection provider is allowed by
`New`, whose signature is unchanged. `PublicKey` then returns nil, the same
as for a symmetric provider. It does not fall back to the inner provider's
key, because `pat.` tokens are not signed by it. `Sign`, and `ParseToken`
for `pat.` tokens, return `data protection not configured` instead of
panicking. Plain JWTs still go to the inner provider.

Validation passed:

- Before the fix, on a HEAD worktree: `accesstoken.New(nil,
  nil).PublicKey()` panicked with `invalid memory address or nil pointer
  dereference`.
- After the fix, `TestPublicKey` checks nil for a symmetric provider with
  and without an inner provider, and the exact key from a stub asymmetric
  provider. With a nil `dp`, with and without an inner provider, it checks
  a nil `PublicKey` and the exact `Sign` and `ParseToken` errors, and that
  a plain JWT still parses. `PublicKey` coverage went from 0% to 100%.
- The same repository race, lint, docs and coverage runs as XPKI-078.

### XPKI-075 — DP1

**Fixed on 2026-09-24.** Approved policy: an opt-in replay store, fail
closed when the in-memory store is full, and `ath`/`cnf.jkt` binding only
when the caller supplies the access token or thumbprint. New API in
`jwt/dpop`:

- `VerifyConfig.ReplayCache` (`ReplayCache` interface:
  `Add(ctx, key, expiresAt) error`, atomic, exactly one concurrent `Add` of a
  key may succeed). `VerifyClaims` records the proof **after** every other
  check passed, so a proof rejected for its signature, htu, time or nonce
  does not consume the jti. The key is base64url SHA-256 of the proof key
  thumbprint and jti: jti is scoped per client key and the stored key is 43
  bytes regardless of jti length. It is retained through `iat +
  DefaultExpiration`, or `exp` if earlier, inclusive, because the verifier
  still accepts the proof at that instant. A replay returns an error wrapping `ErrReplay`
  (`dpop: proof rejected: dpop: proof replayed`); a store error is wrapped
  the same way and also rejects. A nil cache keeps the old behavior and is
  documented as providing no replay detection.
- `NewMemoryReplayCache(max)`: a process-local store with one mutex, a map
  and an expiry min-heap. Expired entries are evicted on every `Add`; when
  the cache is still full, `ErrReplayCacheFull` rejects the proof. The
  default size is 100000. Because it fails closed, a client able to mint
  valid proofs (any client at a token endpoint) can fill it and have other
  proofs rejected for up to the acceptance window; the doc comment says to
  size it for peak load and rate-limit proof sources. Multi-instance servers need a shared
  implementation, for example Redis `SET NX` with an expiry.
- `VerifyConfig.AccessToken`: the proof must carry `ath` equal to
  `AccessTokenHash(token)` (base64url SHA-256, RFC 9449 §4.2), compared in
  constant time. Missing: `dpop: claim not found: ath`; different:
  `dpop: claim mismatch: ath`. Anyone holding the token can compute `ath`,
  so `AccessToken` without `ExpectedThumbprint` is rejected as `dpop:
  ExpectedThumbprint is required with AccessToken` (code review). Leave it empty at the token endpoint, where a
  present `ath` is ignored. `Result.AccessTokenHash` returns the claim.
- `VerifyConfig.ExpectedThumbprint`: the proof key thumbprint must equal the
  access token `cnf.jkt` (constant time), else `dpop: proof key does not
  match cnf.jkt`.
- `VerifyClaimsContext` passes a context to the store. `VerifyClaims` uses
  `context.Background()` and `VerifyRequestClaims` uses the request context.
- The signature is now verified before any claim is decoded (see XPKI-074).
  Claims and the compact protected header are decoded with go-jose's
  case-sensitive `json` fork, as `GetTokenInfo` and go-jose do, so `JTI`,
  `HTU` or `TYP` are not taken for `jti`, `htu` or `typ` (code review).
  Client jti grew from 8 to 22 characters (about 131 bits, RFC 9449 §4.2
  asks for at least 96), and `ClaimAccessTokenHash` names the claim for
  `ForRequest` extra claims.

Compatibility: existing callers compile and behave as before unless they set
the new fields. Legacy mode is not replay-safe.

Validation passed:

- Before the fix, a scratch test on a `git worktree` of HEAD verified the
  same proof twice with no error. There was no way to supply an access
  token. Code review of the first version reproduced, with a scratch test,
  a thief's key accepted with a computed `ath` and no `cnf.jkt`, upper-case
  `JTI`/`HTU` accepted, and a second `Add` succeeding at exactly
  `expiresAt`. All three are fixed and covered above.
- After the fix, `TestVerifyClaims_Replay` covers a nil cache accepting a
  replay, second use rejected (`errors.Is(err, ErrReplay)`), a new proof
  reusing a jti rejected, the same jti under another key accepted, a store
  error propagated through `VerifyRequestClaims`, rejected proofs (wrong
  htu, forged signature, wrong nonce) leaving the store untouched, retention
  at `iat+10m` and at an earlier `exp`, and a 4096-byte jti stored as a
  43-byte key. `TestVerifyClaims_MemberNameCase` rejects upper-case `JTI`,
  `HTU` and `TYP`. `TestVerifyClaims_ConcurrentReplay` releases 32 goroutines on
  a barrier with one proof: exactly 1 accepted, 31 `ErrReplay`, 1 retained
  entry. `TestMemoryReplayCache_Expiry` uses a controlled clock: fail closed
  when full, retention at the expiry instant and eviction 1ns later,
  re-admission after expiry, a replay still detected at exactly
  `iat+10m`, and a proof one second later rejected by the verifier before
  the store.
  `TestVerifyClaims_AccessTokenBinding` checks the RFC 9449 §7.1 `ath`
  vector, a signer-produced `ath`, missing and substituted tokens, a
  mismatched `cnf.jkt`, `ath` from a thief's key without `cnf.jkt`, and the
  token-endpoint cases.
  `ExampleVerifyRequestClaims` compiles and runs the `doc.go` sample.
- `BenchmarkVerifyClaimsReplayCache` (`-count=6 -cpu=1,4`, unique ES256
  proofs): 91.4µs serial and 23.7µs on 4 CPUs per verification, 232
  allocs/op against 226 without a store (`BenchmarkVerifyClaims`, below).
  `BenchmarkMemoryReplayCache`: a unique key costs 612ns serial and 457ns on
  4 CPUs with 1 alloc (map growth to 2–3M entries included); a rejected
  replay costs 367–376ns with 3 allocs; admitting at capacity 1024 while
  evicting costs 214–256ns with 2 allocs and stays at 1 retained entry.
- `go test ./jwt/dpop -race -count=5` passed. `make test RACE=true` passed
  across the repository with SoftHSM and local-kms fixtures. `make lint`
  passed with 0 issues. `make build docs` regenerated the API docs (and the
  line-number drift that `jwt.md` had since JW1). `make covtest` passed at
  **90.7%** aggregate, with `jwt/dpop` at 93.7%.

### XPKI-076 — DP1

**Fixed on 2026-09-24.** Approved policy: keep https as the default scheme
for a server-side request with no URL scheme, so TLS-terminating proxies keep
working, and add `VerifyConfig.ExternalURL`. That is a trusted
`scheme://host[:port]` origin which overrides the client-controlled URL
scheme/host and `Host` header. It must be http or https, with no path
other than `/`, and no query, fragment or userinfo; otherwise `dpop: invalid
ExternalURL ...`. Plain-HTTP servers set it.

`htu` and the request URI are now compared after RFC 3986 §6.2.2/§6.2.3
normalization (`jwt/dpop/htu.go`, `normalizeHTU`): scheme and host
lowercased, the scheme's default port removed, unreserved escapes decoded
and other escapes uppercased, and an empty path becoming `/`. The path stays
case-sensitive; query and fragment are ignored. Dot segments are **not**
removed (code review: a proof for `/public` verified on `/admin/../public`,
which a router that does not clean paths may dispatch to `/admin/`).
A relative or opaque `htu` is rejected as `dpop: invalid http_uri claim`.
The request URI and the signer both keep `URL.RawPath`, so `/a%2Fb` stays
distinct from `/a/b` and round-trips from client to server.

Compatibility: a proof whose path differs from the request only in case is
now rejected (the old whole-URI `EqualFold` accepted it). A proof whose
scheme/host case, default port or escaping differs is now accepted. There is
no case-insensitive compatibility option.

Validation passed:

- Before the fix, on HEAD: a proof for `/api/A` verified against
  `/api/a`, and a plain-HTTP server request was rebuilt as `https://` and
  rejected a correct `http://` proof.
- After the fix, `TestVerifyRequestClaims_RequestURI` uses
  `httptest.NewRequest` server-style requests (empty URL scheme and host)
  and covers the https default, ignored query/fragment, host case with
  `:443`, unreserved escapes, unresolved dot segments, `%2f` versus `%2F`, `%2F`
  versus `/`, `/v1/Resource` versus `/v1/resource`, plain HTTP with and
  without `ExternalURL`, `ExternalURL` overriding an internal and a spoofed
  `Host`, five invalid `ExternalURL` forms, a relative `htu`, a TLS request,
  and a signer-to-server round trip of an escaped path.
  `TestNormalizeHTU` tables 22 inputs, including IPv6, non-default ports,
  literal `.`/`..` and `%2E%2E`, and invalid escapes.
- The same repository race, lint, docs and coverage runs as XPKI-075.

### XPKI-074 — DP1

**Fixed on 2026-09-24.** Approved option: verify with go-jose inside
`jwt/dpop`, so every advertised algorithm works; package `jwt` is
unchanged. `VerifyClaimsContext` parses the compact proof with the same
allow-list (RS256/384/512, PS256/384/512, ES256/384/512, EdDSA) and calls
`JSONWebSignature.Verify` with the embedded public JWK. go-jose rejects a
key whose type or curve does not fit the alg. Claims are decoded (with
`json.Number`) only from the verified payload. The unused `jwt.TokenParser`
in `dpop` was removed.

Validation passed:

- Before the fix, on HEAD: PS256 and EdDSA proofs failed with `dpop: unable
  to verify token: unsupported algorithm`.
- After the fix, `TestVerifyClaims_Algorithms` verifies real signatures for
  all 10 algorithms (RSA 2048, P-256/384/521, Ed25519). It rejects a
  signature by another key, ES256 with a P-384 JWK, RS256 with an EC JWK and
  EdDSA with an RSA JWK (`dpop: unable to verify token`), and `ES256K`
  (`dpop: alg not allowed: ES256K`). Existing HMAC, private-JWK and
  multi-signature cases still pass.
- `BenchmarkVerifyClaims` (`-count=8 -cpu=1,4`, benchstat, ES256, HEAD
  worktree against the fix): 91.7 → 89.9µs serial (−2.0%, p=0.007), 24.1 →
  24.2µs on 4 CPUs (no significant change, p=0.96), 16.4 → 16.3 KiB and
  247 → 226 allocs/op.
- The same repository race, lint, docs and coverage runs as XPKI-075.

### XPKI-070 — JW1

**Fixed on 2026-09-24.** Approved policy: a 10s refresh cooldown, a 10s
per-fetch timeout and a 1 MiB response limit by default. `NewRemoteKeySet`
takes variadic options, so existing calls still compile: `WithHTTPClient`,
`WithRefreshCooldown` (0 disables), `WithFetchTimeout` and
`WithMaxResponseSize`. `RemoteKeySet` now:

- refetches only when no cached key fits the lookup, and at most once per
  cooldown, counted from the end of the previous fetch whether it succeeded
  or failed. A miss inside the cooldown is answered from the cache, or with
  `JWKS refresh throttled after failure: <last error>` when nothing is
  cached;
- bounds each fetch with a context deadline, which also applies to an
  injected client; the default client has the same `Timeout`;
- rejects bodies larger than the limit and non-200 responses, without
  putting response bytes into errors;
- runs the shared fetch on the set's lifetime context, so cancelling one
  waiter does not cancel it. The goroutine publishes the cache, `lastFetch`,
  a fetch counter and a cleared `inflight` before waking waiters. A nil
  constructor context becomes `context.Background()`;
- keeps coalescing when the cooldown is 0 (PR #534 review): a lookup that
  read the cache before a fetch published, and locked after that fetch freed
  its inflight slot, shares the fetch's result instead of starting another;
- accepts `WithMaxResponseSize(math.MaxInt64)`. The read limit is the size
  limit plus one, except at the maximum, where the addition would overflow
  and make every body read as empty (PR #534 review).

Compatibility: a key published in the 10s after a fetch is refused until the
cooldown ends. `WithRefreshCooldown` tunes this. Background TTL refresh, and
`ParserConfig` fields for these options, are in ROADMAP.

Validation passed:

- Before the fix, a scratch test on a `git worktree` of HEAD showed 20
  fetches for 20 unknown kids. After a first waiter timed out on a stalled
  endpoint, a second waiter was still blocked 2s later. An 8 MiB JWKS was
  accepted.
- After the fix, `TestRemoteKeySetRefresh` passes. It covers a 50-kid flood
  costing 1 fetch; rotation with cooldown 0; a stalled endpoint returning
  `context.DeadlineExceeded` within the 100ms fetch timeout and then
  recovering; 8 waiters sharing 1 fetch while a cancelled waiter gets
  `context.Canceled`; exact-size and one-byte-over limits; the 1 MiB
  default; a 500 response that is neither echoed nor retried inside the
  cooldown; invalid JSON; an injected client with a nil context; and
  `NewParser` with `jwks_uri`. `TestRemoteKeySetRotationCooldown` uses a
  controlled clock: the new kid is refused at cooldown−1ns with no fetch,
  and is served at the cooldown with exactly one more fetch.
  `TestRemoteKeySetConcurrentRotation` overlaps 8 lookup workers with
  server-side rotation.
- PR #534 review fixes: `max_int64_size_limit` failed before the fix with
  `failed to decode keys: unexpected end of JSON input`.
  `TestRemoteKeySetStaleSnapshotSharesFetch` failed with the stale-snapshot
  check disabled (2 fetches instead of 1, and 3 instead of 2 for a shared
  failure). Both now pass, and `go test ./jwt -race -count=5` passed.
- `BenchmarkRemoteKeySet` (`-count=8 -cpu=1,4`, benchstat, loopback server).
  Unknown kids went from 1 fetch/op (0.25 with four goroutines, coalesced) to
  0 fetches/op. Time per lookup fell 88–95% (44.9µs → 3.3µs serial). Bytes
  per op fell from 2.6–9.2 KB to 832–855 B, and allocations from 32–105 to
  12–13. Known
  kids showed no significant change (16.6 → 17.6 ns, p=0.06), with 0
  allocations. Rotation is covered by the tests above, not benchmarked.
- `make test RACE=true` passed across the repository with SoftHSM and
  local-kms fixtures. `make lint` passed with 0 issues. `make build docs`
  regenerated the API docs. `make covtest` passed at **90.6%** aggregate.

### XPKI-071 — JW1

**Fixed on 2026-09-24.** Approved policy: use a key only when it is the
single eligible one, with the token algorithm supplied through an optional
interface. `AlgorithmKeySet.GetKeyForAlgorithm(ctx, kid, alg)` is new, and
`StaticKeySet` and `RemoteKeySet` implement it. `parser.ParseToken` passes
`token.SigningMethod` when the key set supports it. `KeySet.GetKey` is
unchanged, applies the same rules and checks only `use`.

A key is eligible when its JWK `use` is empty or `sig` and, when an alg is
given, its JWK `alg` is empty or equal to it and its type and curve fit the
alg: RS256/384/512 need RSA, and ES256/384/512 need P-256/384/521. Other
algorithms have no eligible key. An empty `kid` considers every key. A
non-empty `kid` considers only keys with that `KeyID`, so a `use: enc` key is
refused even when its kid is named. Zero eligible keys return a wrapped
`ErrKeyNotFound`, and more than one returns `ErrAmbiguousKey`; both work
with stdlib and cockroachdb `errors.Is`. `RemoteKeySet` refetches (subject to
the cooldown) when cached selection fails for any reason.

Compatibility: error text changed from `key not found: <kid>` to
`kid="<kid>": key not found`. A kid-less token against a JWKS with several
signing keys of the token's type now fails instead of taking the first.

Validation passed:

- Before the fix, on HEAD: an empty kid returned the `use: enc` RSA key ahead
  of a signing EC key, and `kid=enc` returned the encryption key.
- After the fix, `TestStaticKeySetSelection` passes with 32 cases: enc skipped
  in either order, only-enc, two signing keys, alg choosing the key type in
  either order, no alg ambiguous, JWK `alg` mismatch and match, wrong and
  right curve, PS256, duplicate kids split by alg, and wrapped sentinels.
  `TestParserKeySelection` verifies real RS256 and ES256 tokens without
  `kid` through `NewParser`, in two key orders with an enc key present, and
  rejects an ambiguous set. `TestParserKeyIDTypes` was updated for the new
  error text.
- The same repository race, lint, docs and coverage runs as XPKI-070.

### XPKI-072 — JW1

**Fixed on 2026-09-24.** Approved policy: support `PublicKeys` as kid-less
keys. Each entry must be `*rsa.PublicKey` or `*ecdsa.PublicKey`; any other
type, including nil, fails every lookup with `unsupported public key type at
index N: T`, so a supplied key is never silently ignored. With an empty
`kid`, `PublicKeys` join the `KeySet` entries in single-eligible selection.
With a `kid`, `KeySet` entries win. Only when no `KeySet` entry has that kid
are `PublicKeys` matched by RFC 7638 SHA-256 thumbprint (base64url, no
padding).

Validation passed:

- Before the fix, on HEAD: a `PublicKeys`-only set returned
  `key not found: `.
- After the fix, the `TestStaticKeySetSelection` cases pass: RSA-only and
  EC-only, alg choosing the type, two RSA keys ambiguous, thumbprint match,
  unknown kid, ambiguity across both lists, a single eligible key across both
  lists, `KeySet` taking precedence, thumbprint fallback, ed25519 and nil
  entries rejected. `TestParserKeySelection/public_keys_only` verifies real
  RS256, ES256 and thumbprint-kid tokens through `TokenParser`, and
  rejects a signature from a different key.
- The same repository race, lint, docs and coverage runs as XPKI-070.

### XPKI-037 — CU1

**Fixed on 2026-09-24.** Approved API: a context-aware entry point.
`Bundler.BundleContext(ctx, certs, key)` and `ChainFromPEMContext` are new,
and `Bundle`/`ChainFromPEM` call them with `context.Background()`.
`fetchRemoteCertificate` now:

- builds each request with `http.NewRequestWithContext`, under a deadline of
  the client `Timeout`, or 3s when a configured client has none;
- rejects any status other than 200, even when the body is a valid
  certificate;
- reads at most 1 MiB (`maxAIAResponseSize`) and rejects larger bodies rather
  than truncating them;
- never logs or returns response bytes. Diagnostics name the URL, status and
  byte count.

When the context is done during an AIA fetch, the traversal stops and the
error matches `ctx.Err()` with `errors.Is`. The CLI `cert validate` passes
its command context.

Validation passed:

- Before the fix, `bundler_aia_test.go` failed on the unfixed code. A 500
  or 404 response carrying a valid certificate was accepted, and so was a
  2 MiB chunked PEM body. A stalled server with a zero-timeout client hung
  `Bundle` past the 10s watchdog. The debug log contained the response body
  (`data="aia-body-marker..."`).
- After the fix, `TestBundlerAIAResponseValidation` (200 DER, 200 PEM padded
  to exactly 1 MiB, 500/404 with valid bytes, oversized chunked),
  `TestBundlerAIAStalledResponse` (returns after the 3s default) and
  `TestBundlerAIADoesNotLogBody` pass. `TestBundlerAIACancellation` covers
  cancellation: no further URL is fetched, and a cancelled context does not
  matter when no fetch is needed. It fails (watchdog) when the request
  context is replaced by `context.Background()`.
- `make test RACE=true TEST_FLAGS=-count=1` passed across the repository with
  SoftHSM and local-kms fixtures. `make lint` passed with zero issues.
  `make build docs` regenerated the API docs. `make covtest` passed at
  **90.4%** aggregate.

### XPKI-039 — CU1

**Fixed on 2026-09-24.** `fetchIntermediates` marks an AIA URL as seen
*before* fetching it, so each URL is requested at most once per `Bundle` call,
whether the fetch fails or returns a known certificate. The URL and signature
sets are now separate maps. The sets are per call, so a later call retries a
URL that failed.

Validation passed:

- `TestBundlerAIARequestsPerTraversal` puts a failing URL first in every
  certificate's AIA list, at depths 1, 2 and 4. Before the fix the failing
  URL was fetched 3, 5 and 9 times (2·depth+1). After the fix it is fetched
  once, each issuer once, and a warm second call makes no request.
  `TestBundlerAIARetriesOnNextCall` asserts that a duplicate URL is fetched
  once and that it recovers on the next call.
- `BenchmarkBundlerAIAFailingURL` compared before and after with
  `-count=5 -cpu=1,4` (benchstat, p=0.008). Depth 1/2/4/8 went from 3/5/9/17
  to 1 failed request per op, and from 4/7/13/25 to 2/3/5/9 total requests.
  Wall time fell 10–18% on a loopback server, bytes per op fell 39–45%, and
  allocations fell 25–30%.
- Suite, lint and coverage results are as listed for XPKI-037.

### XPKI-041 — CU1

**Fixed on 2026-09-24.** Approved policy: system roots require an explicit
opt-in.

- New `WithSystemRoots(bool)` adds the explicit roots to
  `x509.SystemCertPool()`.
- The flavor is resolved after all options. The default is Optimal with
  trust roots (explicit roots or system roots) and Force without them. The
  last `WithBundleFlavor` wins.
- `NewBundler` rejects Optimal without trust roots, and any unknown flavor.
- `VerifyOptions().Roots` is never nil, and an Optimal `Bundle` whose
  exported `RootPool` was reset to nil fails with "no trust roots
  configured".
- `xpki-tool cert validate` now requests Optimal together with
  `WithSystemRoots(--root == "")`, instead of assigning `RootPool` after
  construction.

Compatibility: `NewBundler(nil, …, WithBundleFlavor(Optimal))` now returns
an error instead of trusting the system roots. Callers that want system trust
must pass `WithSystemRoots(true)`. `cert validate --root <file without
certificates>` now fails. Before the fix it fell back to Force and accepted
the chain.

Validation passed:

- A throwaway probe on the unfixed code ran a subprocess with
  `SSL_CERT_FILE` set to a generated root. In it,
  `NewBundler(nil, nil, WithBundleFlavor(Optimal))` accepted a chain that
  anchors only in that system root. The new CLI case
  `TestPKICommandInputErrors/validate_empty_roots` failed against the
  unfixed `certs.go`/`bundler.go`.
- `TestNewBundlerTrustRoots` covers nil, empty and explicit roots × default,
  Force, Optimal, both option orders and `WithSystemRoots(false)`. It
  asserts the resolved flavor, the exact error, and that an unknown root
  fails with `UnknownAuthorityError`. It also covers an unknown flavor and a
  `RootPool` cleared after construction.
- `TestBundlerSystemRoots` re-runs itself with `SSL_CERT_FILE`/`SSL_CERT_DIR`
  set to a generated root. It checks that system roots are trusted only
  with `WithSystemRoots`, that they combine with explicit roots, and that
  Force ignores them. It is skipped on darwin/windows, where the variables
  do not replace the platform store; it ran on Linux.
- Suite, lint and coverage results are as listed for XPKI-037.

### XPKI-044 — CU1

**Fixed on 2026-09-24.** The unused `certutil.HTTPClient` is now marked
`Deprecated`, and its comment says that it is never read and points callers
to `WithHTTPClient`. The global was deliberately not activated.
`WithHTTPClient` documents the timeout, status and size rules.

Validation passed: `TestBundlerAIAUsesInjectedClient` asserts that the
injected transport carries exactly one round trip. `make lint` (staticcheck
SA1019) reports no use of the deprecated variable.

### XPKI-049 — AU1

**Fixed on 2026-09-24.** Approved policy: deny-by-default for CSR
extensions, while the trusted `SignRequest` keeps its old rule. `Issuer.Sign`
now builds the template only from CSR fields permitted by `allowed_fields`.
With `allowed_fields` nil, that is the subject and all SAN fields, still
regex-checked. CSR extensions are no longer copied wholesale:

- SKI, KU, SAN, BasicConstraints, AKI, EKU and OCSP no-check
  (`csrDeniedExtensions`) are always dropped from a CSR, even when
  allow-listed.
- Other CSR extensions need an explicit `allowed_extensions` entry; an empty
  list allows none. `omit_disabled_extensions` chooses between drop and
  reject.
- An allow-listed CSR AIA or CRL DP is kept only when the issuer generates
  none. This keeps the SHAKEN delegate flow in
  `testdata/csrprofiles/delegated_l1_ca.yaml` working.
- `SignRequest.Extensions` still allows everything on an empty list and may
  supply profile-owned OIDs (for example, a critical timestamping EKU).

The broken omit branch (TODO) is gone. `SignRequest` docs, README, codemap
and the new `authority/README.md` describe the per-extension source rules.
The ROADMAP item is removed.

Compatibility: a CSR carrying a non-profile-owned extension under a profile
with an empty `allowed_extensions` is now rejected, or dropped with
`omit_disabled_extensions`. A raw CSR SAN is always rebuilt from its parsed
names, so `otherName` SAN entries from a CSR are no longer issued.

Validation passed:

- New tests in `authority/issuer_policy_test.go` reproduced the defect
  before the fix. A hostile signed CSR obtained `keyCertSign`, a code-signing
  EKU, a forged AKI/SKI and OCSP no-check under the default policy.
  `allowed_fields.dns=false` plus an allow-listed SAN let `evil.example.com`
  past the DNS regex, and a CSR CRL DP overrode the issuer's own.
  `TestSignCSRProfileOwnedExtensions`, `TestSignCSRSANBypassesFieldPolicy`
  and `TestSignCSRIssuerGeneratedExtensions` failed before the fix and pass
  after it. `TestSignCSRExtensionAllowList`, `TestSignCSRIssuerGeneratedAIA`
  (added after the fix) and `TestSignRAMayOverrideOwnedExtensions` pin the
  allow-list, AIA and trusted-RA rules.
- `make test RACE=true TEST_FLAGS=-count=1` passed across the repository with
  SoftHSM and local-kms fixtures.
- `make lint` passed with zero issues. `make build docs` regenerated the
  authority and csr API docs. `make covtest` passed at **90.4%** aggregate:
  authority ran fresh, and unchanged packages used cached coverage results.

### XPKI-050 — AU1

**Fixed on 2026-09-24.** Each issued certificate carries exactly one
extension per OID. The ordering is OID-specific:

- Raw extensions are kept in the order profile `extensions`, then
  `SignRequest`, then CSR. The first one for an OID wins.
- Certificate policies and OCSP no-check: when the profile sets `policies` or
  `ocsp_no_check`, fillTemplate replaces any raw copy through `setExtension`.
- KU, EKU, basic constraints, SKI/AKI, SAN, AIA and CRL DP: a kept raw
  profile or `SignRequest` extension overrides the value
  `x509.CreateCertificate` builds from template fields. This is how an RA
  supplies a critical timestamping EKU. The profile-derived value does not
  win over it. The CSR cannot supply these OIDs, except an AIA or CRL DP the
  issuer does not generate (XPKI-049).

`CertProfile.Validate` rejects repeated `extensions` OIDs and raw OIDs that
collide with `policies` or `ocsp_no_check`. `Sign` rejects a repeated OID
in an unvalidated profile.

Validation passed:

- `TestSignExtensionPrecedence`, `TestSignProfileGeneratedExtensionsWin` and
  `TestProfileValidateExtensions` failed before the fix. CreateCertificate
  output did not parse ("duplicate extension"), and a CSR value beat the
  request value. After the fix they assert one extension per OID and the
  exact bytes and criticality. Suite, lint and coverage results are as
  listed for XPKI-049.

### XPKI-054 — AU1

**Fixed on 2026-09-24.** Approved policy: reject requests outside the
envelope. `validityWindow` computes the defaults as before. It rejects an
explicit NotBefore earlier than now − backdate (default 5m, with minute
truncation), a NotAfter not after NotBefore, and a lifetime longer than the
profile expiry. Shorter lifetimes and future NotBefore values are allowed.
`sign` still clips NotAfter to the issuer NotAfter, and now fails if that
leaves no validity.

Compatibility: an RA that sends only `NotAfter = now + expiry` is rejected
when the default backdate makes the lifetime exceed expiry. Such an RA must
send NotAfter ≤ NotBefore + expiry.

Validation passed:

- `TestValidityWindow` checks exact boundaries against a fixed clock,
  including the default and profile backdate, overlong, equal, reversed,
  excessive backdate, future NotBefore and no-expiry cases.
- `TestSignValidity` covers the same rules through `Sign`, including
  issuer-expiry clipping and a NotBefore past the issuer NotAfter. Before
  the fix it failed at that case: no error was returned.
- A throwaway probe against the unfixed `HEAD`, in a temporary worktree,
  issued a reversed-validity certificate (NotAfter one hour before
  NotBefore). It also issued a 48h certificate on a 1h profile and a
  certificate backdated 24h.
- Suite, lint and coverage results are as listed for XPKI-049.

### XPKI-057 — AU1

**Fixed on 2026-09-24.** Approved policy: a populated list filters every
profile. `issuerHasProfile` attaches issuer-specific profiles unless a
populated `allowed_profiles` omits them. Wildcard profiles attach only when
listed. An empty list keeps the previous behavior: named profiles, no
wildcards. `LoadConfig` fails when a populated list omits the issuer's
`delegated_ocsp_profile`. The field doc, codemap, README and
`authority/README.md` state the contract.

Validation passed:

- `TestLoadConfigAllowedProfiles` covers named/wildcard × nil/empty/populated
  lists and asserts the exact map keys, including absent ones.
  `TestLoadConfigAllowedProfilesDelegatedOCSP` covers the delegated-profile
  check. Both failed with the previous selection logic swapped back in and
  pass after the fix.
- Suite, lint and coverage results are as listed for XPKI-049.

### XPKI-017 — IM1

**Fully Fixed on 2026-09-21.** IM1 synchronizes the `inmemcrypto` key map
with an RWMutex for registration and lookup. Generation, signing, and PEM
serialization remain outside the lock. Lookups preserve signer identity;
exports retain an empty URI and caller-owned PKCS#1/SEC1 PEM bytes. Token
configuration must remain unchanged during use. Updated the codemap and
regenerated the API documentation.

The `testprov` portion was fixed by [TP1](#xpki-017-testprov--tp1) on
2026-09-20. Both package portions are now implemented and verified;
**XPKI-017 and batch IM1 are Fixed**.

Validation:

- `go test -race ./cryptoprov/inmemcrypto -run '^TestConcurrentKeyOperations$' -count=1 -timeout=60s`
  reproduced registration/lookup races before the fix.
- `go test -race ./cryptoprov/inmemcrypto -run '^TestConcurrentKeyOperations$' -count=5 -cpu=1,4,8 -timeout=120s`
  passed afterward. It checks simultaneous RSA/ECDSA generation, lookup,
  and export; unique IDs; exact missing-key errors; signer identity;
  PKCS#1/SEC1 parsing; signatures from original/exported keys; and PEM buffer
  independence when callers modify returned bytes.
- `go test ./cryptoprov/inmemcrypto -run '^$' -bench '^BenchmarkGetKey$' -benchmem -benchtime=100ms -count=5 -cpu=1`
  passed before/after on the same Go 1.27 linux/amd64 host. Median hits
  were 12.25 → 17.15 ns/op with 0 allocations; misses were 1902 → 1983
  ns/op with 512 B / 9 allocations. Key generation is excluded from timing;
  these serial lookups do not measure mixed-workload throughput.
- `make test RACE=true TEST_FLAGS=-count=1` passed with SoftHSM/local-kms
  fixtures and no cached results, including both providers' concurrency tests.
- `make lint` passed with zero issues. `make build docs` and `make covtest`
  passed; aggregate coverage was **90.2%** (some unchanged packages used
  cached coverage results).

### XPKI-017-testprov — TP1

**testprov portion Fixed on 2026-09-20.** The test provider's private map
now uses an RWMutex for registration and lookup. Key generation, signing,
decryption, and URI formatting remain outside the map lock. Signer identity,
missing-key errors, and URI-only export with nil key bytes are preserved.
Documented concurrent operations and immutable token configuration.
The remaining `inmemcrypto` portion was completed by [IM1](#xpki-017--im1)
on 2026-09-21; **XPKI-017 is now Fixed**.

Validation:

- `go test -race ./cryptoprov/testprov -run '^TestConcurrentKeyOperations$' -count=1 -timeout=60s`
  reproduced data races and a concurrent-map crash before the fix.
- `go test -race ./cryptoprov/testprov -run '^TestConcurrentKeyOperations$' -count=5 -cpu=1,4,8 -timeout=120s`
  passed afterward, checking simultaneous generation/lookup/export, missing
  keys, unique IDs, signer identity, real signatures, and RSA OAEP decryption.
- `go test ./cryptoprov/testprov -run '^$' -bench '^BenchmarkGetKey$' -benchmem -benchtime=100ms -count=5 -cpu=1`
  passed before/after on the same Go 1.27 linux/amd64 host. Median hit cost
  was 12.79 → 17.97 ns/op, retaining 0 allocations; misses were 1842 → 1935
  ns/op, retaining 512 B and 9 allocations. These are serial lookup timings;
  no mixed-workload throughput claim is made.
- `make test RACE=true TEST_FLAGS=-count=1` passed with SoftHSM/local-kms
  fixtures and no cached test results. `make lint` passed with zero issues.
- `make build docs` and `make covtest` passed; aggregate coverage was
  **90.2%** (some unchanged packages used cached coverage results).

### XPKI-062 — TC1

**Fixed on 2026-09-20.** Default common names now use an atomic counter;
`Entity.IncrementSN` protects the existing return-then-increment behavior
with a per-entity mutex. Signing and key generation remain outside the lock.
The exported `NextSN int64` remains usable between calls. Documented that
direct field access requires no calls in flight, an entity must not be copied
after first use, and concurrent issuance requires immutable defaults/options
and a signer that supports concurrent use. Regenerated the testca API docs.

Validation passed:

- The new `go test -race ./testca -run '^TestConcurrent' -count=1 -timeout=60s`
  tests reproduced races, duplicate names, and lost serial increments before
  the fix.
- `go test -race ./testca -run '^TestConcurrent' -count=20 -cpu=1,4,8 -timeout=120s`
  passed, checking unique names, complete serial sequences, quiescent field
  updates, shared-issuer signatures, and caller option ownership.
- `make test RACE=true TEST_FLAGS=-count=1` passed across the full repository
  with SoftHSM/local-kms fixtures and no cached test results.
- `make lint` passed with zero issues; `make covtest` passed at **90.1%**
  aggregate coverage (testca is excluded from that aggregate; some unchanged
  packages used cached coverage results).

### XPKI-107 — TC1

**Discovered and fixed on 2026-09-20.** The shared-issuer regression test
exposed writes into caller-owned spare option-slice capacity. `Entity.Issue`
now copies the options into its own slice before adding its issuer; receiver
precedence is preserved. The test reuses one options slice concurrently and
then checks that the caller's unused option still applies.

`go test -race ./testca -run '^TestConcurrentIssue$' -count=1 -timeout=60s`
reproduced the race and changed option behavior before this fix. The TC1
concurrency matrix, uncached full race suite, `make lint`, and `make covtest`
all passed afterward, as recorded under XPKI-062 above.

### XPKI-093 — SC1

**Fixed on 2026-09-20.** Hardened [SoftHSM setup](scripts/config-softhsm.sh)
argument validation, module discovery, error propagation, configuration
selection, JSON encoding, and PIN generation/storage/output. PIN and output
JSON files use mode 0600. [Make setup](Makefile) builds and uses our
`bin/hsm-tool hsm list` for verification; `softhsm2-util` initializes the
token, and OpenSC is optional.

Validation passed: `make test-scripts` (38 isolated cases), ShellCheck,
real SoftHSM initialization/reuse/delete/force checks, `make hsmconfig` on
a host without `pkcs11-tool`, `go test ./cmd/hsm-tool/cli -run '^TestHsmSuite$'`,
`go test ./crypto11`, and `make lint`. macOS module discovery was checked
with Homebrew stubs; native macOS execution was not available.

### XPKI-105 — XC2

**Fixed on 2026-09-20.** [The CLI test suite](cmd/xpki-tool/cli/suite_test.go)
now allocates fixtures with `s.T().TempDir()` in `SetupSuite`. Removed the
shared-path `MkdirAll` and `TearDownSuite` deletion; Go owns cleanup after
the suite's subtests finish.

Validation passed:

- Before the fix, two overlapping test processes running
  `-test.run=^TestSuite$ -test.count=50` under the same temporary root
  reproduced missing certificate/OCSP fixture errors in one process.
- Built `go test -c -cover -o /tmp/xpki-xc2-validation/coverage.test ./cmd/xpki-tool/cli`
  and `go test -c -race -o /tmp/xpki-xc2-validation/race.test ./cmd/xpki-tool/cli`.
  Ran both concurrently from the package directory with a shared `TMPDIR`,
  separate output files, and `-test.run=^TestSuite$ -test.count=50 -test.timeout=120s`.
  Each passed all 50 suite runs; no fixture directories remained afterward.
- `make lint` passed (zero lint issues).
- `make test RACE=true` and `make covtest` passed; aggregate coverage was
  **90.1%**. Most unchanged packages used cached test results; the changed
  CLI package and the overlap check executed afresh.

## Notes on items needing approval

- **XPKI-036 / XPKI-038** change exported return values (`Bundle` returning an
  error for empty input; `SortBundlesByExpiration` returning a copy).
- **XPKI-049 / XPKI-054 / XPKI-057** were approved and fixed by AU1 on
  2026-09-24; see their Fixed items for the chosen policy and compatibility
  notes.
- **XPKI-075** was approved and fixed by DP1 on 2026-09-24 (opt-in
  `VerifyConfig.ReplayCache`, `AccessToken`, `ExpectedThumbprint`).
- **XPKI-109** (found during the AT1 review): the `jwt` fix, normalizing time
  claims in `Sign` or parsing RFC 3339 in `MapClaims.Time`, changes signed
  token contents or accepted inputs.
- **XPKI-078** was approved and fixed by AT1 on 2026-09-25 (explicit
  lifetime, caller `exp` kept, opt-in `WithAllowNoExpiry` for legacy tokens).
- **XPKI-053** renewal-failure policy was approved and fixed by AU2 on
  2026-09-25 (keep serving from a still-valid cached responder, otherwise an
  error; never the CA key). **XPKI-100**'s fixture convention
  (`internal/testenv`, `XPKI_INTEGRATION=required`) was approved at the same
  time; its other package portions remain open.
- **XPKI-094 / XPKI-095** change what CI runs; enabling lint in CI will fail
  until the remaining `gosec`/`gocritic` style findings are triaged.
