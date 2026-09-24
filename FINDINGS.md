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
| XPKI-051 | authority                             | `ocsp.go` `CreateDelegatedOCSPSigner`                          | Holds `ca.lock` then calls `ca.Sign` → `ca.Profile` → `RLock`: deadlock when `delegated_ocsp_profile` is set                                       | bug         | Open           |
| XPKI-052 | authority                             | `ocsp.go` `SignOCSP` non-delegated branch                      | `ca.responder` read/written without the lock                                                                                                       | race        | Open           |
| XPKI-053 | authority                             | `ocsp.go` `SignOCSP`                                           | Fallback `responder = ca.responder` may be nil → `responder.Cert` panics                                                                           | bug         | Open           |
| XPKI-054 | authority                             | `issuer.go` `Sign`/`fillTemplate`                              | `SignRequest.NotBefore/NotAfter` not bounded by profile expiry; inverted range not rejected                                                        | correctness | **Fixed** ([details](#xpki-054--au1)) |
| XPKI-055 | authority                             | `authority.go` maps                                            | `Authority` maps and `Issuer.Profiles()` live map have no synchronization                                                                          | race        | Open           |
| XPKI-057 | authority                             | `config.go` `AllowedProfiles`                                  | Only filters wildcard (`issuer_label: "*"`) profiles, contrary to the field doc                                                                    | correctness | **Fixed** ([details](#xpki-057--au1)) |
| XPKI-058 | authority                             | `config.go` `IssuerConfig.Type`                                | No json/yaml tag; `type:` in YAML is silently dropped                                                                                              | bug         | Open           |
| XPKI-059 | csr                                   | `csr.go` `SetSAN`, `csrprov.go` `SignRequest`                  | No SAN dedupe or DNS validation; `nil` keeps CSR SANs but empty slice clears them (undocumented)                                                   | correctness | Open           |
| XPKI-062 | testca                                | `configuration.go` `cnCounter`, `entity.go` `NextSN`           | Global common-name and per-issuer serial counters incremented without synchronization                                                               | race        | **Fixed** ([details](#xpki-062--tc1)) |
| XPKI-063 | testca                                | `utils.go` `ToPFX`/`ToPKCS8`                                   | Shell out to `openssl` and panic; stdlib `x509.MarshalPKCS8PrivateKey` covers PKCS#8                                                               | correctness | Open           |
| XPKI-066 | jwt                                   | `jwt.go` `NewProviderWithSymmetricKey`                         | Provider signs without `kid` and has empty `keys`, so it cannot verify its own tokens                                                              | bug         | Open           |
| XPKI-070 | jwt                                   | `jwks.go` `RemoteKeySet.updateKeys`/`GetKey`                   | `http.DefaultClient` without timeout, unbounded body, refresh on every unknown `kid`; a stalled JWKS endpoint blocks all cache misses              | security    | Open           |
| XPKI-071 | jwt                                   | `jwks.go` `StaticKeySet.GetKey`/`RemoteKeySet.GetKey`          | Empty `kid` returns the first JWK regardless of `kty`/`use`                                                                                        | correctness | Open           |
| XPKI-072 | jwt                                   | `jwks.go` `StaticKeySet.PublicKeys`                            | Field documented but never read                                                                                                                    | bug         | Open           |
| XPKI-073 | jwt                                   | `sign.go` `signJWT`                                            | `jti` placed in the JOSE header (non-standard)                                                                                                     | correctness | Open           |
| XPKI-074 | jwt/dpop                              | `verify.go` `supportedSignatureAlgorithm`                      | PS256/384/512 and EdDSA allowed but `jwt.VerifySignature` cannot verify them                                                                       | correctness | Open           |
| XPKI-075 | jwt/dpop                              | `verify.go` `VerifyClaims`                                     | No `jti` replay protection and no `ath` binding although the doc lists both as MUST                                                                | security    | Needs Approval |
| XPKI-076 | jwt/dpop                              | `verify.go` `VerifyRequestClaims`                              | Scheme always defaults to `https`; `htu` compared with `EqualFold` (path is case-sensitive)                                                        | correctness | Open           |
| XPKI-078 | jwt/accesstoken                       | `accesstoken.go` `Sign`                                        | `pat.` tokens get no `exp`; they never expire and `TokenExpiry()` is ignored                                                                       | security    | Needs Approval |
| XPKI-079 | jwt/accesstoken                       | `accesstoken.go` `PublicKey`                                   | Dereferences `p.dp` without nil check                                                                                                              | bug         | Open           |
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
| XPKI-100 | tests                                 | crypto11, cryptoprov, csr, authority, jwt, cmd suites          | Integration tests fail hard (some via `TestMain` panic) instead of skipping when SoftHSM or local-kms is absent                                    | docs        | Open           |
| XPKI-101 | tests                                 | `cmd/hsm-tool/cli/hsm_cli_test.go`                             | Shared kong parser across `Parse` calls masks the `--cfg` required check                                                                           | docs        | Open           |
| XPKI-102 | cmd/xpki-tool/cli                     | `ocsp.go` `OCSPFetchCmd.Run`                                   | All OCSP endpoint failures are printed but the command returns success                                                                             | correctness | Open           |
| XPKI-103 | certutil, cmd/xpki-tool/cli           | `ocsp.go` `CreateOCSPRequest`, `certs.go` `OCSPValidation`     | Nil issuer certificate panics instead of returning an input error                                                                                  | bug         | Open           |
| XPKI-104 | jwt                                   | `jwt.go` `NewProviderWithSymmetricKey`                         | Applying nonempty `WithHeaders` panics because the constructor leaves `headers` nil                                                                | bug         | Open           |
| XPKI-105 | tests                                 | `cmd/xpki-tool/cli/suite_test.go` `SetupSuite`               | Fixed temporary directory is removed by concurrent coverage/race runs, causing missing fixture files                                               | bug         | **Fixed** ([details](#xpki-105--xc2)) |
| XPKI-106 | dataprotection                        | `symmetric_test.go` `TestNewSymmetric`                         | Tamper test copies one random nonce byte over another; equal bytes leave the ciphertext unchanged and make the authentication-failure assertion flaky | bug         | Open           |
| XPKI-107 | testca                                | `entity.go` `Issue`                                           | Appending the issuer overwrites caller option-slice storage when capacity remains and races when the slice is reused concurrently                      | race        | **Fixed** ([details](#xpki-107--tc1)) |

## Fixed items

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
- **XPKI-075 / XPKI-078** require new API surface (`ath`/replay cache in
  `dpop.VerifyConfig`; expiry policy for `pat.` tokens).
- **XPKI-094 / XPKI-095** change what CI runs; enabling lint in CI will fail
  until the remaining `gosec`/`gocritic` style findings are triaged.
