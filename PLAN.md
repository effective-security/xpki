# Findings remediation plan

Reviewed against the working tree at `70307a9` on **2026-09-20**. Covers all
**73 supplied findings**, including items marked **Needs Approval**, plus
**XPKI-106**, discovered during the test review, and **XPKI-107**, discovered
and fixed during TC1, **XPKI-108**, discovered during DP1, and **XPKI-109**,
discovered during the AT1 review. All four are recorded in [FINDINGS.md](FINDINGS.md) as
required by AGENTS.md: **77 findings total**. Later remediation added
**XPKI-110** (PK1 review, batch PK3), **XPKI-111** (a timing-dependent
`authority` test seen during CU2, batch AU5) and **XPKI-112** (PR #543 review,
batch JW4), and **XPKI-113** (CP1 review, batch CP3).
Pending assessments retain the original planning evidence. Fixed entries
record the implementation and validation; completed batches are retained
below and excluded from the pending queue.

## Completed batches

| Batch | Finding | Status | Fixed on |
| --- | --- | --- | --- |
| SC1 | [XPKI-093](FINDINGS.md#xpki-093--sc1) | **Fixed** | 2026-09-20 |
| XC2 | [XPKI-105](FINDINGS.md#xpki-105--xc2) | **Fixed** | 2026-09-20 |
| TC1 | [XPKI-062](FINDINGS.md#xpki-062--tc1), [XPKI-107](FINDINGS.md#xpki-107--tc1) | **Fixed** | 2026-09-20 |
| TP1 | [XPKI-017-testprov](FINDINGS.md#xpki-017-testprov--tp1) | **Fixed** (testprov portion) | 2026-09-20 |
| IM1 | [XPKI-017-inmemcrypto](FINDINGS.md#xpki-017--im1) | **Fixed** (completes XPKI-017) | 2026-09-21 |
| AU1 | [XPKI-049](FINDINGS.md#xpki-049--au1), [XPKI-050](FINDINGS.md#xpki-050--au1), [XPKI-054](FINDINGS.md#xpki-054--au1), [XPKI-057](FINDINGS.md#xpki-057--au1) | **Fixed** | 2026-09-24 |
| CU1 | [XPKI-037](FINDINGS.md#xpki-037--cu1), [XPKI-041](FINDINGS.md#xpki-041--cu1), [XPKI-039](FINDINGS.md#xpki-039--cu1), [XPKI-044](FINDINGS.md#xpki-044--cu1) | **Fixed** | 2026-09-24 |
| JW1 | [XPKI-070](FINDINGS.md#xpki-070--jw1), [XPKI-071](FINDINGS.md#xpki-071--jw1), [XPKI-072](FINDINGS.md#xpki-072--jw1) | **Fixed** | 2026-09-24 |
| DP1 | [XPKI-075](FINDINGS.md#xpki-075--dp1), [XPKI-076](FINDINGS.md#xpki-076--dp1), [XPKI-074](FINDINGS.md#xpki-074--dp1) | **Fixed** | 2026-09-24 |
| AT1 | [XPKI-078](FINDINGS.md#xpki-078--at1), [XPKI-079](FINDINGS.md#xpki-079--at1) | **Fixed** | 2026-09-25 |
| AU2 | [XPKI-051](FINDINGS.md#xpki-051--au2), [XPKI-052](FINDINGS.md#xpki-052--au2), [XPKI-053](FINDINGS.md#xpki-053--au2), [XPKI-100-authority](FINDINGS.md#xpki-100-authority--au2) | **Fixed** (XPKI-100 stays In Progress) | 2026-09-25 |
| PK1 | [XPKI-001](FINDINGS.md#xpki-001--pk1), [XPKI-002](FINDINGS.md#xpki-002--pk1), [XPKI-003](FINDINGS.md#xpki-003--pk1), [XPKI-005](FINDINGS.md#xpki-005--pk1), [XPKI-007](FINDINGS.md#xpki-007--pk1), [XPKI-100-crypto11](FINDINGS.md#xpki-100-crypto11--pk1) | **Fixed** (XPKI-100 stays In Progress) | 2026-09-25 |
| PK2 | [XPKI-011](FINDINGS.md#xpki-011--pk2), [XPKI-006](FINDINGS.md#xpki-006--pk2) | **Fixed** | 2026-09-25 |
| JW2 | [XPKI-066](FINDINGS.md#xpki-066--jw2), [XPKI-104](FINDINGS.md#xpki-104--jw2), [XPKI-100-jwt](FINDINGS.md#xpki-100-jwt--jw2) | **Fixed** (XPKI-100 stays In Progress) | 2026-09-25 |
| CU2 | [XPKI-035](FINDINGS.md#xpki-035--cu2) | **Fixed** | 2026-09-25 |
| CP1 | [XPKI-016](FINDINGS.md#xpki-016--cp1), [XPKI-026](FINDINGS.md#xpki-026--cp1), [XPKI-099-cryptoprov](FINDINGS.md#xpki-099-cryptoprov--cp1), [XPKI-100-cryptoprov](FINDINGS.md#xpki-100-cryptoprov--cp1) | **Fixed** (XPKI-099 and XPKI-100 stay In Progress) | 2026-09-26 |
| GC1 | [XPKI-018](FINDINGS.md#xpki-018--gc1), [XPKI-023](FINDINGS.md#xpki-023--gc1), [XPKI-025-gcpkmscrypto](FINDINGS.md#xpki-025-gcpkmscrypto--gc1) | **Fixed** (XPKI-025 stays In Progress) | 2026-09-26 |
| CP3 | [XPKI-113](FINDINGS.md#xpki-113--cp3) | **Fixed** | 2026-09-26 |

**SC1 / XPKI-093:** hardened SoftHSM setup argument handling, tool/module
discovery, failure propagation, configuration selection, JSON encoding, and
PIN generation/storage/output. PIN and output JSON files use mode 0600.
`make hsmconfig` builds and uses our `hsm-tool hsm list` for verification,
with `softhsm2-util` retained for token initialization. OpenSC is optional
and removed from the CI install step.

Validation passed: `make test-scripts` (38 isolated cases), ShellCheck,
real SoftHSM initialization/reuse/delete/force checks, `make hsmconfig` on
a host without `pkcs11-tool`, `go test ./cmd/hsm-tool/cli -run '^TestHsmSuite$'`,
`go test ./crypto11`, and `make lint`. macOS module discovery was checked
with Homebrew stubs; native macOS execution was not available.

**XC2 / XPKI-105 — Fixed on 2026-09-20:** the CLI suite now owns a unique
`s.T().TempDir()` created in `SetupSuite`, with automatic cleanup after
its subtests. Removed the shared-path creation and manual `TearDownSuite`
deletion.

Validation: the pre-fix overlap check reproduced missing certificate/OCSP
fixtures. Built `go test -c -cover -o /tmp/xpki-xc2-validation/coverage.test ./cmd/xpki-tool/cli`
and `go test -c -race -o /tmp/xpki-xc2-validation/race.test ./cmd/xpki-tool/cli`;
both passed 50 concurrent suite runs with a shared `TMPDIR`, separate output
files, and `-test.run=^TestSuite$ -test.count=50 -test.timeout=120s`. No fixture
directories remained. `make lint` (zero issues), `make test RACE=true`, and
`make covtest` passed; aggregate coverage was **90.1%**. Most unchanged
packages used cached test results; the changed CLI package and overlap check
executed afresh.

**TC1 / XPKI-062, XPKI-107 — Fixed on 2026-09-20:** default common names
use an atomic counter; a per-entity mutex protects serial allocation while
preserving `NextSN`'s exported type and return-then-increment behavior.
Key generation/signing remain outside the lock. `Issue` copies caller
options before appending its issuer, preserving receiver precedence and
preventing a newly reproduced slice-ownership race (107). Documented direct
field access only between calls, no copying an entity after first use, and
immutable defaults/options with a concurrently usable signer. Regenerated
the testca API docs.

Validation: `go test -race ./testca -run '^TestConcurrent' -count=1 -timeout=60s`
reproduced counter races, duplicate names and lost increments before the fix;
`go test -race ./testca -run '^TestConcurrentIssue$' -count=1 -timeout=60s`
separately reproduced the option-slice race and mutation.
`go test -race ./testca -run '^TestConcurrent' -count=20 -cpu=1,4,8 -timeout=120s`
passed afterward, as did `make test RACE=true TEST_FLAGS=-count=1` with the
full SoftHSM/local-kms fixtures and no cached test results. `make lint`
passed with zero issues; `make covtest` passed at **90.1%** (testca is
excluded from the aggregate; some unchanged packages used cached coverage
results).

**TP1 / XPKI-017-testprov — Fixed on 2026-09-20:** the test provider's map
uses an RWMutex for registration/lookup; generation, signing, decryption,
and URI formatting remain outside the lock. Signer identity, missing-key
errors, and URI-only export with nil key bytes are preserved. Token
configuration must remain immutable during use. The remaining inmemcrypto
portion was completed by IM1 on 2026-09-21; **XPKI-017 is now Fixed**.

Validation: `go test -race ./cryptoprov/testprov -run '^TestConcurrentKeyOperations$' -count=1 -timeout=60s`
reproduced data races and a concurrent-map crash before the fix.
`go test -race ./cryptoprov/testprov -run '^TestConcurrentKeyOperations$' -count=5 -cpu=1,4,8 -timeout=120s`
passed afterward, verifying lookup/export during generation, missing keys,
unique IDs, signer identity, real signatures, and RSA OAEP decryption.
`make test RACE=true TEST_FLAGS=-count=1` passed with SoftHSM/local-kms
fixtures and no cached results. `make lint` passed with zero issues;
`make build docs` and `make covtest` passed (**90.2%** aggregate coverage;
some unchanged packages used cached coverage results).

The same-host Go 1.27 linux/amd64 comparison used
`go test ./cryptoprov/testprov -run '^$' -bench '^BenchmarkGetKey$' -benchmem -benchtime=100ms -count=5 -cpu=1`.
Median hits were 12.79 → 17.97 ns/op with 0 allocations; misses were
1842 → 1935 ns/op with 512 B / 9 allocations. Key generation is excluded
from timing; these serial lookup results do not measure mixed-workload
throughput.

**IM1 / XPKI-017-inmemcrypto — Fixed on 2026-09-21:** the provider's map
uses an RWMutex for registration/lookup; generation, signing, and PEM
serialization stay outside the lock. Lookups retain signer identity;
exports remain caller-owned PKCS#1/SEC1 PEM bytes with an empty URI.
Documented immutable token configuration and concurrent operations, updated
the codemap, and regenerated the API reference. **XPKI-017 is fully Fixed**
now that both IM1 and TP1 are implemented and verified.

Validation: `go test -race ./cryptoprov/inmemcrypto -run '^TestConcurrentKeyOperations$' -count=1 -timeout=60s`
reproduced registration/lookup races before the fix.
`go test -race ./cryptoprov/inmemcrypto -run '^TestConcurrentKeyOperations$' -count=5 -cpu=1,4,8 -timeout=120s`
passed afterward, checking concurrent RSA/ECDSA generation/lookup/export,
unique IDs, exact missing-key errors, signer identity, PKCS#1/SEC1 parsing,
signatures with original/exported keys, and independent mutable PEM buffers.
`make test RACE=true TEST_FLAGS=-count=1` passed with SoftHSM/local-kms
fixtures and no cached results, including both providers' concurrency tests.
`make lint` passed with zero issues; `make build docs` and `make covtest`
passed (**90.2%** aggregate coverage; some unchanged packages used cached
coverage results).

The same-host Go 1.27 linux/amd64 comparison used
`go test ./cryptoprov/inmemcrypto -run '^$' -bench '^BenchmarkGetKey$' -benchmem -benchtime=100ms -count=5 -cpu=1`.
Median hits were 12.25 → 17.15 ns/op with 0 allocations; misses were
1902 → 1983 ns/op with 512 B / 9 allocations. Key generation is excluded
from timing; these serial lookup results do not measure mixed-workload
throughput.

**AU1 / XPKI-049, 050, 054, 057 — Fixed on 2026-09-24:** the decisions were
approved on 2026-09-24:

- **049.** CSR extensions are deny-by-default: an empty `allowed_extensions`
  allows none from the CSR, while RA `SignRequest.Extensions` keep "empty =
  all". SKI, KU, SAN, BasicConstraints, AKI, EKU and OCSP no-check are never
  taken from a CSR. The RA may still supply them. An allow-listed CSR AIA or
  CRL DP is kept only when the issuer generates none, which preserves the
  SHAKEN delegate CSR flow. The template is built from `allowed_fields` only
  (nil = subject and all SANs).
- **050.** One extension per OID. Raw extensions resolve as profile
  `extensions` > RA > CSR. Profile `policies`/`ocsp_no_check` replace any raw
  copy. For other template-built OIDs (KU, EKU, basic constraints, SKI/AKI,
  SAN, AIA, CRL DP) a kept raw profile or RA extension overrides the
  profile-derived value. `Validate` rejects repeated or colliding profile
  OIDs.
- **054.** Explicit times outside the envelope are rejected: NotBefore
  before now − backdate, NotAfter not after NotBefore, or lifetime longer
  than expiry. Issuer clipping fails when no validity remains.
- **057.** A populated `allowed_profiles` filters named and wildcard
  profiles alike and must include `delegated_ocsp_profile`.

The new `authority/README.md` documents the flow and the per-extension
source table. The codemap, README, `csr.SignRequest` docs and API docs are
updated, and the ROADMAP item is removed.

Validation: the new `authority/issuer_policy_test.go` and `config_test.go`
cases failed before the fix. A hostile CSR obtained `keyCertSign`, a
code-signing EKU, a forged AKI/SKI and OCSP no-check. A CSR SAN bypassed
`allowed_fields` and the DNS regex, a CSR CRL DP overrode the issuer's,
duplicate OIDs produced unparsable certificates, and populated
`allowed_profiles` did not filter named profiles. A throwaway probe on
unfixed `HEAD` issued reversed-validity, overlong and 24h-backdated
certificates. After the fix, `make test RACE=true TEST_FLAGS=-count=1` passed
with SoftHSM/local-kms fixtures. `make lint` passed with zero issues.
`make build docs` passed, and `make covtest` passed at **90.4%** aggregate
(authority fresh; unchanged packages used cached coverage results). No
benchmark was needed (AU1 is policy-only). Compatibility: CSRs with
non-profile-owned extensions under an empty allow-list are now rejected (or
dropped with `omit_disabled_extensions`). CSR `otherName` SANs are no longer
issued. An RA sending only `NotAfter = now + expiry` must shorten it by the
backdate.

**CU1 / XPKI-037, 041, 039, 044 — Fixed on 2026-09-24:** approved decisions
were an explicit system-root opt-in (041) and a new context-aware entry
point (037).

- **041.** `WithSystemRoots(bool)` is the only way to trust
  `x509.SystemCertPool()`. The flavor is resolved after all options: Optimal
  with trust roots, Force without them, and the last `WithBundleFlavor`
  wins. `NewBundler` rejects Optimal without trust roots and unknown
  flavors. `VerifyOptions().Roots` is never nil, and an Optimal `Bundle`
  with a nil `RootPool` fails. `xpki-tool cert validate` uses
  `WithSystemRoots` instead of assigning `RootPool`.
- **037.** `BundleContext`/`ChainFromPEMContext` are new, and
  `Bundle`/`ChainFromPEM` delegate with `context.Background()`. Each AIA
  request uses `NewRequestWithContext` with a deadline of the client
  `Timeout`, or 3s when it is zero. Only a 200 response of at most 1 MiB is
  parsed, and body bytes are never logged or returned.
- **039.** A URL is marked as seen before it is fetched, so it is requested
  at most once per call. The next call retries it.
- **044.** `HTTPClient` is marked `Deprecated` as unused; it was not
  activated.

Docs: codemap invariants and test layout, the `certutil/doc.go` example
(compiled), a README trust note, and regenerated API docs.

Validation: before the fix, the new tests showed the unfixed code accepting
non-200 and 2 MiB responses, hanging on a stalled server, logging the body,
and fetching a failing URL 2·depth+1 times. A subprocess probe with
`SSL_CERT_FILE` showed Optimal without roots trusting the system root, and
`cert validate --root <empty>` accepted the chain. After the fix,
`make test RACE=true TEST_FLAGS=-count=1` passed with SoftHSM/local-kms
fixtures, and `make lint` passed with zero issues. `make build docs` passed,
and `make covtest` passed at **90.4%** aggregate. Benchmark evidence for 039
is in the performance table. Compatibility: Optimal without roots is now an
error rather than ambient system trust. A root file without certificates no
longer degrades `cert validate` to Force. Non-200 or >1 MiB AIA responses
are rejected.

**JW1 / XPKI-070, 071, 072 (2026-09-24).** Decisions: accept a key only when
it is the single eligible one, pass the token algorithm through the new
optional `AlgorithmKeySet.GetKeyForAlgorithm` (`KeySet` is unchanged), treat
`PublicKeys` as kid-less keys that also match by RFC 7638 thumbprint, and
default to a 10s cooldown, 10s fetch timeout and 1 MiB limit.

- **070.** `NewRemoteKeySet(ctx, url, opts...)` takes `WithHTTPClient`,
  `WithRefreshCooldown`, `WithFetchTimeout` and `WithMaxResponseSize`. A
  refetch starts at most once per cooldown, counted from the end of the last
  fetch. Each fetch has a context deadline and a body limit, and errors never
  echo the body. The shared fetch ignores waiter cancellation, and the cache
  is published before waiters wake. PR #534 review: a fetch counter keeps
  lookups that missed against an older snapshot from starting another fetch
  when the cooldown is 0, and the read limit no longer overflows at
  `math.MaxInt64`.
- **071.** Eligibility: `use` is empty or `sig`, and the JWK `alg`, key type
  and curve fit the token alg. Zero eligible keys return a wrapped
  `ErrKeyNotFound`, and several return `ErrAmbiguousKey`. The parser passes
  `token.SigningMethod`.
- **072.** `PublicKeys` take part in kid-less selection and thumbprint
  matching. Unsupported entries fail the lookup.

Docs: codemap invariants and test layout, a README parser note, the ROADMAP
JWKS entry (remaining: TTL background refresh and `ParserConfig` options),
and regenerated API docs.

Validation: a scratch test on a HEAD worktree showed 20 fetches for 20
unknown kids, a waiter still blocked after the first timed out on a stalled
endpoint, an 8 MiB JWKS accepted, an empty or `enc` kid returning the
encryption key, and `PublicKeys` ignored. After the fix, the new
`jwks_test.go`/`jwks_internal_test.go` tests pass, including a
controlled-clock rotation test and a concurrent rotation race test.
`make test RACE=true` passed with SoftHSM/local-kms fixtures, and
`make lint` passed with 0 issues. `make build docs` passed, and
`make covtest` passed at **90.6%** aggregate. Benchmark evidence is in the
performance table. Compatibility: key-not-found text is now
`kid="<kid>": key not found`. Kid-less tokens against several same-type
signing keys fail as ambiguous. A key published within 10s after a fetch
waits for the cooldown.

**DP1 / XPKI-075, 076, 074 (2026-09-24).** Decisions: an opt-in replay
store (nil keeps the old, replay-unsafe behavior), a bounded in-memory store
that fails closed when full, keep https as the default scheme and add a
trusted `ExternalURL` origin, and verify signatures with go-jose inside
`jwt/dpop`, so the advertised PS\*/EdDSA algorithms work. Package `jwt` is
unchanged, and `ath` is decoded from a local proof-claims struct.

- **075.** `VerifyConfig` gained `ReplayCache`, `AccessToken` and
  `ExpectedThumbprint`, plus `VerifyClaimsContext`, `NewMemoryReplayCache`,
  `ErrReplay`, `ErrReplayCacheFull`, `AccessTokenHash`,
  `ClaimAccessTokenHash` and `Result.AccessTokenHash`. The store is called
  last, only for a fully valid proof. Its key is SHA-256(thumbprint, jti),
  retained through `iat+10m` or an earlier `exp`, inclusive. `AccessToken`
  requires `ExpectedThumbprint`. Claims and header are decoded
  case-sensitively. The signer's jti is now 22
  characters.
- **076.** `ExternalURL` overrides the client-controlled scheme/host.
  `normalizeHTU` compares scheme/host case-insensitively without default
  ports, normalizes escapes, keeps path case and dot segments, and ignores
  query/fragment. The request URI and the signer keep `RawPath`.
- **074.** `JSONWebSignature.Verify` with the embedded JWK runs before any
  claim is read.

New finding **XPKI-108** (LOW, Open): `htm` is still compared
case-insensitively. It was left unchanged because fixing it would reject
lowercase-method clients.

Docs: `doc.go` usage (compiled by `ExampleVerifyRequestClaims`), codemap
rules, concept rows and test layout, the ROADMAP DPoP entry (remaining:
shared-store implementation and server nonces), and regenerated API docs.

Validation: a scratch test on a HEAD worktree accepted a replayed proof and
`/api/A` for `/api/a`, rebuilt a plain-HTTP request as https, and failed
PS256/EdDSA with `unsupported algorithm`. After the fix, the new
`verify_policy_test.go` and `htu_internal_test.go` tests pass, including a
32-goroutine duplicate-proof race (exactly one accepted) and a
controlled-clock expiry test. `go test ./jwt/dpop -race -count=5`,
`make test RACE=true` (SoftHSM/local-kms) and `make lint` (0 issues) passed.
`make build docs` passed, and `make covtest` passed at **90.7%** aggregate
(`jwt/dpop` 93.7%). Benchmark evidence is in the performance table. A
`/code-review` pass then reproduced four issues: `ath` accepted without
`cnf.jkt`, case-insensitive claim names, dot-segment resolution of the
received path, and a replay at exactly `expiresAt`. All four are fixed and
tested, and `jwt/dpop` race (`-count=5`), lint and coverage (93.5%) were
rerun. Compatibility: path case now matters in `htu`, while scheme/host case,
default ports and escaping no longer do. The new checks apply only when
their fields are set.

**AT1 / XPKI-078, 079 (2026-09-25).** Decisions: `WithTokenExpiry` takes
precedence over the inner provider's `TokenExpiry`; if neither is positive,
`Sign` fails (no built-in default). A caller-supplied `exp` is kept, even
past the lifetime, and normalized to NumericDate. `ParseToken` rejects
`pat.` tokens without `exp` unless `WithAllowNoExpiry` is set for migration.
`New` gained variadic options (existing calls compile), and `TokenPrefix` is
exported.

- **078.** `Sign` copies the claims, normalizes present `exp`/`iat`/`nbf` to
  NumericDate (rejecting unparsable ones), and adds `exp`/`iat`/`nbf` (the
  last two only when absent) via `jwt.TimeNowFn`. `TokenExpiry()` reports
  the effective lifetime (negative → 0). `ParseToken` requires `exp`; under
  the opt-in an unparsable `exp` is still rejected (`invalid exp claim`),
  and revocation still applies.
- **079.** With a nil `dp`, `PublicKey` returns nil (no fallback to the inner
  provider's key), and `pat.` `Sign`/`ParseToken` return `data protection
  not configured`. Plain JWTs still delegate.

Docs: `doc.go` usage (compiled by `ExampleNew`), codemap rules and concept
row, and regenerated API docs.

Validation: a scratch test on a HEAD worktree accepted a token 100 years
after signing with an 8h inner provider, and `New(nil, nil).PublicKey()`
panicked. After the fix, `TestSign_Expiry`, `TestSign_CallerClaims`,
`TestParse_ExpiryBoundary`, `TestParse_LegacyNoExpiry` and `TestPublicKey`
pass. `go test ./jwt/accesstoken -race -count=5`, `make test RACE=true`
(SoftHSM/local-kms) and `make lint` (0 issues) passed. `make build docs`
passed, and `make covtest` passed at **90.8%** aggregate
(`jwt/accesstoken` 94.0%, `PublicKey` 0% → 100%). No benchmark was needed.
Compatibility: `New(dp, nil).Sign` without `exp` needs `WithTokenExpiry`,
parsed claims include the added time claims, and legacy tokens without `exp`
need `WithAllowNoExpiry`. A `/code-review` pass found that only `exp` was
normalized, so a `time.Time` `nbf` was not enforced; `iat`/`nbf` are now
normalized (the new cases fail with the `exp`-only version), with the
accurate `invalid exp claim` error, the negative `TokenExpiry()` reported
as 0, and multi-line test tables. The same `time.Time` gap in `jwt` is new
open finding **XPKI-109** (needs approval; unscheduled). Review items that
contradict the approved policy (capping or rejecting a caller `exp`) were
not applied.

**AU2 / XPKI-051, 052, 053, 100-authority (2026-09-25).** Decisions: on
renewal failure, keep serving from a delegated responder that is still valid
at signing time, otherwise return an error (never the CA key). For fixtures,
the new test-only `internal/testenv` (`RequireTCP`) gate with
`XPKI_INTEGRATION=required` exported by the Makefile; an unreachable fixture
skips only in optional mode, and a reachable fixture always runs.

- **051.** Responder issuance uses its own `renewLock`; `Issuer.lock` guards
  only profiles. Lock order `renewLock` → `lock`.
- **052.** `caResponder` is immutable from `CreateIssuer`; the delegated
  responder is an `atomic.Pointer` snapshot. One caller renews; callers with a
  still-valid responder do not wait (`TryLock`); callers without one wait and
  re-check.
- **053.** A renewal failure with a valid cache logs and uses it, with no retry
  for 1 minute (`ocspRenewRetryInterval`); without one, `SignOCSP` returns a
  wrapped error and no response. `CreateDelegatedOCSPSigner` returns the error.
  Delegated `NextUpdate` is capped at the responder's `NotAfter`. Queued
  callers share a failed attempt's error; the retry window is lock-free
  (atomic `ocspRenewal`). `CreateIssuer` rejects a delegated profile that is
  missing, lacks OCSP signing, or has expiry ≤ `ocsp_expiry`. A responder
  capped by an expiring CA is re-issued at most once a minute.
- **100-authority.** Only `TestNewRoot` needs local-kms and is gated;
  `TestShakenRoot`/`TestIssuerSign` use `inmemcrypto`. SoftHSM was not used.

Docs: `authority/README.md` OCSP responder section, codemap (invariants,
concept rows, tests, fixture table), AGENTS.md fixture rule, ROADMAP and
coverage-plan notes, and regenerated API docs.

Validation: before the fix, a deadline-bounded test deadlocked (051), and
concurrent cold `SignOCSP` in a HEAD worktree raced under `-race` (052).
The 053 nil dereference was unreachable, masked by the 051 deadlock. After
the fix, `ocsp_responder_test.go` and `TestNewIssuerDelegatedOCSP` pass, and
`go test ./authority -race -count=20 -run 'OCSP|Responder'` passed. The
fixture modes were checked with `kms2` stopped (skip / required-fail), and
with a dummy server on the port, where the test ran and failed. `make lint`
(0 issues), `make test RACE=true TEST_FLAGS=-count=1`, `make build docs` and
`make covtest` (**91.2%**) passed. Benchmark (`BenchmarkSignOCSP`, benchstat
vs a HEAD worktree): delegated warm lookup 264 → 37 ns serial and
258 → 9.7 ns on 4 CPUs, 4 → 0 allocs; signing unchanged or −1.2%.
Issuance (cold start/renewal) costs 318 µs, with no pre-fix baseline because
of the deadlock.
A `/code-review` pass led to the shared-failure, lock-free retry window,
consistent `CreateDelegatedOCSPSigner` error and profile validation
follow-ups. `TestDelegatedOCSPWaitersShareFailure` fails (33 vs 1 CA
signatures) without the fix. `BenchmarkDelegatedOCSPRetryWindow` measured
47.8 → 10.5 ns on 4 CPUs. The `ThisUpdate` ≥ responder `NotBefore` rejection
was not applied (not required by RFC 6960; it would add post-renewal
failures).
PR #537 review follow-ups: the delegated profile's effective EKU is decoded
(a raw EKU extension must list OCSP signing, and `fillTemplate` honors it);
the profile snapshot is revalidated before each issuance, covering
`AddProfile` replacement; the waiter test uses a hook instead of a sleep.
A second round judges a failed attempt from its completion time, rejects CA
delegated profiles, and requires `expiry > ocsp_expiry + backdate + 1m`.
Compatibility: `delegated_ocsp_profile` issuers now construct instead of
hanging, unless the profile is missing, lacks OCSP signing, or its expiry is
not longer than `ocsp_expiry` (such configs never worked). `SignOCSP` can now
return an error (no responder) where it would have panicked.

**PK1 / XPKI-001, 002, 003, 005, 007, 100-crypto11 — Fixed on 2026-09-25.**
Approved decisions: a per-path module refcount (the last `Close` finalizes,
never a module initialized outside this package), `Close() error`, blocking
at a per-slot cap of 1024 configurable with `WithMaxSessions`, and a `Close`
that rejects new work and waits for in-flight operations.

- **001.** New `crypto11/module.go` registry: one `*pkcs11.Ctx` per
  resolved library path. The first reference runs `C_Initialize`; the last
  runs `C_Finalize`, then `Destroy`. `Close` is idempotent, closes this
  wrapper's pooled and login sessions, and sets `Ctx` to nil. Every
  `Ctx`-using method goes through the lifecycle guard and returns
  `errClosed` after `Close`.
- **002.** Pools are created and looked up under `PKCS11Lib.mu`
  (`acquirePool`); `setupSessions` was removed.
- **003.** Pools are created on first use for any slot; an invalid slot fails
  in `C_OpenSession` and never blocks.
- **005.** `sessionPool` bounds live sessions per slot. Borrowers wait on a
  `sync.Cond`, and a return never blocks. Sessions are closed on panic and
  on `sessionUnusable` codes. Nested borrowing was removed: key generation
  draws randomness on the held session, and `KeyInfo` uses one session.
  `KeyInfo` and `DestroyKeyPairOnSlot` use the pool; `EnumKeys` keeps a
  guarded read-only session for write-protected tokens.
- **007.** `Init` takes a module reference first and unwinds it (and the
  login session) on any later error.
- **100-crypto11.** `TestMain` loads SoftHSM only when the config exists and
  closes it explicitly. SoftHSM tests use `requireP11` →
  `internal/testenv.RequireFile`.

Docs: codemap (files, invariants, concept rows, test layout, fixture
gating), `crypto11/doc.go` lifecycle sample (compiled), `internal/testenv`
doc, ROADMAP, and regenerated API docs.

Validation: pre-fix reproductions ran in a HEAD worktree. A fresh
`C_Initialize` after `Init`+`Close`, and after a failed `Init`, returned
`CKR_CRYPTOKI_ALREADY_INITIALIZED` (001/007). A `-race` data race hit
`sessions.go:47` (002). `GenRandom` on a pool-less slot did not return
within 3s (003). The saturation benchmark left 76 of 1,100 borrowers stuck
with a peak of 1,100 sessions (005). After the fix, the fake-session pool
tests pass, including under `-race -cpu 1,4,8`. So do the SoftHSM lifecycle
tests and the re-executed fresh-process child tests, which prove
`C_Finalize` ran and that an external module is not finalized. The fixture
modes were checked with the config moved away (21 skips / required-fail)
and with a broken config (fail). `make lint` (0 issues), `make test
RACE=true`, `make build docs` and `make covtest` (**91.5%**) passed.
Benchmarks (benchstat against the HEAD worktree, `-cpu 1,4,16 -count 6`):
`GenRandom`/ECDSA `Sign` show no significant change except +2.1% for
one-CPU parallel `GenRandom`, with allocations unchanged. Init/Close is
30–61% faster and leaks 0 sessions (one per cycle before). Saturation
peaks at 1,024 with 0 stuck. Compatibility: `Close()` returns `error`, and
`Ctx` is nil after `Close`. Caller-owned `NewSession` sessions must be
closed before the last `Close`. More than 1,024 concurrent operations per
slot now wait instead of opening more sessions.

PK1 `/code-review` follow-ups (2026-09-25). Seven were applied, each with a
regression test that failed with its fix reverted:

- `ExportKey` is guarded (`TestExportKey_CloseAfterLookup`, using the
  `exportKeyFound` hook).
- The public caller-session methods and `EnumTokens(true)` return
  `errClosed` after `Close` instead of panicking; they wrap unexported
  versions used by the pooled paths.
- `moduleID` matches paths by `os.SameFile` (symlinks, hardlinks) and bare
  names by name, not under the working directory (`TestModuleID`,
  `TestInit_SymlinkSharesModule`).
- `Close` runs once, and concurrent calls wait and share its result.
- Close errors for sessions returned during `Close` are joined into its
  result.
- The redundant `err = nil` was removed.

Declined: per-lib mutex contention (no measured cost), and `GenRandom`
reusing `randomOnSession` (a different short-read contract). Deferred: re-login
after a device error, recorded as XPKI-110 (PK3). PR #540 review follow-ups:
modules are matched by dynamic loader handle on unix, so a bare-name alias
no longer gets finalized (`TestLifecycle_BareNameAlias`). `ExportKey` runs
its lookup and token info in one pooled operation
(`TestExportKey_CloseWhileAdmitted`). `Init` joins cleanup errors. Each test
failed with its fix reverted; `make covtest` is at **91.4%** after them. Second PR round: a discarded session holds its pool capacity until
`CloseSession` returns (`TestWithSession_DiscardHoldsCapacity` failed on the
old ordering), a nil `Option` is rejected, `EnumTokens(true)` holds its guard
until return, the saturation benchmark propagates borrower errors with a
bounded fill wait, and the stale FINDINGS text was corrected. Re-validated after the follow-ups: `go test -race ./crypto11` ×3 and with `-cpu 1,4,8`, `make lint`,
`make test RACE=true`, `make build docs` and `make covtest`.

**PK2 / XPKI-011, XPKI-006 (2026-09-25):** decisions: internal readers use a
checked `bytesToUlong` (exact `C.sizeof_ulong` width, `binary.NativeEndian`,
no `unsafe`; `errMalformedUlong` from `EnumKeys`, `KeyInfo` and
`FindKeyPair`). The exported `BytesToUlong` keeps its signature, returns
`^uint(0)` for malformed input and is `Deprecated`. Token selection matches
every nonempty configured field, so both set means AND. `Init` rejects a
config with neither before loading the module (`errNoTokenSelector`).
Pre-fix evidence came from a HEAD worktree. A 1-byte slice decoded seven
bytes past its end, `nil` panicked, and SoftHSM opened the unit-test token
for label plus a wrong serial and for serial plus a wrong label. The new
selection table, run against HEAD's predicate, failed 6 of 10 cases.
Validation: `go test -race -count=1 ./crypto11`, `make lint`, `make build
docs` and `make covtest` (**91.5%**; `crypto11` 81.0%) passed. Limitation: the
4-byte CK_ULONG branch is untested because no 32-bit C toolchain is
installed. No benchmark was run; the plan asked for boundary tests only.

**JW2 / XPKI-066, XPKI-104, XPKI-100-jwt (2026-09-25):** decisions: the
standalone symmetric provider signs without a `kid` by default, so the header
seen by the secdi/ReadMe consumer is unchanged. It verifies kid-less tokens
and its own `kid` (a nonempty string from `WithHeaders`), and any other `kid`
is `unexpected kid`. One `validateHeaders` check after the options, in every
constructor, rejects an `alg` override. With HS keys it also rejects a `kid`
other than the signing key's; asymmetric `kid`, `typ` and `jwk` stay
overridable. The constructor rejects an empty key and copies the key.
`Test_SignPrivateKMS` is gated with `testenv.RequireTCP` on `localhost:14555`.
Pre-fix evidence came from HEAD's `jwt.go`: self-verification failed, a
custom `kid` panicked, 7 of 11 header cases were accepted, and a config
provider with `kid` "0" could not verify its own token. Fixture modes were
checked with `kms1` stopped: skip when optional, fail when required, fail on
a fake listener, and pass after `make start-local-kms`. Validation: `make
lint`, `make covtest` (**91.5%**; `jwt` 92.6% → 93.0%) and `make build docs`
passed. No benchmark was needed. No race run was needed either, because no
shared state changed.

**CU2 / XPKI-035 (2026-09-25):** decisions: copy-on-write pools under
`Bundler.mu` (RWMutex). The exported fields are kept as set-up state, and
there is no cross-call AIA coalescing (recorded in ROADMAP). `verifyChain`
learns into a private clone and publishes it once with `learn`, merging when
another call published first. Pre-fix: `TestBundlerConcurrentBundle` gave 60
race reports and a fatal concurrent map access. After: it passes `-race
-count=20`, and certutil passes with `-race -cpu 1,4,8`. Benchmarks (benchstat,
`-count 6 -cpu 1,4`): warm Bundle unchanged (51 allocs) at pool sizes
0/100/1000. Learning one intermediate costs one pool clone: +2.6% at pool 100
and +23–25% at pool 1000 (707 → 884 µs, 20.6 → 346 KiB). `make lint`, `make
covtest` (**91.6%**) and `make build docs` passed. `make test RACE=true`
passed on its second run; the first hit the unrelated `authority` timing
flake recorded as XPKI-111 (AU5).

**CP1 / XPKI-016, XPKI-026, XPKI-099-cryptoprov, XPKI-100-cryptoprov
(2026-09-26):** decisions: re-adding the same provider instance (compared with
`reflect`, including the default) is a no-op. A different instance with a
registered or the default manufacturer and model returns a wrapped
`ErrDuplicateProvider`, so `Load` rejects two configs with the same key.
Nil and typed-nil providers return a wrapped `ErrNilProvider` from `New` and
`Add`. `Crypto` keys a `providerKey` struct map published copy-on-write
through an `atomic.Pointer`: `Add` holds a mutex, and lookups do not lock.
`Load` closes the providers it already loaded when it fails. Pre-fix:
`TestCryptoConcurrentAddLookup` gave 17 race reports, and `concurrent map
writes` without `-race`. A HEAD worktree showed panics for nil and typed-nil
providers, silent replacement, a shadowed default-key provider, and a
duplicate `inmem` `Load` that succeeded. After: `-race -count=20 -cpu 1,4,8`
passes. Benchmarks (benchstat, `-count 6 -cpu 1,4`): lookup hits −15–31%
serial and −19–25% on 4 CPUs, 0 allocs; misses unchanged except one +7.6%
case. An RWMutex variant was rejected (46–71 ns parallel hits against 5.7–5.9
ns). With one `Add` in 1024: 29.9 / 7.3 ns (serial / 4 CPUs). Tests: only four
SoftHSM tests remain, gated by `requireSoftHSM`. HEAD failed 7 tests without
the config. Now optional → 4 skips and a pass, required → fail, broken →
fail. Built-in loaders are no longer unregistered, `Test_Load` no longer
needs a checkout named `xpki`, and the empty `Test_Aws`/`Test_Gcp` became
`TestLoad_KMSProviders` (no KMS contacted). Validation: `make lint` (0
issues), `make test RACE=true TEST_FLAGS=-count=1`, `make build docs` and
`make covtest` (**91.8%**; `cryptoprov` 81.6% → 84.9%) passed.

**GC1 / XPKI-018, XPKI-023, XPKI-025-gcpkmscrypto (2026-09-26):** decisions:
Close rejects new calls with `ErrClosed`, waits for in-flight ones (the
crypto11 PK1 model, `enter`/`exit` plus `sync.Once`), then closes the client
and returns its error; the `KmsClient` field is kept. Missing optional KMS
metadata is omitted (no `protection`/`algo` Meta, nil `CreationTime`), and
labels are sorted. A missing signature checksum or a nil response is an
error. Nil, typed-nil or unsupported signer options and wrong digest lengths
fail before any RPC; there is no default digest. Pre-fix (HEAD worktree):
Close returned during in-flight signs, Sign after Close panicked, a
Close/Sign overlap raced, nil opts, missing checksums, missing metadata and
nil responses panicked, and label order varied. After: the lifecycle,
signer and metadata tests pass `-race -count=20 -cpu 1,4,8`. No benchmark
(the guard adds two short mutex sections per call and does not serialize
signing). Validation: `make lint` (0 issues), `make test RACE=true
TEST_FLAGS=-count=1`, `make build docs` and `make covtest` (**91.7%**;
`gcpkmscrypto` 95.6% → 97.1%) passed. The CP1 review item, `Load` rejecting a
non-comparable default provider, is recorded as XPKI-113 (CP3).

**CP3 / XPKI-113 (2026-09-26, PR #544 review):** `Load` no longer re-adds the
default provider, so a non-comparable default loads; `Crypto.Add`'s re-add
no-op is documented for comparable providers only, and
`gcpkmscrypto.ErrClosed` for KMS-calling operations only.
`TestLoad_NonComparableDefault` failed on the committed code and passes now;
`go test -race ./cryptoprov/...`, `make lint` and `make build docs` passed.

## Classification and priority

The findings index still calls its classification column `Severity`, but its
values are **types**. This plan preserves those types and assigns **proposed
severity** independently. Severity estimates assume the affected feature is
used; deployment exposure can change the estimate. They are not CVSS scores.

| Severity | Meaning for this library | Priority |
| --- | --- | --- |
| CRITICAL | Untrusted input can bypass certificate issuance policy at a trust boundary | P0: address first |
| HIGH | Authentication/trust protection fails, a normal feature hangs/crashes, or concurrent use can stop a process | P1: next remediation cycle |
| MEDIUM | A supported operation fails under particular inputs/configuration, or reliability/performance is materially impaired | P2: scheduled remediation |
| LOW | Limited interoperability, metadata, documentation, or tooling impact | P3: follow-up |

**Importance = severity first, then type.** For a sortable score, assign
severity CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1 and type security=6, bug=5,
race=4, correctness=3, performance=2, docs=1. Score = `10 × severity + type`;
higher scores go first. Thus HIGH/correctness (33) precedes MEDIUM/security
(26), and HIGH/security (36) precedes HIGH/bug (35). This makes the combination
explicit without letting a cosmetic security-related item outrank an outage.

A batch inherits its highest item score; lower-priority companions do not
acquire a higher severity. Break ties by production exposure, dependencies,
then smaller reviewable scope. Regression risk below describes the **change**,
not the severity of the existing defect.

Every implementation batch has **one package owner**. Scripts, workflow, and
build configuration have separate non-Go owners. Multi-package findings are
split into linked portions; an ID is complete only after all portions are
complete. The suffixes in this plan are scope labels, not replacement IDs.

`Decision` means the existing FINDINGS compatibility decision must be resolved
before implementing the changed contract. It does not block test design,
reproduction, or this plan. Do not silently change public APIs to make an
implementation easier; record larger contract work in [ROADMAP.md](ROADMAP.md).

## Batch queue

Order is the default execution order within each priority. Dependencies and
the test prerequisites below can move a small preparatory change earlier.

| Batch | Owner | Findings (package portion where split) | Priority / score | Regression risk | Decision |
| --- | --- | --- | --- | --- | --- |
| AU3 | `authority` | 055 | P1 / 34 | High: live maps and pointer ownership | Snapshot/mutation contract |
| OA1 | `jwt/oauth2client` | 081, 080 | P1 / 34 | High: registry consistency and mutable config pointers | Scope of unused verification settings |
| GC2 | `cryptoprov/gcpkmscrypto` | 020, 019, 022 | P1 / 33 | High: persisted key identity and destructive operations | Version and unsupported-purpose policy |
| CU3 | `certutil` | 036, 042, 038, 045 | P2 / 25 | Medium: return values and slice ownership | 036, 038 |
| CU4 | `certutil` | 103-certutil; 099-certutil, 100-certutil | P2 / 25 | Low: invalid-input errors; medium for fixture separation | None |
| AW1 | `cryptoprov/awskmscrypto` | 025-awskmscrypto, 031; 100-awskmscrypto | P2 / 25 | Medium: signing options and key purpose | Unsupported-purpose policy |
| HC1 | `cmd/hsm-tool/cli` | 084, 101; 100-hsm-cli | P2 / 25 | Medium: CLI errors, exit status, parser state | None |
| XC1 | `cmd/xpki-tool/cli` | 103-xpki-cli, 102 | P2 / 25 | Medium: exit status used by scripts | Partial endpoint success policy |
| GC3 | `cryptoprov/gcpkmscrypto` | 021, 024 | P2 / 23 | Medium: client factory, retry classification, timing | Context propagation extension |
| AW2 | `cryptoprov/awskmscrypto` | 033, 032 | P2 / 23 | Medium: listing completeness and throttling | Partial results and prefix meaning |
| CP2 | `cryptoprov` | 027 | P2 / 23 | Medium: URI parsing and credential precedence | Query/path conflict policy |
| CU5 | `certutil` | 043 | P2 / 23 | Medium: encrypted-key compatibility | Supported PKCS#8 encryption formats |
| PK3 | `crypto11` | 110 | P2 / 23 | Medium: re-login on a live token after device errors | Re-login trigger and PIN retention |
| CS1 | `csr` | 059; 100-csr | P2 / 23 | High: existing names and nil/empty SAN semantics | DNS validation and error API |
| AR1 | `armor` | 047 | P2 / 23 | Medium: acceptance of legacy corruption fixtures | CRC acceptance contract |
| BU1 | root build tooling | 096, 095-build | P2 / 23 | Low–medium: tool compatibility and formatter gate | Coordinate CI requirement |
| BU2 | `docker-compose.yml` | 098 | P2 / 23 | Medium: emulator reachability and image behavior | None |
| CI1 | `.github/workflows` | 095-CI, 094 | P2 / 23 | Medium: required checks and skipped-job semantics | 094, 095 |
| DT1 | `dataprotection` | 083, 106 | P2 / 21 | Low for documentation/test correction; high if format changes | Rotation API is separate roadmap work |
| AU4 | `authority` | 058 (revalidate) | P3 / 15 | Low: serialization casing | No YAML data-loss fix justified |
| IV1 | `internal/version` | 097-version | P3 / 15 | Low–medium: fallback version reporting | Generated-file policy |
| BU3 | root build tooling | 097-build | P3 / 15 | Low–medium: build/install paths | Coordinate IV1 |
| AW3 | `cryptoprov/awskmscrypto` | 034 (revalidate) | P3 / 13 | Medium: credential-provider precedence | Demonstrate refresh failure first |
| JW3 | `jwt` | 073 | P3 / 13 | Medium: consumers of custom JOSE headers | Header removal/migration policy |
| TC2 | `testca` | 063 | P3 / 13 | Medium: PEM versus DER and OpenSSL compatibility | Preserve test-only panic contract |
| AU5 | `authority` (tests) | 111 | P3 / 15 | Low: test-only timing | None |
| JW4 | `jwt` | 112 | P3 / 13 | Medium: configured HS384/HS512 consumers | Pin the key ring to HS256 or configure algs |

Execution dependencies:

- AU1 is **Fixed (2026-09-24)** and AU2 is **Fixed (2026-09-25)**. The AU2
  lock order (`renewLock` → `Issuer.lock`) and the AU1 extension/validity
  rules in `Issuer.Sign` must hold for AU3; do not take a registry mutex
  around `Sign` or responder renewal.
- CU1 is **Fixed (2026-09-24)**: trust/client options are specified
  (`WithSystemRoots`, `BundleContext`, per-traversal URL set). CU2 is
  **Fixed (2026-09-25)** and kept them; no lock is held during AIA I/O or
  `x509.Verify`. CU3/CU4 must keep the copy-on-write rule: never modify a
  published `IntermediatePool`/`KnownIssuers` in place.
- CU4 precedes XC1's nil-issuer assertion update. The CLI portion must verify
  propagation even though the nil check belongs in `certutil`.
- GC2 must keep generation, lookup, export, signing, and destruction on the
  **same selected version**. Do not change just the string-building helper.
- DP1 is **Fixed (2026-09-24)** within `jwt/dpop`: local proof claims carry
  `ath`, and go-jose verifies every allowed algorithm; `jwt.Claims` and
  `jwt.VerifySignature` are unchanged. Keep the order signature → claims →
  replay store. XPKI-108 (`htm` case) is a separate open item.
- BU1 precedes CI1. IV1 defines the runtime fallback before BU3 wires builds;
  neither portion alone closes 097.
- XC2 is **Fixed (2026-09-20)**; overlapping CLI coverage/race processes now
  use isolated suite fixtures and must retain separate output files.
  TC1 is **Fixed (2026-09-20)**; concurrent `testca` generation is supported
  with immutable defaults/option data and signers supporting concurrent use.
  Direct entity-field access must not overlap issuance or serial allocation.
- For 100, make each package's unit tests independent of optional infrastructure,
  while keeping a CI mode that **fails** when required integrations are missing.
  Do not turn fixture failures into a passing but untested CI run. The
  convention is fixed by AU2: gate with `internal/testenv` (`RequireTCP`, or
  `RequireFile` for a fixture file such as the SoftHSM config, added by PK1),
  with `XPKI_INTEGRATION=required` exported by the Makefile.

## Evidence and coverage baseline

Code was located with the codebase graph and
[codemap](Documentation/codemap.md), then implementations and test assertions
were inspected. Test names below are stable references; source links point to
the owning file. `Partial` means useful existing assertions but no complete
regression test for the finding. `Characterization` means a test deliberately
asserts the defective current behavior and must change with the fix. `Absent`
means no targeted assertion was found, even if other tests execute the function.

An existing local `coverage.out` reports **90.2%** statement coverage. It was
**not regenerated by this planning task**, and has no revision provenance that
establishes it as a fresh measurement. The historical
[coverage report](Documentation/coverage-plan.md) records 90.1%; do not present
either number as new validation. Its high percentages do not establish input,
policy, lifecycle, or concurrency completeness.

| Package | Existing local profile | Particularly misleading or missing coverage |
| --- | ---: | --- |
| `crypto11` | 77.2% | `Close` 0% (after PK1: package 79.1%, `Close` 96.7%); `BytesToUlong` 100% does not cover short buffers (after PK2: package 81.0%, malformed lengths covered) |
| `cryptoprov` | 84.8% | AWS/GCP wrapper tests are empty; registry concurrency absent |
| `cryptoprov/inmemcrypto` | 84.3% | Serial key operations only |
| `cryptoprov/testprov` | 73.9% | Serial key operations only |
| `cryptoprov/awskmscrypto` | 89.9% | Listing contents/prefix and credential refresh are not established |
| `cryptoprov/gcpkmscrypto` | 95.6% | Generation and Close 100%; permissive mocks and no concurrent close |
| `certutil` | 94.5% | `ExpiresInHours` 0%; sorting 100% without ownership/tie assertions (after CU2: 93.5%, concurrent Bundle covered) |
| `authority` | 91.0% | Fresh delegated responder creation bypassed; constructor only 37.2% |
| `csr` | 94.3% | SAN 92.9% without the full nil/empty/duplicate/validation matrix |
| `jwt` | 91.8% | Known symmetric-provider defects explicitly asserted (after JW2: 93.0%, replaced by round-trip and header tests) |
| `jwt/dpop` | 90.8% | Request matching 100% without case-sensitive path and replay checks |
| `jwt/accesstoken` | 86.4% | `PublicKey` 0%; expiration tested only when supplied by the caller |
| `jwt/oauth2client` | 97.3% | RegisterClient 100% without concurrent operations |
| `armor` | 90.6% | Legacy CRC acceptance rules embedded in corruption expectations |
| `dataprotection` | 87.1% | Round trips do not validate documented usage limits |
| `cmd/hsm-tool/cli` | 85.7% | Parser reuse masks a missing-required-flag scenario |
| `cmd/xpki-tool/cli` | 96.2% | Nil-issuer panic and success-on-error are characterization tests |
| `internal/version` | 100% | No test that a built binary reports the current build version |
| `testca`, scripts, build, workflow | Not in this Go coverage profile | Testca is excluded; scripts/build/CI need their own smoke checks |

Current workflow evidence takes precedence over stale summaries: the actual
[workflow](.github/workflows/unittest.yml) sets `MIN_TESTCOV: 90`, and its
status comparison is strictly `>`, while AGENTS/codemap still mention 80.
[Make helpers](.project/gomod-project.mk) already provide `fmt-check` and a
`lint` target including `vulns`; the workflow runs `covtest`, not `lint`.
Therefore 095 is principally CI wiring and a non-mutating lint entry point,
not creation of a nonexistent formatter check or vulnerability target.

## Package assessments

### authority — AU1, AU2, AU3, AU4

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-049 — CRITICAL / security / 46 — **Fixed (AU1, 2026-09-24)** | [Issuer.Sign](authority/issuer.go) builds the template from `allowed_fields` only, never copies CSR extensions wholesale, always drops `csrDeniedExtensions` from the CSR, requires explicit allow-listing for other CSR OIDs (empty = none), and lets issuer-generated AIA/CRL DP win. RA extensions keep "empty = all". | **Covered:** [issuer_policy_test.go](authority/issuer_policy_test.go) uses hostile signed CSRs with nil/explicit fields, empty/populated allow-lists, deny versus omit, SAN bypass, issuer-generated CRL DP/AIA and RA-owned EKU, asserting on the parsed issued certificate. |
| XPKI-050 — HIGH / correctness / 33 — **Fixed (AU1, 2026-09-24)** | One extension per OID. Raw extensions resolve as profile `extensions` > RA > CSR; profile `policies`/`ocsp_no_check` replace any raw copy (`setExtension`); other kept raw extensions override template-built values. `Validate` and `Sign` reject repeated or colliding profile OIDs. | **Covered:** `TestSignExtensionPrecedence`, `TestSignProfileGeneratedExtensionsWin` and `TestProfileValidateExtensions` assert extension count, criticality and bytes. |
| XPKI-054 — HIGH / correctness / 33 — **Fixed (AU1, 2026-09-24)** | [validityWindow](authority/issuer.go) rejects NotBefore before now − backdate, NotAfter not after NotBefore, and lifetime > expiry; shorter lifetimes and future NotBefore are kept; issuer clipping fails when nothing remains. | **Covered:** `TestValidityWindow` (fixed clock, exact boundaries) and `TestSignValidity` (through `Sign`, issuer clipping). |
| XPKI-057 — HIGH / correctness / 33 — **Fixed (AU1, 2026-09-24)** | `issuerHasProfile` in [config.go](authority/config.go) applies a populated `allowed_profiles` to named and wildcard profiles; empty keeps named only; a populated list must include `delegated_ocsp_profile`. | **Covered:** `TestLoadConfigAllowedProfiles` (named/wildcard × nil/empty/populated, exact key absence) and `TestLoadConfigAllowedProfilesDelegatedOCSP`. |
| XPKI-051 — HIGH / bug / 35 — **Fixed (AU2, 2026-09-25)** | [CreateDelegatedOCSPSigner](authority/ocsp.go) issues through `newDelegatedResponder` under `renewLock`; `Issuer.lock` guards only profiles (lock order `renewLock` → `lock`). | **Covered:** `TestDelegatedOCSPFreshCreation`, `TestDelegatedOCSPFreshSignOCSP` (deadline-bounded) and `TestNewIssuerDelegatedOCSP` verify EKU, no-check, missing AIA/CRL, CA signature, reuse and the parsed response. |
| XPKI-052 — HIGH / race / 34 — **Fixed (AU2, 2026-09-25)** | `caResponder` is immutable from `CreateIssuer`; the delegated responder is an `atomic.Pointer` snapshot; one caller renews and valid-cache callers never wait. | **Covered:** `TestDelegatedOCSPConcurrentColdStart`, `TestDelegatedOCSPConcurrentRenewal` (32 goroutines + `AddProfile`, exactly one issuance) and `TestCAResponderConcurrent` under `-race`; `BenchmarkSignOCSP` recorded. |
| XPKI-053 — HIGH / bug / 35 — **Fixed (AU2, 2026-09-25)** | A valid cached responder is used on renewal failure (retry after 1 minute); otherwise `SignOCSP` returns a wrapped error and no response, never the CA key. `NextUpdate` is capped at the responder's `NotAfter`. | **Covered:** `TestDelegatedOCSPRenewalFailureUsesValidCache`, `TestDelegatedOCSPFailureWithoutValidResponder` (missing and expired), `TestDelegatedOCSPResponderClipsNextUpdate`, `TestDelegatedOCSPShortLivedResponderIsNotReissued`. |
| XPKI-055 — HIGH / race / 34 | [Authority](authority/authority.go) mutates registry maps without locks; [Issuer.Profiles](authority/issuer.go) returns a live map after releasing its read lock. Synchronize registries and define snapshot/ownership rules for maps and pointed-to profiles. | **Partial:** `TestNewAuthority` and extension tests validate serial lookup and live profile identity. Add concurrent registration/lookups/enumeration, iteration during writes, and caller mutation of returned snapshots. A shallow map copy alone does not make mutable `*CertProfile` values safe. |
| XPKI-058 — LOW / bug / 15, **claim partly disproved** | `IssuerConfig.Type` lacks tags, but an actual `yaml.Unmarshal` into this type loaded `type: ocsp` as `"ocsp"` with no error. JSON marshaling emitted `"Type":"ocsp"`. Revalidate/replace the YAML-loss description; add explicit tags only for an agreed serialization format. | **Partial:** config tests do not assert Type. Add YAML/JSON decoding and round-trip key-casing assertions. Avoid treating this as an outage fix or changing accepted legacy JSON casing unintentionally. |

AU1 and AU2 are Fixed; their compatibility notes are recorded under Completed batches.
The existing root bootstrap, delegated OCSP and SHAKEN delegate fixtures still
issue. AU2/AU3 need one documented
lock order; avoid callbacks or signing while holding a registry mutex.
**Benchmarks:** AU2's OCSP baseline and comparison are recorded below. AU3 should have a lookup/update benchmark if choosing snapshots versus
locks; it is recommended, not a blocker for a minimal race fix. AU1/AU4 need no
performance benchmark. Fixture scope 100-authority was completed by AU2.

### certutil — CU1 through CU5

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-037 — HIGH / security / 36 — **Fixed (CU1, 2026-09-24)** | [fetchRemoteCertificate](certutil/bundler.go) uses `NewRequestWithContext` with the `BundleContext` context and a deadline of the client `Timeout` (3s when zero), accepts only 200, rejects bodies over 1 MiB, and never logs or returns body bytes. | **Covered:** [bundler_aia_test.go](certutil/bundler_aia_test.go) covers 200 DER/PEM at the limit, non-2xx with valid bytes, oversized chunked bodies, a stalled server with a zero-timeout client, cancellation via `BundleContext`, and log content; `TestBundlerAIA` keeps DER/PEM/malformed/disabled behavior. |
| XPKI-041 — HIGH / security / 36 — **Fixed (CU1, 2026-09-24)** | [NewBundler](certutil/bundler.go) resolves the flavor after all options, rejects Optimal without trust roots and unknown flavors, and trusts system roots only with `WithSystemRoots`; `VerifyOptions().Roots` is never nil and an Optimal `Bundle` with a nil `RootPool` fails. | **Covered:** `TestNewBundlerTrustRoots` (nil/empty/explicit roots × default/Force/Optimal/both orders, unknown root, unknown flavor, cleared `RootPool`), subprocess `TestBundlerSystemRoots` with `SSL_CERT_FILE`/`SSL_CERT_DIR`, and CLI `validate_empty_roots`. |
| XPKI-039 — MEDIUM / performance / 22 — **Fixed (CU1, 2026-09-24)** | `fetchIntermediates` marks each URL seen before fetching; failing and duplicate URLs are requested once per call and retried on the next call. | **Covered:** `TestBundlerAIARequestsPerTraversal` (exact per-path counts at depth 1/2/4, warm call makes none), `TestBundlerAIARetriesOnNextCall`, and `BenchmarkBundlerAIAFailingURL`. |
| XPKI-044 — LOW / docs / 11 — **Fixed (CU1, 2026-09-24)** | `HTTPClient` is marked `Deprecated` and documented as never read; `WithHTTPClient` documents the request rules. The global was not activated. | **Covered:** `TestBundlerAIAUsesInjectedClient` asserts the injected transport carries the request. |
| XPKI-035 — HIGH / race / 34 — **Fixed (CU2, 2026-09-25)** | [Bundler](certutil/bundler.go) guards its fields with `mu` once in use. Calls verify a `snapshot` without the lock, and `verifyChain` learns into a private clone that `learn` publishes (merging after a concurrent publish). Pools and maps once read are never modified. The exported fields are set-up state. | **Verified:** `TestBundlerConcurrentBundle` (warm plus two AIA chains, 8 workers each, released together, fixtures built first) failed with 60 races and a fatal map access before the fix and passes `-race -count=20` after. It checks exact chains and roots, per-worker fetch bounds and no request after learning. `TestBundlerLearnMerge` and `TestBundlerLearnNilPool` cover the merge and nil set-up paths. The benchmark is in the performance table. |
| XPKI-036 — MEDIUM / bug / 25 | `Bundle` returns `(nil, nil)` for empty input. After the existing decision, return a clear input error for nil and empty certificate slices. | **Characterization:** `TestBundlerChainBehavior` explicitly requires nil chain and no error. Replace this expectation with exact error behavior and test downstream callers; do not merely add a new test elsewhere. |
| XPKI-042 — MEDIUM / bug / 25 | [BuildBundle](certutil/bundle.go) dereferences the input chain, its certificate, and status. Validate required members and return an error, or initialize an optional status according to the contract. | **Partial:** bundle-loading tests cover fully populated chains. Add nil chain/certificate/status separately, plus legitimate rootless Force output so validation does not reject a supported chain shape. |
| XPKI-038 — LOW / correctness / 13 | `SortBundlesByExpiration` aliases the input backing array and uses unstable sorting. After the existing decision, return a copied, stably ordered slice without reordering the caller's slice. | **Partial:** `Test_SortBundlesByExpiration` checks only descending output for distinct expiries. Add input preservation, shared backing-array independence, equal-expiry ordering, and nil/empty slices. Copying certificates themselves is not implied. |
| XPKI-045 — LOW / docs / 11 | `ExpiresInHours` truncates an integer duration while its comment promises rounding up. Prefer documenting truncation; changing rounding is a separate observable-behavior decision. | **Absent:** existing profile reports 0%. If behavior changes, add deterministic fractional/negative/exact-hour cases using a controlled time seam. A comment-only correction needs no new test mirroring the one-line implementation. |
| XPKI-103-certutil — MEDIUM / bug / 25 | [CreateOCSPRequest](certutil/ocsp.go) dereferences crt/issuer before checking either. Return wrapped invalid-input errors before any work. | **Partial:** `Test_LoadAndVerifyBundleFromPEM` checks valid and mismatched issuers. The nil panic is only characterized in CLI tests. Add package-local black-box nil certificate, nil issuer, both nil, valid chain, and mismatch cases. |
| XPKI-043 — MEDIUM / correctness / 23 | [GetKeyDERFromPEM / ParsePrivateKeyPEMWithPassword](certutil/pem.go) handles legacy PEM encryption but does not decrypt encrypted PKCS#8 containers. Define supported encryption formats; implement explicit support or report an accurate unsupported-format error and correct the claim. | **Partial:** `TestPEMMalformedInputs` covers malformed legacy encryption and unencrypted PKCS#8, not an encrypted PKCS#8 round trip. Add generated encrypted RSA/EC samples, correct/wrong/missing password, malformed parameters, and preserved existing formats. Supporting one scheme must not be documented as supporting all PKCS#8 encryption. |

CU1 is Fixed; its compatibility notes are recorded under Completed batches.
CU2 can regress trust and cache behavior; test chain output, root selection,
timeouts, and successful AIA recovery together. CU3 has medium contract risk,
CU4 low input-validation risk, and CU5 medium encoding/dependency risk.
**Benchmarks:** CU1's 039 and CU2's 035 comparisons are recorded in the
performance table (CU2: warm/learn Bundle, serial/parallel, clone cost versus
pool size). CU4 fixture
changes and the other helpers need no benchmark. See 099/100 scopes below.

### jwt — JW1 (Fixed), JW2 (Fixed), JW3

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-070 — HIGH / security / 36 — **Fixed (JW1, 2026-09-24)** | [RemoteKeySet](jwt/jwks.go) used unbounded `http.DefaultClient` reads and refetched on every unknown kid. It now takes options for an injected client, a per-fetch deadline (10s), a body limit (1 MiB) and a refresh cooldown (10s, measured from the end of the last fetch). Inflight coalescing is kept, the shared fetch ignores waiter cancellation, and the cache is published before waiters wake. | **Verified:** `TestRemoteKeySetRefresh` covers a 50-kid flood costing 1 fetch, rotation with cooldown 0, a stalled endpoint timing out and recovering (no stuck inflight), 8 waiters sharing 1 fetch past a cancelled waiter, exact and over-limit sizes, the default limit, a 500 response that is neither echoed nor retried, invalid JSON, an injected client and the parser. `TestRemoteKeySetRotationCooldown` (controlled clock) shows rotation refused inside the cooldown and served after it. `TestRemoteKeySetConcurrentRotation` runs under the race detector. PR #534 review: `TestRemoteKeySetStaleSnapshotSharesFetch` (stale snapshot shares a fetch or its failure; fails with the check disabled) and a `math.MaxInt64` size limit case (failed before the fix). |
| XPKI-071 — MEDIUM / correctness / 23 — **Fixed (JW1, 2026-09-24)** | Selection now requires exactly one eligible key: `use` empty or `sig`, and when the alg is known, a matching JWK `alg`, key type and curve. The alg arrives through the optional `AlgorithmKeySet.GetKeyForAlgorithm`, which the parser uses. `GetKey` is unchanged in signature and checks only `use`. Ambiguous and ineligible results return wrapped `ErrAmbiguousKey`/`ErrKeyNotFound`. | **Verified:** `TestStaticKeySetSelection` (32 cases: enc-only, multiple signing keys, reordered sets, incompatible alg/curve/JWK alg, duplicate kids, unsupported alg) and `TestParserKeySelection` (real kid-less RS256/ES256 tokens through `NewParser` in two key orders, plus the ambiguous rejection). |
| XPKI-072 — MEDIUM / bug / 25 — **Fixed (JW1, 2026-09-24)** | `StaticKeySet.PublicKeys` is now used. Entries are kid-less RSA/ECDSA keys that take part in empty-kid selection together with `KeySet`, and match a kid by RFC 7638 SHA-256 thumbprint only when no `KeySet` entry has that kid. Unsupported or nil entries fail every lookup. | **Verified:** RSA-only and EC-only, ambiguity across both lists, a single eligible key across both lists, `KeySet` precedence, thumbprint fallback, and rejected ed25519/nil entries. `TestParserKeySelection/public_keys_only` verifies real RS256, ES256 and thumbprint-kid tokens and rejects a different key. |
| XPKI-066 — HIGH / bug / 35 — **Fixed (JW2, 2026-09-25)** | [NewProviderWithSymmetricKey](jwt/jwt.go) keeps its key in the ring under its `kid` (empty unless `WithHeaders` sets one), and `allowNoKid` makes `ParseToken` verify kid-less tokens and that `kid`. Other kids are rejected, and the default header is unchanged (no `kid`). Empty keys are rejected and the key is copied. | **Verified:** the characterization test became `TestStandaloneSymmetricProvider` (round trip, raw-key verification, wrong key, tampering, ES256 token refused, caller slice mutation) and `TestStandaloneSymmetricProviderKeyID` (own kid, kid-less, other kid, kid on a kid-less provider). It failed against HEAD's `jwt.go`. |
| XPKI-104 — MEDIUM / bug / 25 — **Fixed (JW2, 2026-09-25)** | The constructor creates `headers`, `WithHeaders` creates a missing map, and `validateHeaders` runs in every constructor. It rejects an `alg` override, a `kid` other than the signing key's for HS keys, and a non-string or empty standalone `kid`. | **Verified:** the assert-panic became `TestStandaloneSymmetricProviderOptions` (nil/empty/custom headers, option order, alg and kid rejects, empty key, exact decoded headers) and `TestProviderHeaderValidation` (config and crypto-signer constructors), plus `TestWithHeadersNilMap`. At HEAD there was a panic and 7/11 cases were accepted. |
| XPKI-073 — LOW / correctness / 13 | [signJWT](jwt/sign.go) generates jti in the protected header. Stop presenting that header as the token identifier; preserve caller-provided payload jti and define whether absent payload jti is generated. This is not by itself proof that an otherwise valid signed token is invalid. | **Partial:** signing/claims tests verify signatures and claims, but not absence of header jti or preservation of a payload identifier. Add decoded header/payload assertions and compatibility coverage for consumers of the old custom header. |

JW1 is **Fixed (2026-09-24)**. The cooldown does not block rotation
indefinitely: a new key is served on the first lookup after the cooldown, and
waiter cancellation does not affect the shared fetch. Miss tracking uses no
per-kid memory, only the last fetch time and error. The benchmark comparison
is in the performance table. JW2 must keep the `AlgorithmKeySet` selection
rules; any kid policy it chooses for the symmetric provider does not go
through `KeySet`. JW2/JW3 need no benchmark. JW2 also owns the jwt portion of fixture finding 100.
JW2 is **Fixed (2026-09-25)**; see [completed batches](#completed-batches).
The standalone kid policy does not go through `KeySet`. PR #543 follow-ups
(2026-09-26): the standalone provider is pinned to HS256, and a present `kid`
is rejected when it has none. The `NewProvider` ring's HS384/HS512 acceptance
is recorded as XPKI-112 (JW4). JW3 (XPKI-073, the header `jti`) remains and
must keep the `validateHeaders` rules.

### jwt/dpop — DP1

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-075 — HIGH / security / 36 — **Fixed (DP1, 2026-09-24)** | [VerifyClaimsContext](jwt/dpop/verify.go) required jti but never consumed it and had no access-token input. It now takes an opt-in atomic `VerifyConfig.ReplayCache` (key SHA-256(thumbprint, jti), retained until `iat+10m` or an earlier `exp`, called only after every other check) with a bounded, fail-closed `NewMemoryReplayCache`. `AccessToken` requires a matching `ath`, and `ExpectedThumbprint` binds the proof key to the token `cnf.jkt`. Token-endpoint proofs leave both empty. A nil store is documented as not replay-safe. | **Verified:** `TestVerifyClaims_Replay` (first use and replay, reused jti, per-key scope, store error through the request context, rejected proofs not consuming the jti, retention at `iat+10m` and `exp`, fixed-length key), `TestVerifyClaims_MemberNameCase`, `TestVerifyClaims_ConcurrentReplay` (32 simultaneous duplicates, exactly one accepted), `TestMemoryReplayCache_Expiry` (controlled clock: full → fail closed, retention at the expiry instant, eviction after it, re-admission), and `TestVerifyClaims_AccessTokenBinding` (RFC 9449 §7.1 vector, missing/wrong ath, wrong `cnf.jkt`, ath without `cnf.jkt`, token endpoint). The signature is verified before claims are read. |
| XPKI-076 — HIGH / correctness / 33 — **Fixed (DP1, 2026-09-24)** | An empty server-side URL scheme still means https (proxy compatibility). The trusted `VerifyConfig.ExternalURL` origin overrides the client-controlled scheme/host. `normalizeHTU` lowercases scheme/host, drops default ports, normalizes escapes, keeps path case and dot segments, and ignores query/fragment. The request URI and the signer keep `RawPath`. | **Verified:** `TestVerifyRequestClaims_RequestURI` uses server-style `httptest` requests with an empty URL scheme and covers TLS and plain HTTP, `/v1/Resource` versus `/v1/resource`, `%2f`/`%2F`/`/`, host case and `:443`, ignored query/fragment, `ExternalURL` overriding internal and spoofed Hosts, invalid `ExternalURL` forms, a relative htu, and a signer round trip of an escaped path. `TestNormalizeHTU` has 22 table cases; `/admin/../v1/Resource` does not match `/v1/Resource`. |
| XPKI-074 — MEDIUM / correctness / 23 — **Fixed (DP1, 2026-09-24)** | The advertised list is kept. The proof is now verified by go-jose `JSONWebSignature.Verify` with the embedded JWK, which implements RS\*, PS\*, ES\* and EdDSA and rejects a key type or curve that does not fit the alg. `jwt` is unchanged. | **Verified:** `TestVerifyClaims_Algorithms` verifies real signatures for all 10 algorithms. It rejects another key's signature, ES256 with a P-384 JWK, RS256 with an EC JWK and EdDSA with an RSA JWK, and rejects ES256K early as `alg not allowed`. Existing HMAC/private-JWK/multi-signature rejections still pass. |

The protected-resource binding and URI checks should follow
[RFC 9449 §4.3](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.3), with
replay policy informed by [§11.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.1).
DP1 is **Fixed (2026-09-24)**. Legacy behavior is kept when the new fields
are unset and is documented as providing no replay protection; enforcement
is per `VerifyConfig`. The concurrency proof is
`TestVerifyClaims_ConcurrentReplay`, and the benchmarks are in the
performance table. A shared-store implementation and server-issued nonces are
in ROADMAP. XPKI-108 (`htm` compared case-insensitively) is open and
unscheduled; a fix needs a compatibility decision for lowercase-method
clients.

### jwt/accesstoken — AT1

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-078 — HIGH / security / 36 — **Fixed (AT1, 2026-09-25)** | [Sign](jwt/accesstoken/accesstoken.go) encrypted the supplied claims unchanged and ignored TokenExpiry. It now copies the claims, keeps and normalizes caller `exp`/`iat`/`nbf` (rejecting unparsable ones), and otherwise adds `exp` = now + `TokenExpiry()` (`WithTokenExpiry`, else the inner provider's) with `iat`/`nbf` when absent; a non-positive lifetime fails. `ParseToken` rejects `pat.` tokens without a parsable `exp` unless `WithAllowNoExpiry`. | **Verified:** `TestSign_Expiry` (option, inner, option over inner, zero, unset, negative), `TestSign_CallerClaims` (seven `exp` encodings kept past the lifetime, caller `iat`/`nbf` including `time.Time`, a future `time.Time` `nbf` enforced, invalid `exp`/`iat`/`nbf`, caller-map non-mutation), `TestParse_ExpiryBoundary` (valid at `exp`, expired one second later), `TestParse_LegacyNoExpiry` (default rejection, opt-in, revocation, unparsable `exp`). `TestAT`/`TestATWithProvider` assert the exact added claims; revocation and inner-JWT tests retained. |
| XPKI-079 — MEDIUM / bug / 25 — **Fixed (AT1, 2026-09-25)** | PublicKey dereferenced a nil dp. A nil dp is now a documented state: `PublicKey` returns nil and `pat.` `Sign`/`ParseToken` return `data protection not configured`; plain JWTs still delegate. | **Verified:** `TestPublicKey` checks symmetric dp with and without an inner provider (nil), the exact key of a stub asymmetric dp, and nil dp with and without an inner provider (nil key, exact errors, plain JWT parses). `PublicKey` coverage 0% → 100%. |

Tests live in [accesstoken_test.go](jwt/accesstoken/accesstoken_test.go).
AT1 is **Fixed (2026-09-25)**. No benchmark was needed; encryption format
and key rotation are unchanged (see DT1 and ROADMAP).

### crypto11 — PK1, PK2

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-001 — HIGH / bug / 35 — **Fixed (PK1, 2026-09-25)** | [module.go](crypto11/module.go) shares one context per resolved path; the last [Close](crypto11/crypto11.go) finalizes, then destroys, never a module initialized outside this package. `Close() error` is idempotent, rejects new work, waits for borrowed sessions and closes this wrapper's sessions. | **Verified:** [lifecycle_test.go](crypto11/lifecycle_test.go) covers shared refs, repeated close, a remaining wrapper still working, `errClosed` from every entry point, closing with live and active sessions (SoftHSM handle probes), and fresh-process children proving `C_Finalize` ran (and was skipped for an external init). `TestMain` closes explicitly. |
| XPKI-002 — HIGH / race / 34 — **Fixed (PK1, 2026-09-25)** | Pools are created and looked up under `PKCS11Lib.mu` in `acquirePool`, with the closed flag and active count; `setupSessions` is gone. | **Verified:** reproduced under `-race` in a HEAD worktree; `TestWithSession_ConcurrentPoolsAndClose` (8 slots × 8 workers plus Close behind a barrier) passes under `-race -cpu 1,4,8`. |
| XPKI-003 — HIGH / bug / 35 — **Fixed (PK1, 2026-09-25)** | Pools are created on first use for any slot; an invalid slot returns the wrapped `C_OpenSession` error and releases its pool slot. | **Verified:** the pre-fix hang reproduced (3s deadline); `TestWithSession_PoolCreatedOnFirstUse`, `TestWithSession_OpenErrorReleasesSlot` and a new SoftHSM wrapper's first operations pass with deadlines. |
| XPKI-005 — HIGH / performance / 32 — **Fixed (PK1, 2026-09-25)** | `sessionPool` caps live sessions per slot (`DefaultMaxSessions` 1024, `WithMaxSessions`); borrowers wait, returns never block, and panics or `sessionUnusable` codes close the session. Nested borrows were removed (`randomOnSession`, single-session `KeyInfo`). | **Verified:** `BenchmarkSession_Saturation` went from 76/1,100 stuck (peak 1,100) to 0 stuck (peak 1,024). Fake-session tests cover bounds, contention peak, disposal table, panic, open error and close while borrowed. Benchmarks are recorded under [completed batches](#completed-batches). |
| XPKI-007 — HIGH / bug / 35 — **Fixed (PK1, 2026-09-25)** | [Init](crypto11/config.go) takes a module reference first; a deferred `Close` unwinds the login session, pools and reference on every later error. | **Verified:** a fresh-process child shows the module finalized after an unknown label and after a wrong PIN, and a retry succeeding. `TestInit_FailureReleases` checks refs and live sessions in process. `Test_LoadConfigTwice` closes both wrappers. |
| XPKI-011 — HIGH / bug / 35 — **Fixed (PK2, 2026-09-25)** | [common.go](crypto11/common.go) `bytesToUlong` accepts exactly `ulongSize` (`C.sizeof_ulong`) bytes via `binary.NativeEndian` and returns `errMalformedUlong` otherwise. `EnumKeys`, `KeyInfo` and `FindKeyPair` propagate it. The deprecated exported `BytesToUlong` returns `^uint(0)` instead of panicking. No `unsafe` remains in `common.go`. | **Verified:** the pre-fix OOB read and nil panic were reproduced at HEAD. `Test_bytesToUlong_Malformed` (zero/short/long/double lengths with guard bytes), `Test_bytesToUlong_RoundTrip` (against miekg's own encoding, up to the largest CK_ULONG), `Test_keyTypeAndClass` and SoftHSM `Test_KeyTypeAndClass` pass. The 4-byte width was not run (no 32-bit toolchain). |
| XPKI-006 — MEDIUM / correctness / 23 — **Fixed (PK2, 2026-09-25)** | [selectToken](crypto11/config.go) returns the first token matching every nonempty selector (AND when both are set), `errTokenNotFound` when none match, and `errNoTokenSelector` when both are empty. `Init` checks for no selector before loading the module. | **Verified:** at HEAD, SoftHSM accepted conflicting selectors, and the table failed 6/10 cases against the old predicate. `Test_selectToken` (fixture-free matrix), `TestInit_NoTokenSelector` and SoftHSM `TestInit_TokenSelection` pass. |

PK1 and PK2 are **Fixed (2026-09-25)**; see [completed batches](#completed-batches).
PK3 (XPKI-110) remains. These fixes belong in lifecycle and input batches, not an indiscriminate HSM
rewrite. Regression risk is high, especially finalization ownership and
conversion across platforms. Use real SoftHSM plus small unexported seams only
where needed; do not invent a new broad mock hierarchy.
PK1's benchmark ([sessions_bench_test.go](crypto11/sessions_bench_test.go):
serial/parallel `GenRandom`, parallel sign, time-bounded saturation and
Init/Close with open/live session counts) is recorded under completed batches.
PK2 needed boundary tests, not a speed benchmark, and added them.

### cryptoprov — CP1, CP2

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-016 — HIGH / race / 34 — **Fixed (CP1, 2026-09-26)** | [Crypto](cryptoprov/provider.go) publishes a `providerKey` map copy-on-write (`atomic.Pointer`, `Add` under a mutex, lock-free lookups). Same-instance re-add is a no-op; a different instance with a registered or the default key is `ErrDuplicateProvider`; `Load` closes loaded providers on error. | **Verified:** [crypto_concurrency_test.go](cryptoprov/crypto_concurrency_test.go) reproduced 17 races and a fatal map write, then passed `-race -count=20 -cpu 1,4,8`; [crypto_test.go](cryptoprov/crypto_test.go) covers duplicates (registered, default, non-comparable values, key concatenation), the zero value and `Load` close-on-error; `Test_P11`'s double `Add` still passes. Benchmarked; see [completed batches](#completed-batches). |
| XPKI-026 — MEDIUM / bug / 25 — **Fixed (CP1, 2026-09-26)** | `New` and `Add` return a wrapped `ErrNilProvider` for nil and typed-nil providers (checked with `reflect`); `New` names the bad list index. | **Verified:** HEAD panicked on `New(nil, nil)` and a typed-nil `Add`; `TestNew_Nil`, `TestNew_DefaultOnly` and the nil `Add` cases assert exact messages and both `errors.Is`. |
| XPKI-027 — MEDIUM / correctness / 23 | [URI parsers](cryptoprov/uri.go) parse only `u.Opaque`, never RawQuery. Parse supported query attributes separately and preserve key identity; define duplicate/conflicting values and propagation of credentials/module selection. | **Partial:** [uri_test.go](cryptoprov/uri_test.go) covers only simple path-form attributes. Add query pin-value/module-path, encoded delimiters, invalid escaping, conflicting pin-source/pin-value, and legacy path compatibility. PrivateKeyURI exposes no credential fields, so parsing alone is not end-to-end propagation. |

URI query syntax and the conflicting-PIN case are described in
[RFC 7512 §2.3–2.4](https://www.rfc-editor.org/rfc/rfc7512.html#section-2.3).
**CP1 is Fixed (2026-09-26)**, including its 099/100 test portions; the 016
benchmark compared lock and snapshot overhead and chose the copy-on-write
snapshot (see [completed batches](#completed-batches)). CP2 has medium
compatibility risk. Keep PINs out of diagnostics while adding credential
parsing. CP2 needs no benchmark.

### cryptoprov/inmemcrypto — IM1; cryptoprov/testprov — TP1

These are **two separate batches**, even though their findings and designs
are similar. **TP1 is Fixed (2026-09-20) and IM1 is Fixed (2026-09-21)**;
the overall XPKI-017 finding is now **Fixed**.

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-017-inmemcrypto — HIGH / race / 34 — **Fixed (IM1, 2026-09-21)** | [provider.go](cryptoprov/inmemcrypto/provider.go) protects map publication/lookup with an RWMutex. Generation, signing, and PEM serialization remain outside the lock. Signer identity, missing-key errors, and PKCS#1/SEC1 export are preserved for this provider used by delegated OCSP code. | **Verified:** [concurrency_test.go](cryptoprov/inmemcrypto/concurrency_test.go) reproduced the race, then passed five repetitions at each of 1/4/8 CPUs. It checks generation/lookup/export overlap, key identity, parsed exports, signatures from original/exported keys, and independent PEM buffers. Serial lookup benchmarks, the uncached full race suite, lint, build/docs and coverage passed; see [completed batches](#completed-batches). |
| XPKI-017-testprov — MEDIUM / race / 24 — **Fixed (TP1, 2026-09-20)** | [provider.go](cryptoprov/testprov/provider.go) now protects map publication/lookup with an RWMutex. Generation and cryptographic operations remain outside the lock; signer identity, missing-key errors and URI-only export are preserved. | **Verified:** [concurrency_test.go](cryptoprov/testprov/concurrency_test.go) reproduced the map race/crash, then passed five repetitions at each of 1/4/8 CPUs. It checks concurrent generation/lookup/export through the public API, signatures and RSA decryption. Serial lookup benchmarks, the uncached full race suite, lint, build/docs and coverage passed; see [completed batches](#completed-batches). |

Regression risk is medium for completed IM1 and low–medium for completed TP1.
Both serial hit/miss benchmark comparisons are recorded above with generation
outside the timed loop. Mixed operations passed correctness checks under the
race detector; no mixed-workload throughput benchmark was run. Both fixes
lock only map access, preserving parallel generation and cryptographic work.

### cryptoprov/gcpkmscrypto — GC1, GC2, GC3

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-018 — HIGH / race / 34 — **Fixed (GC1, 2026-09-26)** | [Close](cryptoprov/gcpkmscrypto/gcpkmsprov.go) runs once, rejects new calls with `ErrClosed`, waits for in-flight calls registered by `enter`/`exit`, then closes the client and returns its error; the client field is kept. | **Verified:** [lifecycle_test.go](cryptoprov/gcpkmscrypto/lifecycle_test.go) blocks 4 signs in the fake RPC under 3 concurrent Close calls (Close stays blocked, the client is never closed mid-sign, one Close reports the client error), then checks `ErrClosed` with no RPC for every client-using method; passes `-race -count=20 -cpu 1,4,8`. |
| XPKI-023 — MEDIUM / bug / 25 — **Fixed (GC1, 2026-09-26)** | Getters everywhere; missing `VersionTemplate`/`CreateTime` omitted, labels sorted; nil responses are `empty response` errors; Sign requires `VerifiedDigestCrc32C` and a present, matching `SignatureCrc32C`. | **Verified:** [metadata_test.go](cryptoprov/gcpkmscrypto/metadata_test.go), [signer_test.go](cryptoprov/gcpkmscrypto/signer_test.go) and a bare key in `TestEnumKeysPagination` (all panicked or failed on HEAD) assert exact Meta, labels, `CreationTime`, errors and the five response-integrity cases. |
| XPKI-025-gcpkmscrypto — MEDIUM / bug / 25 — **Fixed (GC1, 2026-09-26)** | `signDigest` rejects nil/typed-nil opts, hashes other than SHA-256/384/512 and wrong digest lengths before any RPC; no default digest. | **Verified:** `TestSignRejectsOptionsLocally` (9 cases, no RPC recorded) and `TestSignRequest` (digest variant, name, CRC32C for 4 option types); HEAD panicked on nil opts. |
| XPKI-020 — HIGH / correctness / 33 | GetKey/genKey/keyVersionName and exported URI metadata assume version 1. Resolve an explicit version, preserve it in signer/exported identity, and use it consistently for public-key lookup, signing, metadata, and destruction. | **Characterization/partial:** `Test_KmsProvider` asserts serial=1; `TestKMSFailurePropagation` asserts destroying version 1. Add two versions with different public keys, reload an exported reference after rotation, disabled/missing versions, and verify exactly which version is signed/destroyed. Do not assume every asymmetric key has a useful Primary version. |
| XPKI-019 — MEDIUM / correctness / 23 | GenerateRSAKey pairs ASYMMETRIC_DECRYPT purpose with signing algorithms; Sign uses opts independently of the selected key algorithm. Reject unsupported decrypt purpose before creation, or design a proper decrypter separately; validate algorithm/hash compatibility. | **Partial but insufficient:** [Test_KmsProvider](cryptoprov/gcpkmscrypto/gcpkmsprov_test.go) returns one EC public key and arbitrary signature bytes even for RSA requests and accepts requests via mock.Anything. Add exact request matchers, realistic RSA keys, allowed/rejected purpose/hash matrix, and real local signature verification. |
| XPKI-022 — MEDIUM / correctness / 23 | KeyLabelAndID adds four UUID hex characters, then truncates the entire ID to 63 bytes; long labels can lose the entire random suffix. Sanitize labels/IDs according to their separate constraints and reserve enough random suffix space. | **Partial:** TestKeyLabelOrID compares two short names; coverage tests assert long label and ID lengths, preserving the problem. Add deterministic length/charset/truncation assertions, long-label suffix retention, invalid characters, and service collision handling. Avoid probabilistic uniqueness as the sole test. |
| XPKI-021 — MEDIUM / correctness / 23 | Init stores Endpoint but calls a factory with no endpoint input. Apply configured endpoint through the real SDK construction path. | **Absent for configuration wiring:** the gRPC pagination test constructs a local client itself. Add Init-to-local-server verification and default/custom endpoint cases, preserving authentication behavior and test-factory restoration. |
| XPKI-024 — MEDIUM / performance / 22 | genKey polls up to 60 times with unconditional one-second sleeps and substring error matching. Use cancellation-aware bounded waits and structured retry classification; stop immediately on permanent errors. | **Partial:** failure tests cover immediate errors, not pending generation/cancellation/exhaustion. Add fake-clock or controlled retry tests, precise attempt counts, and cancellation latency. Public methods currently create Background contexts, so caller cancellation needs a separately agreed context-aware API; fixing the internal wait alone does not supply it. |

GC2 has high persisted-identity risk and needs migration tests for saved URIs.
**GC1 is Fixed (2026-09-26)**; its guard does not serialize Sign, so 018
needed no benchmark. GC3 has medium transport risk; note that Close now also
waits for `genKey`'s generation wait, which GC3's cancellation-aware wait
will shorten. **Benchmark required for 024** before timing/retry
changes: attempts, cancellation latency, readiness latency, and allocations
with a deterministic fake service/clock, not a real 60-second cloud wait.

### cryptoprov/awskmscrypto — AW1, AW2, AW3

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-025-awskmscrypto — MEDIUM / bug / 25 | [sigAlgo](cryptoprov/awskmscrypto/signer.go) calls opts.HashFunc after selecting key type. Validate nil/unsupported options before any RPC with behavior aligned to the separately documented GCP contract. | **Partial:** [Test_KmsProvider](cryptoprov/awskmscrypto/awskmsprov_test.go) supplies normal hashes and checks Sign errors, not independent signature validity. Add nil options, typed-nil PSS options, valid PKCS#1/PSS/EC signatures, wrong digest sizes, and no RPC on invalid input. |
| XPKI-031 — MEDIUM / correctness / 23 | [GenerateRSAKey](cryptoprov/awskmscrypto/awskmsprov.go) creates ENCRYPT_DECRYPT keys but always returns a Signer. Reject unsupported purpose before side effects or implement a separately designed Decrypter; do not create an unusable key. | **Absent:** integration tests only generate purpose 1. Add purpose-2 behavior and assert CreateKey is not called on rejection, or encryption/decryption round trips if support is implemented. |
| XPKI-033 — MEDIUM / correctness / 23 | EnumKeys logs DescribeKey failures and continues, presenting incomplete results as success. Return a wrapped error with defined partial-result semantics and preserve service error identity. | **Absent for the failure:** tests require successful/nonempty lists. Add permission/throttle failures in first/middle/last pages, no silent omissions, and exact result/error assertions. |
| XPKI-032 — MEDIUM / performance / 22 | EnumKeys scans account pages and describes every key; prefix is only logged. Define whether prefix applies to key ID/alias/label, filter correctly, then optimize only service calls that can be avoided. | **Partial but weak:** Test_KmsProvider calls with `test_` and only asserts nonempty output before deleting listed keys. It does not prove filtering. Add controlled unrelated keys, pagination and exact contents, request counters, and bounded concurrency/throttling tests if parallel fetches are selected. Do not promise removal of N+1 calls without a viable metadata source. |
| XPKI-034 — LOW / correctness / 13, **revalidate** | Init manually replaces the SDK credential provider when access-key env vars exist. Redundancy is visible, but refresh failure is not demonstrated by this code alone. Compare actual SDK-chain behavior before removing the override; retain emulator credentials. | **Partial:** current test sets dummy static env credentials and checks endpoint/region behavior, not refresh/precedence. Add controlled expiring-provider/default-chain tests only for a demonstrated difference. Removing this branch does not make static environment credentials refreshable by itself. |

AW1/AW2 have medium API/operational risk; AW3 can change credential precedence
despite its low defect priority. **Benchmark required for 032:** increasing key
counts/page counts, prefix selectivity, calls per listing, latency and
allocations, using the existing KMS client seam and controlled latency. Include
throttled/error cases. Fix 033's truthfulness before claiming a faster listing.
AW1/AW3 need no benchmark. AW1 owns 100-awskmscrypto.

### jwt/oauth2client — OA1

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-081 — HIGH / race / 34 | [RegisterClient](jwt/oauth2client/provider.go) writes three registry maps without locks while lookups iterate/read them. Publish coherent registrations and synchronize all readers/writers. | **Partial:** [TestProviderRegistrationConflicts](jwt/oauth2client/request_coverage_test.go) correctly checks serial errors and override identity. Add actual concurrent register/lookup/enumeration and snapshot consistency, plus unchanged maps after failed registration. Test complete multi-index behavior, not just absence of a race report. |
| XPKI-080 — MEDIUM / correctness / 23 | [Client](jwt/oauth2client/client.go) stores but never reads verifyKey; JwksURL in [config.go](jwt/oauth2client/config.go) is unused. SetClientSecret mutates a config pointer read by token-request creation; Config exposes that pointer. Define ownership and synchronize mutable state. Clarify/deprecate unused verification settings or scope a real verification API separately. | **Partial:** `Test_Config`/`TestProvider` check configuration and setters; `TestTokenRequestAuthStyles` checks actual requests and caller-form preservation. None proves verification or concurrent secret updates. Add setter/request overlap, snapshot ownership, exact outgoing authentication, and tests for whichever verification contract is chosen. |

Regression risk is high if Config changes from a live pointer to a snapshot or
override semantics change. A mutex on the client cannot protect arbitrary
external mutation of its original config pointer. **Benchmark recommended**
for registry lookup/enumeration and request building under occasional updates,
particularly if deep copies are introduced. Both issues need race tests even
though 080's primary type remains correctness.

### csr — CS1

**XPKI-059 — MEDIUM / correctness / 23.** [SetSAN](csr/csr.go) classifies
and appends without deduplication or DNS validation; nil preserves existing
SANs and a non-nil empty slice clears them. [SignRequest](csr/csrprov.go)
also handles SAN input. Define canonicalization/validation rules and preserve
or explicitly migrate nil/empty behavior. Localhost, wildcard names, email,
IP, URI, and internationalized names need deliberate rules rather than an
overly restrictive DNS regex.

Coverage is **partial**: [TestSetSAN](csr/csr_test.go) checks counts for five
ordinary values; provider/parsing tests cover ordinary generated CSRs and
invalid requests. Add exact values/order, duplicates within each SAN type,
nil versus empty replacement including raw SAN extensions, invalid DNS, and
agreement between request generation and template mutation. The current
SetSAN signature cannot return an error, so strict validation needs a checked
API or an agreed compatible policy. Regression risk is **high** for name
acceptance. No benchmark is needed for this correctness fix unless profiling
later motivates a large-SAN optimization. CS1 owns 100-csr.

### testca — TC1, TC2

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-062 — MEDIUM / race / 24 — **Fixed (TC1, 2026-09-20)** | [configuration.go](testca/configuration.go) uses an atomic common-name counter; [Entity.IncrementSN](testca/entity.go) uses a per-entity mutex without locking generation/signing. `NextSN` remains exported; direct field access requires no calls in flight and entities must not be copied after first use. | **Verified:** [concurrency_test.go](testca/concurrency_test.go) reproduces the old races and checks unique names, complete serial ranges from zero/configured values, quiescent field updates, and shared-issuer certificate signatures. Twenty race repetitions at each of 1/4/8 CPUs, the uncached full race suite, lint, and coverage passed. See [completed batches](#completed-batches). |
| XPKI-107 — MEDIUM / race / 24 — **Fixed (TC1, 2026-09-20)** | The new shared-issuer test exposed `Issue` appending into caller-owned spare slice capacity. `Issue` now copies the option slice before adding its issuer, retaining receiver precedence. | **Verified:** reproduced the race and overwritten option; concurrent calls reuse one slice with spare capacity, verify receiver precedence and signatures, then confirm the caller's unused option still applies. Passed the same TC1 race/lint/coverage checks. |
| XPKI-063 — LOW / correctness / 13 | [ToPKCS8 / ToPFX](testca/utils.go) execute OpenSSL. Replace PKCS#8 encoding with stdlib plus PEM wrapping to preserve current output; PFX still needs a PKCS#12 implementation or an explicit OpenSSL dependency. Panic on test-fixture failure is an allowed package contract. | **Partial:** TestPFX only asserts no panic; it does not decode the result. Add RSA/EC PKCS#8 parse/round trips and PEM type checks; verify PFX cert/key/password with the chosen implementation. Test failure/dependency behavior without requiring removal of the intentional test-only panic convention. |

Completed TC1 has low–medium sequencing/API risk; TC2 has medium encoding
risk. **No benchmark was required for TC1**: only serial allocation is locked,
and parallel uniqueness/signature checks and race tests passed. Direct field
mutation during calls and copying an entity after first use remain unsupported.

### armor — AR1

**XPKI-047 — MEDIUM / correctness / 23.** [Decode](armor/armor.go)
requires a five-character CRC suffix and rejects a mismatch. Accept armor
without that footer while retaining framing/base64 validation. Full
[RFC 9580 §6.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-6.1)
compatibility also means CRC absence, malformation, or disagreement alone must
not reject an otherwise valid OpenPGP object; simply making CRC optional and
retaining all mismatch rejection is incomplete.

Coverage is **partial with legacy expectations**:
[Test_ArmorDecode / Test_ArmorDecode_Corrupted](armor/armor_test.go) check
decoded blocks/counts from fixtures, some relying on CRC rejection. Classify
each corrupted fixture by actual malformed framing/base64 versus CRC-only
failure; update only the appropriate expectations. Add missing/present/bad
CRC, payload lengths with base64 padding, multiple blocks, and rest-byte
preservation. Regression risk is **medium** because accepted input broadens;
document the CRC field's meaning when absent. No benchmark is required.

### dataprotection — DT1

**XPKI-083 — MEDIUM / docs / 21.** [NewSymmetric / Protect](dataprotection/symmetric.go)
derive a key with HKDF and prepend a random 12-byte GCM nonce, without key IDs
or rotation hooks. Document required high-entropy secret material, that HKDF
does not replace password hardening, per-key usage limits, and operational
rotation/decryption retention. Derive numerical limits from the chosen threat
model/AEAD guidance before publishing them; do not invent an arbitrary safe
message count. Keep a new versioned ciphertext/rotation API in ROADMAP.

Coverage is **partial for crypto behavior, absent for operational guidance**:
[TestNewSymmetric](dataprotection/symmetric_test.go) covers round trips, short
input and authentication failures. Its short `"secret"` is a test fixture,
not an example of production entropy. Documentation examples should use
generated key material. Regression risk is **low** for documentation; changing
KDF/blob format would be high and outside this batch. No benchmark is required.

**XPKI-106 — LOW / bug / 15 (new test finding).** The same test assigns
`protected[0] = protected[1]`. With equal random nonce bytes, the input is
unchanged and Unprotect correctly succeeds, contradicting the test's required
authentication error. The current assertion is therefore **flaky**, not a
reliable tamper check. Use a guaranteed mutation (for example, flip one bit),
assert the input changed, and retain the actual authentication-error assertion.
Regression risk is **low** and confined to test correctness. No benchmark is
needed. The source comment references the new ID; the test behavior remains
unchanged in this planning task.

### cmd/hsm-tool/cli — HC1

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-084 — MEDIUM / bug / 25 | [CryptoProv](cmd/hsm-tool/cli/cli.go) uses Panicf on missing/bad config. Return errors through command Run paths, retaining useful diagnostics and the documented parse/run exit behavior. | **Partial:** command tests exercise valid providers and ordinary errors, not bad-config panic handling. Add missing config, nonexistent/invalid config, and provider-init failure; assert returned errors and no panic. Verify the real executable's exit status as an integration check without mixing its parent package into this implementation batch. |
| XPKI-101 — MEDIUM / docs / 21 | [TestParse](cmd/hsm-tool/cli/hsm_cli_test.go) reuses one parser/config after setting --cfg and then expects a parse without --cfg to succeed. Recreate both parser and destination per independent test case. | **Existing assertion is misleading:** it tests retained state rather than a fresh invocation. Assert the actual missing-flag error with fresh state and retain a separate reuse test only if parser reuse is supported intentionally. |

Regression risk is **medium** because CryptoProv's return signature affects
commands throughout this package. Compile all callers and smoke-test `hsm`
and `csr` command paths. No benchmark is required. Include 100-hsm-cli.

### cmd/xpki-tool/cli — XC1, XC2

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-102 — MEDIUM / correctness / 23 | [OCSPFetchCmd.Run](cmd/xpki-tool/cli/ocsp.go) prints endpoint errors but returns nil. Return failure when every endpoint fails; specify whether one valid response is enough for success. Preserve useful endpoint diagnostics. | **Characterization:** [TestRevocationFetchAndInfo](cmd/xpki-tool/cli/coverage_test.go) requires success after a bad endpoint and checks only printed ERROR text. Change the returned-error assertion; add all-fail, first-fail/second-success, mixed-success, and output-write failure cases. Smoke-test nonzero CLI exit status. |
| XPKI-103-xpki-cli — MEDIUM / bug / 25 | [OCSPValidation](cmd/xpki-tool/cli/certs.go) forwards to certutil then would perform HTTP work. Propagate CU4's input error with ocsp.Unknown and no network request. | **Characterization:** TestRevocationValidationFailures explicitly asserts nil-issuer panic. Replace it after CU4; assert returned error/status and zero HTTP calls, retaining valid/mismatched-issuer and cancellation tests. |
| XPKI-105 — MEDIUM / bug / 25 — **Fixed (XC2, 2026-09-20)** | [suite_test.go](cmd/xpki-tool/cli/suite_test.go) allocates a unique `s.T().TempDir()` in `SetupSuite`; Go cleans up after the suite. Shared-path creation and manual deletion are removed. | **Verified:** reproduced missing files with two pre-fix processes; overlapping coverage/race binaries each passed 50 suite runs under a shared temporary root, with separate outputs and no leftover fixtures. `make lint`, `make test RACE=true`, and `make covtest` passed (90.1%; most unchanged packages cached). See [completed batches](#completed-batches). |

XC1 has **medium** script compatibility risk; completed XC2 has **low** product
risk. No benchmark is required for either. XC2's cross-process overlap
validation passed; race detection alone would not establish fixture isolation.

### Scripts, CI, build, and version — SC1, CI1, BU1–BU3, IV1

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-093 — HIGH / bug / 35 — **Fixed (SC1, 2026-09-20)** | [config-softhsm.sh](scripts/config-softhsm.sh) now validates flags/tools, discovers the module, propagates failures, and securely generates/stores PINs without printing them. `make hsmconfig` verifies the result with our CLI; OpenSC is optional. | **Verified:** 38 isolated shell cases, real SoftHSM setup flows, `make hsmconfig` without `pkcs11-tool`, HSM CLI and `crypto11` tests, ShellCheck, and `make lint`. Native macOS execution remains unverified; discovery uses tested Homebrew stubs. See [completed batches](#completed-batches). |
| XPKI-094 — LOW / bug / 15 | [UnitTest](.github/workflows/unittest.yml) needs detect-noop but has no job-level skip condition. Gate the intended expensive work while preserving required-check/status behavior. | **No automated workflow behavior tests found.** Validate docs-only PR, code PR, push and tag scenarios; ensure skipped jobs do not leave pending required statuses. The current workflow gates status publication, not the entire job. Medium integration risk; existing approval decision applies. |
| XPKI-095-CI — MEDIUM / correctness / 23 | Workflow installs tools but runs covtest only. Invoke an agreed non-mutating lint/vulnerability gate after BU1 and retain coverage. | **Partial tooling exists:** local lint includes vet, vulns and golangci-lint; this says nothing about CI execution. Validate workflow syntax, a real representative CI run, clean checkout after formatting checks, and failure propagation. Existing approval decision applies. |
| XPKI-095-build — MEDIUM / correctness / 23 | [.project/gomod-project.mk](.project/gomod-project.mk) has lint/covtest depending on fmt, which edits files; fmt-check already exists. Provide/wire the non-mutating path needed by CI without silently changing the developer fmt command. | **No target-level regression tests found.** Run checks on deliberately misformatted temporary source in an isolated checkout: nonzero result and unchanged bytes; verify clean source passes. Do not lower lint/coverage requirements to enable the gate. |
| XPKI-096 — MEDIUM / correctness / 23 | [Makefile tools](Makefile) installs all tools at @latest. Pin tested versions compatible with Go 1.27 and .golangci.yaml, with a deliberate update procedure. | **No version-lock assertion found.** Verify clean installation and execute each pinned tool. Risk low–medium: incompatible pins can break the toolchain, and existing releases may already require newer Go. No speculative version numbers in this plan. |
| XPKI-097-version — LOW / bug / 15 | [current.go](internal/version/current.go) is tracked despite its generated-file comment and embeds v0.2.76. Define a reliable runtime fallback for non-Make builds and a version-injection/generated-file contract. | **Partial:** [versioninfo_test.go](internal/version/versioninfo_test.go) tests parsing/comparison, not source freshness. Add tests for the selected fallback/injection mechanism. Keep the package buildable from a clean checkout/source archive. |
| XPKI-097-build — LOW / bug / 15 | Makefile's version target is not a build dependency. Wire the agreed IV1 mechanism into release/build paths without requiring developers to have a previously generated untracked file. | **Absent:** no built-binary version assertion. Build both CLIs from a clean checkout and inspect their version output; also check supported plain go build/go install behavior. Coordinate IV1 before closing the ID. |
| XPKI-098 — MEDIUM / correctness / 23 | [docker-compose.yml](docker-compose.yml) declares obsolete version metadata, public-range static addresses, and an untagged emulator image. Pin a tested image and use non-conflicting private/default networking while keeping expected ports. | **Partial:** integration tests depend on :14555/:14556 but do not validate configuration portability or image identity. Run compose config, then a clean startup/readiness check and both endpoint integration suites. Preserve service data intentionally; no blind deletion of volumes is part of this fix. |

No performance benchmarks are needed for these batches. Use shell/workflow
validation and executable smoke checks. Check lint findings against the
current tree: the approval note's prediction of existing lint failures may be
stale; the historical coverage report records a clean lint run.

## Cross-cutting test findings, split by package

The following are explicit portions of their named **single-package** batches,
not one repository-wide test rewrite. Severity/type remains the finding's
classification; a high-priority batch can contain lower-priority test cleanup.

| Finding / importance | Batch and owner | Evidence; expected outcome and completeness check |
| --- | --- | --- |
| XPKI-099 — LOW / docs / 11 — **cryptoprov portion Fixed (CP1, 2026-09-26)** | CP1 — `cryptoprov` | The empty stubs are replaced by [TestLoad_KMSProviders](cryptoprov/provider_test.go): `Load` dispatches to the self-registered AWS (lazy client) and GCP (stubbed `KmsClientFactory`, restored) loaders without KMS, checks types, lookup and a duplicate AWS config; `TestRegistered` also checks `SoftHSM`. |
| XPKI-099 — LOW / docs / 11 | CU4 — `certutil` | [TestKeyInfoKMS](certutil/keyinfo_test.go) connects to configured KMS and may create a key. Exercise pure KeyInfo with generated/local signer data and classify any retained KMS case as an explicit integration. Assert type, size, and public-key identity; no real cloud account should be needed for unit tests. |
| XPKI-100 — MEDIUM / docs / 21 — **crypto11 portion Fixed (PK1, 2026-09-25)** | PK1 — `crypto11` | [TestMain](crypto11/crypto11_test.go) loads SoftHSM only when its config exists and closes it explicitly (a close error fails the run); SoftHSM tests call `requireP11` (`internal/testenv.RequireFile`), and pool/config/DSA tests are fixture-free. **Verified:** config absent → 21 skips and a pass; absent with `XPKI_INTEGRATION=required` → fail; present but broken → fail. |
| XPKI-100 — MEDIUM / docs / 21 — **cryptoprov portion Fixed (CP1, 2026-09-26)** | CP1 — `cryptoprov` | Only `Test_LoadConfig`, `Test_Load`, `Test_P11` and `Test_LoadSigner_P11` need SoftHSM and call `requireSoftHSM` (`testenv.RequireFile`); the rest use inmemcrypto/testprov; no test unregisters a built-in loader. **Verified:** HEAD failed 7 tests without the config; now optional → 4 skips and a pass, required → fail, broken config → fail. |
| XPKI-100 — MEDIUM / docs / 21 | AW1 — `cryptoprov/awskmscrypto` | [awskmsprov_test.go](cryptoprov/awskmscrypto/awskmsprov_test.go) requires local-kms. Separate deterministic client-seam tests from emulator cases, and test both emulator-absent optional mode and required CI mode. |
| XPKI-100 — MEDIUM / docs / 21 — **authority portion Fixed (AU2, 2026-09-25)** | AU2 — `authority` | The suite loads (without connecting) the local-kms provider; only `TestNewRoot` needs local-kms and is gated by `internal/testenv.RequireTCP`; `TestShakenRoot`/`TestIssuerSign` moved to `inmemcrypto`; SoftHSM is not used. Verified skip (optional), fail (`XPKI_INTEGRATION=required`) and a reachable-but-broken endpoint (fails) with `kms2` stopped. |
| XPKI-100 — MEDIUM / docs / 21 | CS1 — `csr` | [csrprov_test.go](csr/csrprov_test.go) includes HSM-backed paths, while current `TestCSR` uses inmemcrypto. Scope fixture handling to actual external cases; the codemap's claim that TestCSR needs SoftHSM is stale. Assert unit SAN/parsing tests still run without it. |
| XPKI-100 — MEDIUM / docs / 21 — **jwt portion Fixed (JW2, 2026-09-25)** | JW2 — `jwt` | [Test_SignPrivateKMS](jwt/jwt_test.go) is gated by `testenv.RequireTCP` on `localhost:14555` (`kmsConfig`/`localKMSAddr`); all other jwt tests are fixture-free. **Verified** with `kms1` stopped: optional → skip and the package passes; required → fail; fake listener → fail; restarted → pass. |
| XPKI-100 — MEDIUM / docs / 21 | CU4 — `certutil` | TestKeyInfoKMS is the fixture-dependent case; the bundler/PEM tests use local/generated data. Coordinate 099-certutil; test no-infrastructure execution and the remaining required integration if retained. |
| XPKI-100 — MEDIUM / docs / 21 | HC1 — `cmd/hsm-tool/cli` | [csr_test.go](cmd/hsm-tool/cli/csr_test.go) depends on KMS/config fixtures. Keep parser/provider-error tests independent; guard only fixture-dependent command cases and verify they run in provisioned CI. |

Regression risk for 099 is low except accidental loss of integration coverage.
For every 100 portion it is **medium**: broad Skip calls can hide real product
failures. Test an unavailable fixture, a correctly provisioned fixture, and a
present-but-broken fixture; only the first may skip in optional local mode.
Use the established config constants and Makefile emulator endpoints/env.
No benchmark is needed for either finding.

## Benchmark and race-test protocol

No `Benchmark*` functions were found during the original planning review.
TP1 and IM1 now add and record `BenchmarkGetKey` for each provider's serial
hit/miss lookups.
Other baselines below still need to be created where marked required.

| Finding(s) | Before-fix benchmark decision | What to record |
| --- | --- | --- |
| 002, 005 (PK1) — **Fixed** | **Recorded before/after comparison** (`sessions_bench_test.go`, `-cpu 1,4,16 -count 6`, benchstat, HEAD worktree; saturation `-benchtime=1x`, 10s bound) | GenRandom/ECDSA sign: no significant change except +2.1% one-CPU parallel GenRandom, allocs unchanged; Init/Close 81.5/113.2/143.0 → 57.1/56.4/55.1 µs, 12.3 → 5.6 KiB, live sessions after run 8.5k–15k → 0; saturation peak 1,100 → 1,024, stuck 76 → 0 |
| 016 (CP1) — **Fixed** | **Recorded before/after comparison** (`BenchmarkByManufacturer`, `BenchmarkByManufacturerWithAdd`, `-count 6 -cpu 1,4`, benchstat, before = unchanged code) | hits 0 allocs before/after: default 6.2–6.4 → 5.2–5.3 ns, registered 26.1–30.1 → 20.5–21.3 ns serial, 7.1–7.9 → 5.7–5.9 ns on 4 CPUs; misses 416 B / 7 allocs, not significant except +7.6% in one case; rejected RWMutex variant 46–71 ns parallel hits; mixed (1 Add in 1024) 29.9 / 7.3 ns vs RWMutex 27.8 / 53.1 ns, no pre-fix baseline (crash) |
| 017-inmemcrypto (IM1) — **Fixed** | **Recorded serial hit/miss comparison** | median hits 12.25 → 17.15 ns/op, 0 allocations; misses 1902 → 1983 ns/op, 512 B / 9 allocations; generation excluded, mixed throughput not measured |
| 017-testprov (TP1) — **Fixed** | **Recorded serial hit/miss comparison** | median hits 12.79 → 17.97 ns/op, 0 allocations; misses 1842 → 1935 ns/op, 512 B / 9 allocations; generation excluded, mixed throughput not measured |
| 018 (GC1) — **Fixed** | **Not required**: the `enter`/`exit` guard adds two short mutex sections per call and does not serialize RPCs | none recorded; correctness proven by the blocked-RPC lifecycle test under `-race` |
| 024 (GC3) | **Required**, using deterministic timing | retry count, readiness/cancellation latency, allocations; distinguish wall time from CPU work |
| 032 (AW2) | **Required** | ListKeys/DescribeKey counts, size/page/selectivity scaling, throttling, peak concurrency |
| 035 (CU2) — **Fixed** | **Recorded before/after comparison** (`BenchmarkBundle`, `-count 6 -cpu 1,4`, benchstat, before = unchanged code) | warm Bundle serial/parallel at pool 0/100/1000 unchanged (124.7–128.5 µs serial, 32.7–33.4 µs on 4 CPUs, 51 allocs; one +0.9% serial case); learning one intermediate: pool 0 unchanged, pool 100 +2.6%, pool 1000 +23–25% (707 → 884 µs, 20.6 → 346 KiB, 335 → 1,361 allocs) from the pool clone; concurrent learning has no pre-fix baseline (racy) and is proven by the race test |
| 039 (CU1) — **Fixed** | **Recorded before/after comparison** (`BenchmarkBundlerAIAFailingURL`, `-count=5 -cpu=1,4`, benchstat p=0.008) | depth 1/2/4/8: failed requests 3/5/9/17 → 1, total requests 4/7/13/25 → 2/3/5/9; wall time −10–18% on loopback, B/op −39–45%, allocs/op −25–30%; subsequent-call recovery covered by `TestBundlerAIARetriesOnNextCall` |
| 052 (AU2) — **Fixed** | **Recorded before/after comparison** (`BenchmarkSignOCSP`, `-count=6 -cpu=1,4`, benchstat, HEAD worktree baseline) | delegated warm lookup 264 → 37 ns serial, 258 → 9.7 ns on 4 CPUs, 152 B / 4 allocs → 0; delegated sign 885.6 → 875.0 µs (−1.2%, p=0.004), 4-CPU not significant; CA path unchanged; issuance (`BenchmarkDelegatedOCSPCreate`) 318 µs / 660 allocs with no pre-fix baseline (deadlock); concurrent cold start/renewal proven by tests (exactly one issuance), not timed |
| 055 (AU3) | **Recommended**; conditional on lock/copy design | lookup and profile snapshot costs as registry size/readers grow |
| 062, 107 (TC1) — **Fixed** | **Not required**; generation/signing remain outside the serial mutex | verified unique serials/names, signed certificates, and option ownership with synchronized workers and the race detector |
| 081 and shared-state portion of 080 (OA1) | **Recommended** | registry and token-request latency/allocations with concurrent config updates |
| 070 (JW1) — **Fixed** | **Recorded before/after comparison** (`BenchmarkRemoteKeySet`, `-count=8 -cpu=1,4`, benchstat p<0.001 for unknown kids, loopback server) | unknown kids 1 → 0 fetches/op (0.25 → 0 with 4 goroutines); unknown-kid lookups −88–95% time (44.9µs → 3.3µs serial), 2.6–9.2 KB → 832–855 B, 32–105 → 12–13 allocs; known kids 16.6 → 17.6 ns (p=0.06, not significant), 0 allocs; miss tracking is O(1) (last fetch time/error); rotation covered by the controlled-clock test, not benchmarked |
| 075, 074 (DP1) — **Fixed** | **Recorded before/after comparison** for verification (`BenchmarkVerifyClaims`, `-count=8 -cpu=1,4`, benchstat, HEAD worktree) and new-store measurements (`BenchmarkVerifyClaimsReplayCache`, `BenchmarkMemoryReplayCache`, `-count=6 -cpu=1,4`) | go-jose verification 91.7 → 89.9µs serial (−2.0%, p=0.007), 24.1 → 24.2µs on 4 CPUs (p=0.96), 247 → 226 allocs; with the memory store 91.4µs / 23.7µs and 232 allocs; store alone: unique key 612/457ns, 1 alloc; replay 367–376ns, 3 allocs; admit-with-eviction at capacity 214–256ns, 2 allocs, 1 retained entry. Replay safety is proven by the 32-goroutine test, not the benchmark |
| 105 (XC2, cross-process fixture interference) — **Fixed** | **Not needed** | verified 50 suite runs per overlapping coverage/race process and automatic fixture cleanup |

Performance fixes require an existing-behavior reproduction plus a baseline
before optimization. Use generated fixtures and local/fake HTTP/KMS services;
keep service latency controlled. Compare the same scenarios/toolchain/machine
before and after, for example `go test ./<package> -run '^$' -bench <name>
-benchmem -count=5 -cpu=1,4,8`. For pool/network work, request/resource counts
and bounded completion are acceptance criteria alongside timing.

Do **not** run a known racy map or hanging pool unbounded to obtain a baseline.
Use a safe serial baseline or isolated, time-bounded reproduction, then measure
the concurrent implementation once it is correct. Record that limitation.
Run race detection separately from timing; race-instrumented timings are not
comparable production-performance measurements.

For every shared-state fix, add a test with overlapping reads and writes
(barriers/channels, not merely t.Parallel on independent objects), assert
results, and run `make test RACE=true` with required fixtures provisioned.
TC1 is fixed; keep testca defaults, entity fields and option data immutable
during concurrent generation and use a signer supporting concurrent calls. Passing the
existing mostly serial race suite is insufficient evidence that these races
are fixed.

## Completion and validation

For each batch:

1. Reproduce the finding or correct its premise first. Write the missing
   behavioral assertions before changing the implementation; update existing
   characterization tests in the same batch. Do not close a finding solely
   because statement coverage is high.
2. Resolve the listed contract decisions with concrete API/config examples.
   Preserve the existing Needs Approval statuses until those decisions exist.
   Security/outage fixes in independent batches can proceed meanwhile.
3. Run the owning package's targeted tests and affected consumers, with local
   servers/generated fixtures wherever possible. Perform the required
   benchmark comparison and concurrency validation for that batch.
4. Run required integration checks using the established SoftHSM and local-kms
   fixtures. Use `make lint`; shared-state changes also require `make test
   RACE=true`. XC2's CLI fixture isolation is fixed; overlapping CLI coverage
   and race runs still need separate output files.
   Preserve the actual CI coverage gate and exclusions; adding skips must not
   hide integration execution in CI.
5. In the same change, mark the retained `FINDINGS.md` row **Fixed** and add
   the ID, batch, completion date, change summary, and actual validation under
   **Fixed items**. Mark the finding and batch **Fixed** in this plan's completed
   table, update their assessment rows, and remove completed batches from the
   pending queue. Keep both files synchronized, even when `PLAN.md` is ignored
   by Git. Close a finding only when every linked package portion is complete;
   otherwise record partial progress and remaining work. Never delete fixed
   findings or reuse IDs, and state any validation limitations.
6. Update the codemap for changed APIs, ownership, locking, formats, algorithms,
   fixture conventions, and compatibility decisions. Put larger API
   designs/migrations in ROADMAP and keep examples compiling.

Validation performed for **this plan**:

- Full existing tests passed for `armor`, `dataprotection`, `jwt/dpop`,
  `jwt/accesstoken`, `jwt/oauth2client`, `cryptoprov/gcpkmscrypto`,
  `cryptoprov/inmemcrypto`, `cryptoprov/testprov`, and `testca`
  (`go test`; some results used Go's test cache).
- Focused tests passed in `authority`, `certutil`, `jwt`,
  `cmd/xpki-tool/cli`, and `csr`: issuer extensions/template errors, OCSP
  response/reuse, bundler AIA/chain behavior, malformed PEM, standalone
  symmetric JWT, JWKS cache hits, revocation failure/fetch, and SAN handling.
- A temporary Go program reproduced 058's lowercase YAML decoding success and
  capitalized JSON output using the actual IssuerConfig type and dependencies.
- Existing coverage artifacts and test assertions were inspected. Full
  integration coverage, race tests, lint, and performance benchmarks were
  **not rerun** for this documentation-only task. No claim is made that the
  open defects have been fixed or that the planned concurrency cases pass.
