# Findings remediation plan

Pending remediation batches for the open items in [FINDINGS.md](FINDINGS.md).
Batches completed up to v0.29 are summarized in
[`Documentation/RELEASE_NOTES_0.29.md`](Documentation/RELEASE_NOTES_0.29.md);
their plans, validation and benchmarks are in git history. When a batch is
fixed, remove it and its assessment rows from this file, remove its findings
from FINDINGS.md, and summarize the change in the next release notes.

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
| HC1 | `cmd/hsm-tool/cli` | 101; 100-hsm-cli | P2 / 21 | Low: test parser state and fixture gating | None |
| XC1 | `cmd/xpki-tool/cli` | 102 | P2 / 23 | Medium: exit status used by scripts | Partial endpoint success policy |
| CP2 | `cryptoprov` | 027 | P2 / 23 | Medium: URI parsing and credential precedence | Query/path conflict policy |
| PK3 | `crypto11` | 110 | P2 / 23 | Medium: re-login on a live token after device errors | Re-login trigger and PIN retention |
| CS1 | `csr` | 059, 114; 100-csr | P2 / 23 | High: existing names and nil/empty SAN semantics; medium: default hash for 3072-bit RSA | DNS validation and error API; 3072-bit RSA hash for GCP KMS |
| AR1 | `armor` | 047 | P2 / 23 | Medium: acceptance of legacy corruption fixtures | CRC acceptance contract |
| BU1 | root build tooling | 096, 095-build | P2 / 23 | Low–medium: tool compatibility and formatter gate | Coordinate CI requirement |
| BU2 | `docker-compose.yml` | 098 | P2 / 23 | Medium: emulator reachability and image behavior | None |
| CI1 | `.github/workflows` | 095-CI, 094 | P2 / 23 | Medium: required checks and skipped-job semantics | 094, 095 |
| DT1 | `dataprotection` | 083 | P2 / 21 | Low for documentation; high if format changes | Rotation API is separate roadmap work |
| TC2 | `testca` | 063 | P3 / 13 | Medium: PEM versus DER and OpenSSL compatibility | Preserve test-only panic contract |

Execution dependencies:

- CS1 owns XPKI-114 (`csr` picks SHA-384 for 3072-bit RSA, which GCP KMS
  cannot sign); `gcpkmscrypto` already rejects the mismatched hash locally.
- BU1 precedes CI1.
- For 100, make each package's unit tests independent of optional
  infrastructure, while keeping a CI mode that **fails** when required
  integrations are missing. Gate with `internal/testenv` (`RequireTCP`, or
  `RequireFile` for a fixture file such as the SoftHSM config), with
  `XPKI_INTEGRATION=required` exported by the Makefile. Remaining portions:
  CS1 (csr), HC1 (cmd/hsm-tool).

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
establishes it as a fresh measurement. The historical coverage report
(`Documentation/coverage-plan.md`, removed in PR #546) recorded 90.1%; do
not present either number as new validation. Its high percentages do not establish input,
policy, lifecycle, or concurrency completeness.

| Package | Existing local profile | Particularly misleading or missing coverage |
| --- | ---: | --- |
| `crypto11` | 81.0% | Login-session recovery after a device error is not tested |
| `cryptoprov` | 84.8% | URI query attributes are not tested |
| `csr` | 94.3% | SAN 92.9% without the full nil/empty/duplicate/validation matrix |
| `armor` | 90.6% | Legacy CRC acceptance rules embedded in corruption expectations |
| `dataprotection` | 87.1% | Round trips do not validate documented usage limits |
| `cmd/hsm-tool/cli` | 85.7% | Parser reuse masks a missing-required-flag scenario |
| `cmd/xpki-tool/cli` | 96.2% | Success-on-error is a characterization test |
| `testca`, scripts, build, workflow | Not in this Go coverage profile | Testca is excluded; scripts/build/CI need their own smoke checks |

Current workflow evidence takes precedence over stale summaries: the actual
[workflow](.github/workflows/unittest.yml) sets `MIN_TESTCOV: 90`, and its
status comparison is strictly `>`, while AGENTS/codemap still mention 80.
[Make helpers](.project/gomod-project.mk) already provide `fmt-check` and a
`lint` target including `vulns`; the workflow runs `covtest`, not `lint`.
Therefore 095 is principally CI wiring and a non-mutating lint entry point,
not creation of a nonexistent formatter check or vulnerability target.

## Package assessments

### crypto11 — PK3

PK3 (XPKI-110): after a device or token error the pooled sessions are
reopened, but the login session is not. Decide the re-login trigger and whether
the PIN is retained. Test with real SoftHSM plus small unexported seams only
where needed; do not invent a broad mock hierarchy.

### cryptoprov — CP2

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-027 — MEDIUM / correctness / 23 | [URI parsers](cryptoprov/uri.go) parse only `u.Opaque`, never RawQuery. Parse supported query attributes separately and preserve key identity; define duplicate/conflicting values and propagation of credentials/module selection. | **Partial:** [uri_test.go](cryptoprov/uri_test.go) covers only simple path-form attributes. Add query pin-value/module-path, encoded delimiters, invalid escaping, conflicting pin-source/pin-value, and legacy path compatibility. PrivateKeyURI exposes no credential fields, so parsing alone is not end-to-end propagation. |

URI query syntax and the conflicting-PIN case are described in
[RFC 7512 §2.3–2.4](https://www.rfc-editor.org/rfc/rfc7512.html#section-2.3).
CP2 has medium compatibility risk. Keep PINs out of diagnostics while adding
credential parsing. CP2 needs no benchmark.

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

**XPKI-114 — MEDIUM / correctness / 23 (found during GC2).**
[DefaultSigAlgo](csr/csrprov.go) and [SigAlgo](csr/keyreq.go) choose SHA-384
for 3072-bit RSA keys, but GCP KMS offers only SHA-256 algorithms for
3072-bit keys, so a 3072-bit GCP key cannot sign a CSR or certificate with
the defaults; the provider now rejects the hash locally (`hash SHA-384 does
not match key algorithm RSA_SIGN_PKCS1_3072_SHA256`) instead of KMS returning
`INVALID_ARGUMENT`. Decide between SHA-256 for 3072-bit keys and letting
providers advertise the hash their key supports. Coverage is **absent**: no
test signs a CSR with a 3072-bit KMS key.

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

### cmd/hsm-tool/cli — HC1

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-101 — MEDIUM / docs / 21 | [TestParse](cmd/hsm-tool/cli/hsm_cli_test.go) reuses one parser/config after setting --cfg and then expects a parse without --cfg to succeed. Recreate both parser and destination per independent test case. | **Existing assertion is misleading:** it tests retained state rather than a fresh invocation. Assert the actual missing-flag error with fresh state and retain a separate reuse test only if parser reuse is supported intentionally. |

Regression risk is **low**: test-only changes. No benchmark is required.
Include 100-hsm-cli.

### testca — TC2

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-063 — LOW / correctness / 13 | [ToPKCS8 / ToPFX](testca/utils.go) execute OpenSSL. Replace PKCS#8 encoding with stdlib plus PEM wrapping to preserve current output; PFX still needs a PKCS#12 implementation or an explicit OpenSSL dependency. Panic on test-fixture failure is an allowed package contract. | **Partial:** TestPFX only asserts no panic; it does not decode the result. Add RSA/EC PKCS#8 parse/round trips and PEM type checks; verify PFX cert/key/password with the chosen implementation. Test failure/dependency behavior without requiring removal of the intentional test-only panic convention. |

TC2 has medium encoding risk (PEM versus DER and OpenSSL compatibility). No
benchmark is required.

### cmd/xpki-tool/cli — XC1

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-102 — MEDIUM / correctness / 23 | [OCSPFetchCmd.Run](cmd/xpki-tool/cli/ocsp.go) prints endpoint errors but returns nil. Return failure when every endpoint fails; specify whether one valid response is enough for success. Preserve useful endpoint diagnostics. | **Characterization:** [TestRevocationFetchAndInfo](cmd/xpki-tool/cli/coverage_test.go) requires success after a bad endpoint and checks only printed ERROR text. Change the returned-error assertion; add all-fail, first-fail/second-success, mixed-success, and output-write failure cases. Smoke-test nonzero CLI exit status. |

XC1 has **medium** script compatibility risk. No benchmark is required.

### Scripts, CI and build — CI1, BU1, BU2

| Finding / importance | Evidence and expected outcome | Existing tests: correctness, completeness, and additions |
| --- | --- | --- |
| XPKI-094 — LOW / bug / 15 | [UnitTest](.github/workflows/unittest.yml) needs detect-noop but has no job-level skip condition. Gate the intended expensive work while preserving required-check/status behavior. | **No automated workflow behavior tests found.** Validate docs-only PR, code PR, push and tag scenarios; ensure skipped jobs do not leave pending required statuses. The current workflow gates status publication, not the entire job. Medium integration risk; existing approval decision applies. |
| XPKI-095-CI — MEDIUM / correctness / 23 | Workflow installs tools but runs covtest only. Invoke an agreed non-mutating lint/vulnerability gate after BU1 and retain coverage. | **Partial tooling exists:** local lint includes vet, vulns and golangci-lint; this says nothing about CI execution. Validate workflow syntax, a real representative CI run, clean checkout after formatting checks, and failure propagation. Existing approval decision applies. |
| XPKI-095-build — MEDIUM / correctness / 23 | [.project/gomod-project.mk](.project/gomod-project.mk) has lint/covtest depending on fmt, which edits files; fmt-check already exists. Provide/wire the non-mutating path needed by CI without silently changing the developer fmt command. | **No target-level regression tests found.** Run checks on deliberately misformatted temporary source in an isolated checkout: nonzero result and unchanged bytes; verify clean source passes. Do not lower lint/coverage requirements to enable the gate. |
| XPKI-096 — MEDIUM / correctness / 23 | [Makefile tools](Makefile) installs all tools at @latest. Pin tested versions compatible with Go 1.27 and .golangci.yaml, with a deliberate update procedure. | **No version-lock assertion found.** Verify clean installation and execute each pinned tool. Risk low–medium: incompatible pins can break the toolchain, and existing releases may already require newer Go. No speculative version numbers in this plan. |
| XPKI-098 — MEDIUM / correctness / 23 | [docker-compose.yml](docker-compose.yml) declares obsolete version metadata, public-range static addresses, and an untagged emulator image. Pin a tested image and use non-conflicting private/default networking while keeping expected ports. | **Partial:** integration tests depend on :14555/:14556 but do not validate configuration portability or image identity. Run compose config, then a clean startup/readiness check and both endpoint integration suites. Preserve service data intentionally; no blind deletion of volumes is part of this fix. |

No performance benchmarks are needed for these batches. Use shell/workflow
validation and executable smoke checks. Check lint findings against the
current tree before enabling lint in CI.

## Cross-cutting test findings, split by package

The following are explicit portions of their named **single-package** batches,
not one repository-wide test rewrite. Severity/type remains the finding's
classification; a high-priority batch can contain lower-priority test cleanup.

| Finding / importance | Batch and owner | Evidence; expected outcome and completeness check |
| --- | --- | --- |
| XPKI-100 — MEDIUM / docs / 21 | CS1 — `csr` | [csrprov_test.go](csr/csrprov_test.go) includes HSM-backed paths, while current `TestCSR` uses inmemcrypto. Scope fixture handling to actual external cases; the codemap's claim that TestCSR needs SoftHSM is stale. Assert unit SAN/parsing tests still run without it. |
| XPKI-100 — MEDIUM / docs / 21 | HC1 — `cmd/hsm-tool/cli` | [csr_test.go](cmd/hsm-tool/cli/csr_test.go) depends on KMS/config fixtures. Keep parser/provider-error tests independent; guard only fixture-dependent command cases and verify they run in provisioned CI. |

Regression risk for every 100 portion is **medium**: broad Skip calls can hide real product
failures. Test an unavailable fixture, a correctly provisioned fixture, and a
present-but-broken fixture; only the first may skip in optional local mode.
Use the established config constants and Makefile emulator endpoints/env.
No benchmark is needed.

## Benchmark and race-test protocol

No open batch needs a before-fix benchmark.

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
Keep testca defaults, entity fields and option data immutable
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
   RACE=true`.
   Overlapping CLI coverage and race runs need separate output files.
   Preserve the actual CI coverage gate and exclusions; adding skips must not
   hide integration execution in CI.
5. In the same change, remove the fixed finding from `FINDINGS.md` and its
   batch and assessment rows from this plan, and summarize the fix, its
   compatibility impact and the client changes it needs in the next
   `Documentation/RELEASE_NOTES_<version>.md`. Keep both files synchronized,
   even when `PLAN.md` is ignored by Git. Remove a finding only when every
   linked package portion is complete; otherwise record partial progress and
   remaining work. Never reuse IDs, and state any validation limitations in
   the commit or PR.
6. Update the codemap for changed APIs, ownership, locking, formats, algorithms,
   fixture conventions, and compatibility decisions. Put larger API
   designs/migrations in ROADMAP and keep examples compiling.
