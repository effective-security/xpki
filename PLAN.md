# Findings remediation plan

Pending remediation batches for the open items in [FINDINGS.md](FINDINGS.md).
Every batch of the 2026-09-20 audit is complete and summarized in
[`Documentation/RELEASE_NOTES_1.0.md`](Documentation/RELEASE_NOTES_1.0.md);
their plans, validation and benchmarks are in git history. When a batch is
fixed, remove it and its assessment rows from this file, remove its findings
from FINDINGS.md, and summarize the change in the next release notes.

## Classification and priority

The findings index still calls its classification column `Severity`, but its
values are **types**. This plan preserves those types and assigns **proposed
severity** independently. Severity estimates assume the affected feature is
used; deployment exposure can change the estimate. They are not CVSS scores.

| Severity | Meaning for this library                                                                                             | Priority                   |
| -------- | -------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| CRITICAL | Untrusted input can bypass certificate issuance policy at a trust boundary                                           | P0: address first          |
| HIGH     | Authentication/trust protection fails, a normal feature hangs/crashes, or concurrent use can stop a process          | P1: next remediation cycle |
| MEDIUM   | A supported operation fails under particular inputs/configuration, or reliability/performance is materially impaired | P2: scheduled remediation  |
| LOW      | Limited interoperability, metadata, documentation, or tooling impact                                                 | P3: follow-up              |

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

No open batches. New findings get a batch here with the columns below when
they are recorded in FINDINGS.md:

| Batch | Owner | Findings (package portion where split) | Priority / score | Regression risk | Decision |
| ----- | ----- | -------------------------------------- | ---------------- | --------------- | -------- |

Conventions that carry over to the next batches:

- For a fixture-dependent test, gate with `internal/testenv` (`RequireTCP`,
  or `RequireFile` for a fixture file such as the SoftHSM config); the
  Makefile exports `XPKI_INTEGRATION=required`, so a missing fixture fails
  `make test`/`covtest` and CI while a local run without the fixture skips.
  Keep unit tests fixture-free with `inmemcrypto` and `testca`.
- Prove the pre-fix failure (a `git worktree` of HEAD, or the new test
  against the old code) before changing the implementation, and record only
  verified claims.
- The coverage gate in CI is `MIN_TESTCOV=90` with a strict `>` comparison
  (`.github/workflows/unittest.yml`); `make lint` runs in CI and must stay
  clean.

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

## PQC execution plan (ML-DSA)

Execution plan for the roadmap item
[Post-quantum signatures: ML-DSA (FIPS 204)](ROADMAP.md#post-quantum-signatures-ml-dsa-fips-204).
The design, the verified toolchain baseline (2026-11-08) and the per-file
inventory are in [`Documentation/design/pqc.md`](Documentation/design/pqc.md);
this section is the work breakdown. It is not a findings batch: there is no
defect to reproduce, so the "prove the pre-fix failure" step is replaced by
the acceptance tests listed per batch, written before the implementation.
Remove a batch from this section when it is merged and summarize it in the
next `Documentation/RELEASE_NOTES_<version>.md`.

### Decisions to resolve first

The decisions below are described with their recommendation in
`Documentation/design/pqc.md` ("Decisions"). They gate the batches named
in the last column; the other batches can start on tests and fakes.

| Decision | Topic                                                   | Status         | Gates      |
| -------- | ------------------------------------------------------- | -------------- | ---------- |
| D1       | Optional `MLDSAKeyGenerator` interface vs widening `KeyGenerator` | Needs Approval | PQ0, PQ1   |
| D2       | `KeyRequest` encoding (`algo: ML-DSA`, `size: 44\|65\|87`), accepted aliases, PR 568 error text | Needs Approval | PQ0        |
| D3       | `KeyInfo` values for ML-DSA (`Type`, `KeySize`, `Hash`, `Meta`) | Needs Approval | PQ0        |
| D4       | Signer contract: message / μ options, no digest hashes  | Needs Approval | PQ1–PQ5    |
| D5       | OCSP with an ML-DSA issuer: delegated classical responder required (phase 1) | Needs Approval | PQ2        |
| D6       | Hedged signing by default                               | Needs Approval | PQ1, PQ3–5 |
| D7       | Optional `allowed_key_algorithms` profile policy        | Needs Approval | PQ2        |

### Batches

| Batch | Owner package(s)                | Scope                                                                                                                                                                                                                                                         | Depends on | Regression risk |
| ----- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | --------------- |
| PQ0   | `csr`, `certutil`, `cryptoprov` | Foundations, fixture-free. Absorb PR 568 with the review fix (D2). `csr`: `SigAlgo`/`DefaultSigAlgo` for ML-DSA, `KeyRequest.Generate` calling the D1 interface. `certutil`: `NewKeyInfo`, `ParsePrivateKeyDER`, `EncodePrivateKeyToPEM` (PKCS#8), bundler leaf key check, `IsPostQuantumKey`/`IsPostQuantumCertificate`, OpenSSL 3.5 interop vectors under `certutil/testdata/pqc/`. `cryptoprov`: `MLDSAKeyGenerator`, `ParsePrivateKeyDER`. | D1–D3      | Low: additive cases in type switches; existing RSA/ECDSA paths unchanged |
| PQ1   | `cryptoprov/inmemcrypto`, `cryptoprov/testprov`, `testca` | `GenerateMLDSAKey`, `Sign` option forwarding (nil default only for RSA/ECDSA), PKCS#8 export, `IdentifyKey`; `testca` ML-DSA entity option. End-to-end: `csr.Provider.GenerateKeyAndRequest` → `ParsePEM` → `CheckSignature` with an in-memory ML-DSA key. | PQ0, D4, D6 | Low: new generator; the `Sign` default change is covered by existing RSA/ECDSA tests |
| PQ2   | `authority`                     | `CreateIssuer` with an ML-DSA signer (key info, `sigAlgo`), `Sign` issuing from classical and ML-DSA CSRs, `NewRoot`/`GenCert`, `SignProof`/`VerifyProof` message path, OCSP constraint (D5), optional `allowed_key_algorithms` (D7), README and sample profile. | PQ1, D5, D7 | Medium: touches `CreateIssuer` validation and `VerifyProof`; behavior for RSA/ECDSA issuers must be byte-for-byte unchanged |
| PQ3   | `cryptoprov/awskmscrypto`       | `ML_DSA_*` key specs, `GenerateMLDSAKey`, `GetKey`/`EnumKeys` for PQ keys, `Sign` with locally computed μ and `EXTERNAL_MU`/`ML_DSA_SHAKE_256`, option validation before any RPC, outdated comment. `fakeKMS` with real ML-DSA keys and both message types. Gated integration test documented as skipped on `local-kms` (no ML-DSA, verified) and runnable against a real account. | PQ0, D4, D6 | Medium: `Sign` dispatch changes; existing algorithm map must be unchanged for RSA/ECDSA |
| PQ4   | `cryptoprov/gcpkmscrypto`       | `PQ_SIGN_ML_DSA_*` (`_EXTERNAL_MU` preferred) algorithms in `signSchemes`/`x509SignatureAlgorithms`, `GenerateMLDSAKey`, `GetKey`, `Sign` sending `data`/μ with CRC32C, `SignatureAlgorithm()`; fake gRPC KMS extended. | PQ0, D4, D6 | Medium: same as PQ3 |
| PQ5   | `crypto11`                      | Local PKCS#11 v3.2 constants, `CKK_ML_DSA` in `KeyTypeNames`/`keyTypeAndClass`, `PKCS11PrivateKeyMLDSA` (message semantics, handle refresh), `GenerateMLDSAKey`, `findKeyPairOnSession`, public key export, `ConvertToPublic`, `IdentifyKey`, `getPublicKeyPEM`. Second gated fixture (a v3.2 software token such as Kryoptic) with its own config path constant, `scripts/`, Makefile and CI provisioning. | PQ0, D4, fixture available | Medium: shared `keys.go` switches; cgo build must stay clean on every platform |
| PQ6   | `cmd/hsm-tool`, `x/print`, docs | `--algo` help and README regeneration, `csr` profile sample, printer lines for key and signature algorithm, `Documentation/codemap.md` rows and invariants (supported algorithms, signer contract, fixtures), root `README.md`, design documents, release notes. | PQ1–PQ5    | Low |

Second milestone, not scheduled: ML-DSA in `jwt`/`jwt/dpop` (RFC 9964,
go-jose v4.1.9), local OCSP response building for ML-DSA responders,
composite signatures.

### Acceptance criteria

- PQ0: `csr.SigAlgo("ML-DSA", 65) == x509.MLDSA65`;
  `csr.DefaultSigAlgo` on an `*mldsa.PrivateKey` returns the key's
  parameter set algorithm; `certutil.NewKeyInfo` returns the D3 values for
  private, public, signer and JWK inputs; `ParsePrivateKeyDER` and
  `EncodePrivateKeyToPEM` round-trip an ML-DSA key and parse the OpenSSL
  3.5 vectors; `KeyRequest.Generate` for `ML-DSA` with a provider lacking
  the D1 interface returns the "not implemented" error, with a valid
  parameter set checked first. RSA/ECDSA table tests unchanged.
- PQ1: generation, lookup and export of all three parameter sets; a
  concurrency test overlapping generation with lookup and signing
  (`make test RACE=true`); `Sign` with `crypto.SHA256` on an ML-DSA key
  returns an error; CSR created and verified end to end.
- PQ2: an ML-DSA root issues an ML-DSA leaf and an ECDSA leaf, and an ECDSA
  issuer issues an ML-DSA leaf; `x509.Verify` passes for each chain;
  `SignProof`/`VerifyProof` round-trip and reject a tampered proof;
  `CreateIssuer` with an ML-DSA signer and no delegated responder fails
  with the D5 error; `SignOCSP` through the delegated responder works;
  profiles with `allowed_key_algorithms` accept and reject as configured;
  the existing policy suite (`issuer_policy_test.go`) is unchanged.
- PQ3/PQ4: with the fakes, every parameter set signs a certificate and a
  CSR that verify locally; invalid options fail before any RPC; μ matches
  `mldsa.Verify` with the same message; CRC32C and empty-response checks
  hold; RSA/ECDSA tests unchanged. The gated real-service test is recorded
  as not run in CI with the reason.
- PQ5: with the v3.2 fixture, generate, find by id and label, sign, export
  the public key, destroy; without the fixture the tests skip (or fail
  only with `XPKI_INTEGRATION=required` where CI provisions it).
- PQ6: `hsm-tool hsm generate --algo ML-DSA --size 65 --cfg inmem` prints a
  PKCS#8 key; `git diff --exit-code` clean after `make build docs`.

### Validation protocol

For every batch: write the acceptance tests first and see them fail on
the current tree; `make lint`; the owning package's tests plus `authority`,
`csr` and `cmd/hsm-tool/cli` as consumers; `make test RACE=true` for PQ1,
PQ3, PQ4 and PQ5 (provider registries and session pools); `make covtest`
stays above the `MIN_TESTCOV=90` gate without excluding new files. Record
in the PR which fixtures ran (SoftHSM, local-kms, the v3.2 token, a real
KMS) and which were skipped. Update `Documentation/codemap.md` in the same
change (supported algorithms, signer contract, fixtures, new files), and
the design documents under `Documentation/design/` when a decision above
is resolved differently from its recommendation.
