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

No batch is open. New findings get a batch here with the columns below when
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

No open findings batch needs a before-fix benchmark.

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
[3. Post-quantum signatures: ML-DSA (FIPS 204)](ROADMAP.md#3-post-quantum-signatures-ml-dsa-fips-204).
The design and the decisions D1–D7 are in
[`Documentation/design/pqc.md`](Documentation/design/pqc.md). Batches PQ0
(foundations), PQ1 (in-memory providers, `testca`), PQ2 (`authority`), PQ3
(AWS KMS), PQ4 (GCP KMS) and PQ6 (CLI, printing, documentation), `crypto11` on a
PKCS#11 v3.2 token (PQ5b, roadmap 3.1), the OCSP responder (roadmap 3.3) and
`jwt`/`jwt/dpop` (roadmap 3.4) were implemented in v1.1 and are summarized in
[`Documentation/RELEASE_NOTES_1.1.md`](Documentation/RELEASE_NOTES_1.1.md).
What remains is verification that needs outside infrastructure: the batch below
has its code and tests in place and waits for the service.

### Remaining batches

| Batch | Owner package(s) | Scope                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Depends on                                                                                                                                                              | Regression risk                                                                                      |
| ----- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| PQ7   | `gcpkmscrypto`   | Run `TestLiveKMSMLDSA` against the real service once Cloud KMS offers ML-DSA for HSM keys (`XPKI_LIVE_GCP_KMS_KEYRING=projects/<project>/locations/<location>/keyRings/<ring>`, on `go test` directly). The run of 2026-11-12 in `us-central1` was refused for all three parameter sets: `INVALID_ARGUMENT`, "Algorithm PQ_SIGN_ML_DSA_44_EXTERNAL_MU is not supported for protection level: HSM" (reason `ALGORITHM_NOT_SUPPORTED_FOR_PROTECTION_LEVEL`). `GenerateKey` now reports that as `cryptoprov.ErrNotSupported` and the test skips on it, so it can be run again at any time. Fix whatever the service reports then and record the result. Done for AWS: passed for all three parameter sets on 2026-11-09. | Cloud KMS offering ML-DSA at the HSM protection level, which `genKey` asks for; or a decision to add a protection level setting and create ML-DSA keys as software keys | Low: the code paths are exercised on the fake; a live difference would change only the request shape |

Acceptance for PQ7: for all three parameter sets on GCP, a key is
created, a message, a μ and a message with a context are signed and verified
locally, the key reads back with its parameter set, and a CSR and a
certificate are signed; the keys are scheduled for deletion.

### Validation protocol

Run `TestLiveKMSMLDSA` in `gcpkmscrypto` against the live service; it skips
while the service refuses the algorithm. `make lint`;
`make covtest` stays above `MIN_TESTCOV=90`. Record in the PR which account and
location signed, and update `Documentation/design/pqc.md`, the codemap and the
status in `ROADMAP.md` in the same change.

## Key management interfaces (xpki v2): remaining work

Roadmap item 12, the redesign of `cryptoprov.KeyManager` and `KeyGenerator`,
is implemented: batches KM0 to KM9 are summarized in
[`Documentation/RELEASE_NOTES_2.0.md`](Documentation/RELEASE_NOTES_2.0.md),
and the design with its decisions K1 to K12 is in
[`Documentation/design/keymanager.md`](Documentation/design/keymanager.md).
What remains needs infrastructure or a repository this work had no access
to. None of it has code to write here unless a run finds a difference. The
first live runs, on 2026-11-12, are recorded in the release notes
("Validation"): the AWS listing without tag search passed in `us-west-1`,
and the Google Cloud listing with its filters passed in `us-central1`, which
closed the item that was KM12.

### Remaining items

| Item | Owner                     | Scope                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Depends on                                      | Regression risk                                                                                                     |
| ---- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| KM10 | repository                | Cut `release-v1` from the last v1 commit (`b5001f2`) and push it, before the v2 change is merged to `main`. `settag.yml` then tags `v2.0.<n>` from `.VERSION` on `main` and `v1.1.<n>` on `release-v1`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | A maintainer with push rights                   | None for the code; without the branch v1 cannot take a fix                                                          |
| KM11 | `cryptoprov/awskmscrypto` | Run the tag search part of `TestLiveKMSListKeys` against the real service: `XPKI_LIVE_AWS_KMS_REGION=<region> XPKI_LIVE_AWS_KMS_TAGSEARCH=true go test ./cryptoprov/awskmscrypto/ -run 'TestLiveKMSListKeys$' -count=1 -v`. It needs `tag:GetResources` and `kms:TagResource`, tags two keys of one label, waits for the Resource Groups Tagging API to list them, and finds by label the one that has no alias. The first attempt, on 2026-11-12, failed in the test itself (its tag name used the reserved `xpki-` prefix) before any key was created; the flow now also runs on the fakes (`TestLiveKMSListKeysOnFake`). The rest of the test passed live on 2026-11-12. Record the IAM policy that was enough. It creates billable keys and schedules them for deletion. | An AWS account with the two tagging permissions | Low: the request shapes follow SDK v1.62.6 and `resourcegroupstaggingapi` v1.42.0                                   |
| KM13 | `crypto11`                | Run `make test-kryoptic` again. The run of 2026-11-12 failed in one assertion after the three parameter sets: the test still expected `GenerateKey` to return the helper's error for an unknown parameter set, which the request validation now rejects first. The assertion is corrected and runs on SoftHSM too (`TestGenerateMLDSAKeyOnSoftHSM`); the reported output shows no failure in the ML-DSA generation, signing, `KeyInfo` or listing steps, and the rerun is to confirm that.                                                                                                                                                                                                                                                                                   | The Kryoptic build (run by the maintainer)      | Low                                                                                                                 |
| KM14 | downstream repositories   | Migrate porto first (its exported API uses `jwt` and `dpop` types), then kubeca, trustyca (`Keys.Destroy` moves to `DestroyKey`, `ExportKey` gains `ctx`), secdi and martini, with the recipe of the release notes. trusty (v0.19.164) and promptviser (v0.27.281) stay on their pins until someone moves them.                                                                                                                                                                                                                                                                                                                                                                                                                                                              | KM10; the gate below                            | Medium per repository: about 370 files import the module; the compiler finds each one                               |
| KM15 | `cryptoprov/gcpkmscrypto` | Run `TestLiveKMSSign` once against the real service (`XPKI_LIVE_GCP_KMS_KEYRING=projects/<p>/locations/<l>/keyRings/<r> go test ./cryptoprov/gcpkmscrypto/ -run 'TestLiveKMSSign$' -count=1 -v`): for RSA 2048, 3072 and 4096 and ECDSA P-256 and P-384 it creates an HSM key, signs and verifies, loads the key by version, bare id and URI, describes it, signs a CSR and a certificate, lists it and schedules it for destruction. The flow passes on the in-process KMS (`TestLiveKMSSignOnFake`). It creates five billable HSM keys; the 4096-bit one can take a while to generate.                                                                                                                                                                                     | GCP access and a key ring                       | Low: the same code signs on the in-process KMS; a live difference would be in generation latency or a request shape |

### Gate before clients migrate

A client that moves to v2 rewrites every xpki import, so it should do that
once (decision K9). Every signature item 12 planned to change has changed.
The signing half of roadmap item 1 (`authority.Issuer.Sign`,
`csr.Provider.SignRequest`, the `crypto.Signer` path) changes more: merge it
first, or leave it explicitly for a later break, before KM14 starts. An
application moves all of its xpki imports in the release in which it takes
the porto built on v2, and a process that uses PKCS#11 links one major only.

### Validation protocol

KM11, KM13 and KM15 are runs: record the date, the region or token, and the
result in `Documentation/RELEASE_NOTES_2.0.md` ("Validation") and remove the
item here. A difference a run finds becomes a finding in FINDINGS.md with its
batch above.
