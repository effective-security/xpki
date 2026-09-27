# Findings remediation plan

Pending remediation batches for the open items in [FINDINGS.md](FINDINGS.md).
Every batch of the 2026-09-20 audit is complete and summarized in
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

No open batches. New findings get a batch here with the columns below when
they are recorded in FINDINGS.md:

| Batch | Owner | Findings (package portion where split) | Priority / score | Regression risk | Decision |
| --- | --- | --- | --- | --- | --- |

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
