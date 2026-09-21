# RULES OF CONDUCT

This module (`github.com/effective-security/xpki`) is a PKI library plus two
CLIs. The library packages are `cryptoprov` (provider abstraction with
`crypto11`, `awskmscrypto`, `gcpkmscrypto`, `inmemcrypto` backends), `csr`,
`authority`, `certutil`, `jwt` (with `dpop`, `accesstoken`, `oauth2client`),
`dataprotection`, and helpers `armor`, `oid`, `x/print`, `testca`. The CLIs
are `cmd/hsm-tool` and `cmd/xpki-tool`. There is no service, agent loop, or
generated mock tree. Work in one package at a time unless you are changing a
documented internal dependency.

Dependency direction is one way: `cryptoprov` defines the `Provider`
interfaces and must not import a backend; backends register themselves with
`cryptoprov.Register` from `init()`. `csr` depends on `cryptoprov`;
`authority` depends on `csr`, `certutil`, `cryptoprov`; `jwt` depends on
`cryptoprov`, `csr`, `certutil`. Nothing under the library imports `cmd/`.

## NAVIGATION

Do not start by grepping the tree.

1. Open [`Documentation/codemap.md`](Documentation/codemap.md). Use the
   concept index to find the owning file, then the package section for
   entry points and invariants.
2. Open that file (and its `_test.go`) before searching elsewhere.
3. Grep or glob only if the concept is missing from the map. When you find
   it, add it to the map in the same change.
4. For high-level purpose, config samples and install path, see
   [`README.md`](README.md).

## CODING GUIDELINES

### Style

- Target Go 1.27 (`go.mod`). Use the standard library where it now covers a
  helper: `slices.Contains`, `cmp.Or`, `maps.Copy`, `strings.SplitSeq`,
  `math/rand/v2`, `crypto/rand`, range-over-int. Do not add calls to
  functions marked `Deprecated` in the stdlib or in
  `github.com/effective-security/x`; `golangci-lint run` (staticcheck
  SA1019) must stay clean.
- Do not use long one-liners for map or struct population; split
  key-value pairs on new lines for readability.
- Do not use many hardcoded strings or integers; define `const` at the
  top of the file or in the package.
- Memoize into variables; do not call functions with the same parameters
  more than once.
- Use `any`, not `interface{}`.

### Errors

- Use `github.com/cockroachdb/errors` for all error creation and wrapping.
- Wrap external errors (filesystem, YAML/JSON, network, PKCS#11, KMS SDKs)
  using either:
  - `errors.WithMessage(err, "unable to read file")` for static context.
  - `errors.Wrapf(err, "failed to resolve file %s", path)` when context
    includes dynamic values.
- Errors originated from internal sentinel types must also be wrapped so
  the stack is preserved. For `var ErrNotFound = errors.New("not found")`
  do not simply `return ErrNotFound`.
- Compare errors with `errors.Is` / `errors.As`, never `==` or a type
  assertion; wrapped PKCS#11 (`pkcs11.Error`) and KMS errors must still be
  recognised.
- Never ignore errors from serialization, filesystem, or network calls in
  library paths that already return `error`. Helpers that intentionally
  swallow errors (for example `print.JSON`) must keep that behavior
  documented in `Documentation/codemap.md`.
- Keep error strings accurate after refactors. Do not leave stale package
  or function names in runtime errors.
- Library code does not panic on bad input or bad configuration; it
  returns an error. The only intentional panics are `Must*` constructors
  (`jwt.MustNewProvider`), `certutil.Random`/`RandomString` when
  `crypto/rand` fails, `init()`-time table construction
  (`crypto11/ecdsa.go`), and `testca`, which is test-only.
- Every outgoing HTTP call takes a `context.Context` and a client with a
  timeout (`http.NewRequestWithContext`; no bare `http.Get`).
- Cryptographic material: private keys and PINs are never logged; files
  holding keys are written with mode `0600`; random values come from
  `crypto/rand`; use constant-time comparison for secrets and hashes.

### Tests

- Build tests using `assert` and `require` from
  `github.com/stretchr/testify`; suites use `testify/suite`.
- Assert exact behavior, including key absence versus empty values and
  the real `err` from the call being tested.
- Keep test setup and cleanup trustworthy: fixtures should match their
  comments, and tests should actually execute in CI.
- Prefer table tests for conversion and formatting helpers.
- Use `package foo_test` for black-box tests and `package foo` only when a
  test needs unexported seams.
- External fixtures: PKCS#11 tests need the SoftHSM token described by
  `/tmp/xpki/softhsm_unittest.json` (`make hsmconfig`); AWS KMS tests need
  the `local-kms` containers on `:14555` and `:14556`
  (`make start-local-kms`) and the dummy `AWS_*` variables exported by the
  Makefile; GCP KMS tests use an in-process fake KMS client.
  Do not hard-code other paths; reuse the constants the packages define.
- `testca` generates throwaway keys and certificates; use it instead of
  checking new PEM fixtures into `testdata` unless a specific encoding is
  under test.
- Cover shared state with a test that actually races, and run
  `make test RACE=true` before proposing a change to shared state
  (providers, key caches, JWKS refresh, session pools).
- This module has no gomock-generated interfaces; do not introduce mocks
  unless the package under test cannot be exercised directly (KMS clients
  are the existing exception).

### Tools

- `make tools` : install golangci-lint, cov-report, govulncheck
- `make hsmconfig` : create the SoftHSM token and test config
- `make start-local-kms` : start the AWS KMS emulator containers
- `make fmt` : apply go fmt
- `make test` : test entire project
- `make lint` : gofmt, go vet, golangci-lint
- `make covtest coverage` : coverage run and report
- `make docs` : regenerate gomarkdoc API docs in `Documentation/` and CLI help dumps (needs `make build` first)
- `make all` : clean, tools, generate, hsmconfig, start-local-kms, covtest

CI (`.github/workflows/unittest.yml`) runs `make covtest` with SoftHSM and
local-kms and requires **80%** total coverage (`MIN_TESTCOV`). CI does not
run `make lint` or the race detector; run both locally.

### Documentation

- Every package has a `doc.go` with a package comment and, where the
  package has a non-obvious entry point, a short usage example.
- Document all exported types, functions, interfaces, and interface
  methods. Say what a symbol is _for_, not just what it is named.
- Keep samples in `doc.go`, the root `README.md`, `cmd/*/README.md` and
  `Documentation/` accurate against the current API and CLI `--help`
  output. A wrong sample is worse than no sample; compile a changed sample
  before committing it.
- When you add a package, add it to the package table in the root
  `README.md`, add `doc.go`, and add a section plus concept-index rows in
  `Documentation/codemap.md`.
- When you find a defect you are not fixing in the same change, add it to
  `FINDINGS.md` with the next free ID and reference the ID from a code
  comment. Larger API or contract changes go to `ROADMAP.md`.

#### Track remediation status

- In the same change as each verified fix, mark its `FINDINGS.md` index row
  **Fixed** and retain it. Add the finding ID, batch, completion date, concise
  change summary, and actual validation commands/results under **Fixed items**.
  Do not delete completed findings or reuse their IDs.
- Update `PLAN.md` when present, even if it is ignored by Git: explicitly mark
  the finding and batch **Fixed**, record the same date and validation, and
  move completed batches out of the pending queue. Update their assessment
  rows so they do not still describe missing implementation or tests.
- A finding spanning multiple packages is Fixed only after every linked
  portion is implemented and verified. Record partial progress and remaining
  work without closing the whole finding or batch. Record validation limits;
  do not describe planned or unavailable checks as passed.

#### Keep `Documentation/codemap.md` current

Update the codemap in the **same change** when you add functionality or
make a major change, including:

- New, removed, or renamed package, subpackage, or file that owns a
  concept.
- New, moved, or renamed exported entry-point type, func, or interface.
- Changed invariants: panic vs error, process-global state (provider
  registry, OID tables), locking, config file format, key URI format,
  supported algorithms, goroutine/callback rules, or internal imports
  between packages.
- Changed test layout or fixture conventions.

The map must stay the navigation index: concept → file → entry points →
invariants. If you had to grep to find something that belongs there, add
the row.

For package docs, use after changes `make docs`

## REPOSITORY MAP

Start here instead of grepping the tree.

- **[`Documentation/codemap.md`](Documentation/codemap.md)** — concept
  index, per-package files and entry points, invariants, internal
  dependencies, test layout, build and CI.
- **[`README.md`](README.md)** — high-level overview, package table,
  configuration samples and quick-start code.
- **[`FINDINGS.md`](FINDINGS.md)** — known defects and verified fixes, referenced by ID from
  code comments. Read it before "fixing" surprising behavior: it may
  already be recorded, with the compatibility decision still open.
- **[`PLAN.md`](PLAN.md)**, when present — remediation batches, pending work,
  and explicit completion status; keep it synchronized with `FINDINGS.md`.
- **[`ROADMAP.md`](ROADMAP.md)** — larger planned work.
- **[`cmd/hsm-tool/README.md`](cmd/hsm-tool/README.md)** and
  **[`cmd/xpki-tool/README.md`](cmd/xpki-tool/README.md)** — CLI usage.
- Package `doc.go` in each library package.
