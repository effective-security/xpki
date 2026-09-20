# Coverage plan and results

Target from `AGENT.md`: at least 90% statement coverage using `make covtest`
and the existing Makefile exclusions. Production behavior and coverage
exclusions were left unchanged. New defects are recorded in `FINDINGS.md`.

## Completed plan

Work proceeded one package at a time, using uncovered statements in the combined
profile rather than per-test-package `-coverpkg=./...` percentages:

1. `certutil`: chain construction and ranking, AIA retrieval and caching,
   bundle loading, malformed PEM/key inputs, expiration and trust failures.
2. `authority`: direct OCSP responses and cached delegated responders,
   proof signatures, extension policy decisions, and template errors.
3. `cmd/xpki-tool/cli`: certificate filtering and validation, concurrent
   revocation checks, CRL/OCSP fetch and inspection, and input/transport errors.
4. `csr`: BasicConstraints, tampered CSR signatures, ASN.1 GeneralName variants,
   invalid provider requests, and YAML conversions.
5. `jwt/oauth2client`: authentication styles, caller-owned form preservation,
   context cancellation, and provider registration conflicts/overrides.
6. `cryptoprov/gcpkmscrypto`: real SDK pagination against a local gRPC server,
   disabled-key filtering, metadata, deletion, and provider failure propagation.
7. `jwt`: parser configuration, malformed tokens, symmetric/asymmetric signing,
   key-ID types, and claim conversions.
8. Combined coverage, full race tests, lint, and codemap updates.

Fixtures use `testca`, temporary files, local HTTP/gRPC servers, the existing
SoftHSM token, and local-kms containers. New tests require no cloud account.
Existing edits in `.gitignore`, `Documentation/codemap.md`, and
`x/print/certutil_test.go` were preserved and included in the measured baseline.

## Measured results

The fresh baseline was **5,150 / 6,514 statements (79.1%)**. Final coverage is
**5,868 / 6,514 statements (90.1%)**, covering **718 additional statements**.
The statement denominator and exclusions did not change.

Coverage of the changed packages in the final combined profile:

| Package | Coverage |
| --- | ---: |
| `certutil` | 94.5% |
| `authority` | 91.0% |
| `cmd/xpki-tool/cli` | 96.2% |
| `csr` | 94.3% |
| `jwt/oauth2client` | 97.3% |
| `cryptoprov/gcpkmscrypto` | 95.6% |
| `jwt` | 91.8% |

Validation: `make covtest`, `make test RACE=true`, and `make lint` pass.
Lint includes gofmt, go vet, govulncheck, and golangci-lint; golangci-lint reports
zero issues and govulncheck reports no vulnerabilities affecting called code.
Run coverage and race tests sequentially: overlapping runs exposed XPKI-105,
a fixed temporary directory in the existing CLI suite. The separate race run
is the validation result reported here.

## Findings and remaining gaps

Tests characterize, without fixing:

- XPKI-102: OCSP fetch returns success after all endpoints fail.
- XPKI-103: OCSP request creation panics on a nil issuer.
- XPKI-104: the standalone symmetric JWT constructor panics when nonempty
  `WithHeaders` is applied.
- XPKI-105: concurrent CLI test processes remove each other's shared fixtures.
- Existing XPKI-036 and XPKI-066: empty bundler input and standalone symmetric
  JWT self-verification behavior.

Fresh delegated OCSP responder creation remains blocked by the known XPKI-051
lock recursion. Its cached-responder path is covered using a real issuer-signed
certificate. The largest remaining gaps are `crypto11/keys.go`,
`cmd/hsm-tool/cli/csr.go`, `authority/ocsp.go`, and `crypto11/ecdsa.go`.
