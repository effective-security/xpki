# FINDINGS

Open bugs, security issues and correctness problems.

Use the **ID** when commenting or assigning work. Update **Status** in the
same change as the code or decision, and update `PLAN.md` at the same time
when it is present, including when it is ignored by Git. When a finding is
fixed, remove it from this file and `PLAN.md`, and summarize it in the
release notes of the next version (`Documentation/RELEASE_NOTES_<version>.md`).
A finding spanning several packages stays here until every portion is fixed.
IDs are never reused; gaps are fixed or removed findings. The next free ID is
**XPKI-125**. Findings fixed in v0.29 are listed in
[`Documentation/RELEASE_NOTES_0.29.md`](Documentation/RELEASE_NOTES_0.29.md);
their full records are in git history.

## Status

| Status         | Meaning                                                |
| -------------- | ------------------------------------------------------ |
| Open           | Not started                                            |
| In Progress    | Being fixed                                            |
| Needs Approval | Behavior or compatibility change that needs a decision |

Type: **security** > **bug** > **race** > **correctness** > **performance** > **docs**.

Severity: **CRITICAL** > **HIGH** > **MEDIUM** > **LOW**.

Line numbers refer to the tree at the time of the audit (2026-09-20) and may
drift; the symbol name is the stable reference.

## Index

| ID       | Package                               | Location                                                       | Title                                                                                                                                              | Severity    | Status         |
| -------- | ------------------------------------- | -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | -------------- |
| XPKI-027 | cryptoprov                            | `uri.go` `ParseTokenURI`/`ParsePrivateKeyURI`                  | RFC 7512 `?pin-value=`/`?module-path=` query attributes are dropped                                                                                | correctness | Open           |
| XPKI-047 | armor                                 | `armor.go` `Decode`                                            | CRC24 trailer mandatory; RFC 9580 requires accepting armor without it                                                                              | correctness | Open           |
| XPKI-055 | authority                             | `authority.go` maps                                            | `Authority` maps and `Issuer.Profiles()` live map have no synchronization                                                                          | race        | Open           |
| XPKI-058 | authority                             | `config.go` `IssuerConfig.Type`                                | No json/yaml tag; `type:` in YAML is silently dropped                                                                                              | bug         | Open           |
| XPKI-059 | csr                                   | `csr.go` `SetSAN`, `csrprov.go` `SignRequest`                  | No SAN dedupe or DNS validation; `nil` keeps CSR SANs but empty slice clears them (undocumented)                                                   | correctness | Open           |
| XPKI-063 | testca                                | `utils.go` `ToPFX`/`ToPKCS8`                                   | Shell out to `openssl` and panic; stdlib `x509.MarshalPKCS8PrivateKey` covers PKCS#8                                                               | correctness | Open           |
| XPKI-083 | dataprotection                        | `symmetric.go` `NewSymmetric`/`Protect`                        | AES-GCM 96-bit random nonce with no rotation hook; HKDF over possibly low-entropy secret; limits undocumented                                      | docs        | Open           |
| XPKI-084 | cmd/hsm-tool                          | `cli/cli.go` `CryptoProv`                                      | Uses `logger.Panicf` on config errors; bad `--cfg` produces a stack trace and rc=2                                                                 | bug         | Open           |
| XPKI-094 | CI                                    | `.github/workflows/unittest.yml` `UnitTest`                    | Job not gated on `detect-noop` output; the skip step never skips anything                                                                          | bug         | Needs Approval |
| XPKI-095 | CI                                    | `.github/workflows/unittest.yml`, `Makefile`                   | Lint and govulncheck installed but never run; `make fmt` mutates the checkout instead of `fmt-check`                                               | correctness | Needs Approval |
| XPKI-096 | build                                 | `Makefile` `tools`                                             | Tools installed `@latest`; a golangci-lint major bump can break `.golangci.yaml`                                                                   | correctness | Open           |
| XPKI-097 | build                                 | `internal/version/current.go`, `Makefile` `version`            | Tracked generated file is stale (`v0.2.76`); `make version` not wired into `build`/`all`/CI                                                        | bug         | Open           |
| XPKI-098 | build                                 | `docker-compose.yml`                                           | Obsolete `version:`; fixed subnet is a public range; `local-kms` image untagged                                                                    | correctness | Open           |
| XPKI-100 | tests                                 | crypto11, cryptoprov, csr, authority, jwt, cmd suites          | Integration tests fail hard (some via `TestMain` panic) instead of skipping when SoftHSM or local-kms is absent                                    | docs        | In Progress (authority, crypto11, jwt, cryptoprov, certutil, awskmscrypto fixed in v0.29; csr, cmd/hsm-tool remain) |
| XPKI-101 | tests                                 | `cmd/hsm-tool/cli/hsm_cli_test.go`                             | Shared kong parser across `Parse` calls masks the `--cfg` required check                                                                           | docs        | Open           |
| XPKI-102 | cmd/xpki-tool/cli                     | `ocsp.go` `OCSPFetchCmd.Run`                                   | All OCSP endpoint failures are printed but the command returns success                                                                             | correctness | Open           |
| XPKI-106 | dataprotection                        | `symmetric_test.go` `TestNewSymmetric`                         | Tamper test copies one random nonce byte over another; equal bytes leave the ciphertext unchanged and make the authentication-failure assertion flaky | bug         | Open           |
| XPKI-110 | crypto11                              | `sessions.go` `withSession`; `config.go` `Init`                | After a device/token error the pooled sessions are reopened, but the login session is not, so a reinserted token stays logged out (`CKR_USER_NOT_LOGGED_IN`) until a new `Init` | correctness | Open           |
| XPKI-111 | authority                             | `ocsp_responder_test.go` `TestDelegatedOCSPSlowFailureAfterExpiry` | Timing-dependent: the 100ms signer gate is armed before the attempt starts, so under load the attempt can see less than 100ms and fail the `retryAt` bound (seen once in `make test RACE=true` during CU2) | bug         | Open           |
| XPKI-114 | csr, cryptoprov/gcpkmscrypto          | `csr/csrprov.go` `DefaultSigAlgo`; `csr/keyreq.go` `SigAlgo`   | 3072-bit RSA keys are signed with SHA-384, which no GCP KMS 3072-bit algorithm accepts (`RSA_SIGN_PKCS1_3072_SHA256` only), so a 3072-bit GCP key cannot sign a CSR or certificate with the csr defaults (found during GC2) | correctness | Open           |

## Notes on items needing approval

- **XPKI-114** (3072-bit RSA keys signed with SHA-384 by `csr`) needs a
  policy: SHA-256 for 3072-bit keys, or providers advertising their key's
  hash.
- **XPKI-094 / XPKI-095** change what CI runs; enabling lint in CI will fail
  until the remaining `gosec`/`gocritic` style findings are triaged.
