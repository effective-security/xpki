# Roadmap

Open work only. Shipped behavior is documented in [README.md](README.md) and
[`Documentation/codemap.md`](Documentation/codemap.md), and open
defects in [FINDINGS.md](FINDINGS.md). Completed milestones live in git history.

Items here are larger than a bug fix: they change an API, a contract, or the
shape of the module. A defect that can be fixed in place belongs in FINDINGS.

## Provider interface: context propagation

`cryptoprov.Provider`, `KeyGenerator` and `KeyManager` take no
`context.Context`, so `awskmscrypto` and `gcpkmscrypto` call the cloud SDKs
with `context.Background()` and a `Sign` can hang on a network stall. Add
`ctx` to the interfaces (or context-aware variants), thread it through
`csr.Provider`, `authority.Issuer.Sign` and `jwt`. Related: XPKI-024.

## DPoP: replay protection and access-token binding

Implement RFC 9449 `jti` replay cache and `ath` binding in `jwt/dpop`
(XPKI-075). Requires a pluggable store interface in `VerifyConfig` and an
`ath` claim on `jwt.Claims`. Also either implement PSS/EdDSA in
`jwt.VerifySignature` or trim the DPoP algorithm allow-list (XPKI-074).

## JWKS client hardening

Done in JW1 (XPKI-070, 2026-09-24): `jwt.RemoteKeySet` accepts an injected
`*http.Client`, applies a per-fetch timeout and body limit, and throttles
refreshes with a cooldown. Remaining: TTL-based background refresh (honouring
`Cache-Control`), so removed keys expire and new keys are picked up before the
first miss, and `ParserConfig` fields for the `RemoteKeySet` options, which
`NewParser` currently leaves at the defaults.

## PKCS#11 session management

Redesign `crypto11` session handling: bounded session count with proper
close on return, per-key slot usage, pool creation on demand, and a correct
`Close()` that finalizes once per process (XPKI-001..003, XPKI-005).
Consider dropping the remaining cgo `unsafe` helpers in `common.go` in
favor of `encoding/binary`.

## certutil bundler concurrency

`certutil.Bundler` mutates its pools during `Bundle` (XPKI-035). Either
document it as single-goroutine or copy pools per call. Add encrypted PKCS#8
key support (XPKI-043) and drop legacy RFC 1423 PEM decryption
(`x509.DecryptPEMBlock`) once callers have migrated.

## Dependency hygiene

- `gopkg.in/yaml.v3` is archived; `go.yaml.in/yaml/v3` is already an indirect
  dependency. Switch the four direct importers in one change.
- `golang.org/x/crypto/hkdf` in `dataprotection` can move to `crypto/hkdf`.
- Pin tool versions in `Makefile` (`tools`) instead of `@latest` (XPKI-096).

## Tooling and CI

- Run `make lint` and `govulncheck` in CI, and gate the `UnitTest` job on
  `detect-noop` (XPKI-094, XPKI-095).
- Make integration tests skip when SoftHSM or local-kms is unavailable
  (XPKI-100), and add the missing KMS `EnumKeys` coverage (XPKI-099).
- Wire `make version` into `build` and stop tracking
  `internal/version/current.go` (XPKI-097).
- Regenerate `cmd/*/README.md` from `--help` output and add per-command
  examples.
