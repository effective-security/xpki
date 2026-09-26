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

Done in DP1 (XPKI-074/075/076, 2026-09-24): `dpop.VerifyConfig` takes an
opt-in `ReplayCache` (with a bounded, fail-closed `NewMemoryReplayCache`),
`AccessToken` for `ath` and `ExpectedThumbprint` for `cnf.jkt`, plus a
trusted `ExternalURL` for `htu`. go-jose verifies every allowed algorithm.
`ath` lives in a dpop-local claims struct, and `jwt.Claims` is unchanged.
Remaining:

- a shared `ReplayCache` implementation (for example Redis `SET NX` with an
  expiry) for servers with several instances;
- server-issued nonces (RFC 9449 §8/§9): generating and rotating
  `DPoP-Nonce` values and the `use_dpop_nonce` error. `ExpectedNonce`
  compares only a caller-provided value today;
- a decision on case-sensitive `htm` (XPKI-108).

## JWKS client hardening

Done in JW1 (XPKI-070, 2026-09-24): `jwt.RemoteKeySet` accepts an injected
`*http.Client`, applies a per-fetch timeout and body limit, and throttles
refreshes with a cooldown. Remaining: TTL-based background refresh (honouring
`Cache-Control`), so removed keys expire and new keys are picked up before the
first miss, and `ParserConfig` fields for the `RemoteKeySet` options, which
`NewParser` currently leaves at the defaults.

## PKCS#11 session management

Done in PK1 (XPKI-001..003, XPKI-005, XPKI-007, 2026-09-25): bounded
per-slot pools created on demand, a per-path module refcount whose last
`Close() error` finalizes, and `Init` unwinding. Remaining: a
`context.Context`-aware borrow (today a borrower at the session limit waits
without a deadline, since `crypto.Signer` has no context), recovery of the
login session after a device error (XPKI-110). PK2 (2026-09-25) replaced the
`unsafe` CK_ULONG helpers with checked `encoding/binary` decoding (XPKI-011);
the deprecated exported `BytesToUlong` can be removed in the next major
version.

## certutil bundler concurrency

CU2 (2026-09-25) made `certutil.Bundler` safe for concurrent use with
copy-on-write pools (XPKI-035). Remaining: coalescing concurrent AIA fetches of
the same URL across calls (each call still fetches once), and replacing the
exported mutable `RootPool`/`IntermediatePool`/`KnownIssuers` fields with
accessors in the next major version. Add encrypted PKCS#8
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
  (XPKI-100) with `internal/testenv` (done for `authority`, `crypto11`, `jwt`
  and `cryptoprov`; awskmscrypto, csr, certutil and hsm-tool remain), and gate
  `certutil.TestKeyInfoKMS` (XPKI-099, certutil portion).
- Wire `make version` into `build` and stop tracking
  `internal/version/current.go` (XPKI-097).
- Regenerate `cmd/*/README.md` from `--help` output and add per-command
  examples.
