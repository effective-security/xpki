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

## Certificate authority: deny-by-default extension policy

`Issuer.Sign` copies every requester CSR extension into the template and an
empty `allowed_extensions` means "allow all" (XPKI-049). Move to an explicit
field allow-list, make empty mean deny, and add a migration note for
profiles that rely on the current behavior. Bound `SignRequest.NotBefore` /
`NotAfter` by the profile (XPKI-054) in the same release.

## DPoP: replay protection and access-token binding

Implement RFC 9449 `jti` replay cache and `ath` binding in `jwt/dpop`
(XPKI-075). Requires a pluggable store interface in `VerifyConfig` and an
`ath` claim on `jwt.Claims`. Also either implement PSS/EdDSA in
`jwt.VerifySignature` or trim the DPoP algorithm allow-list (XPKI-074).

## JWKS client hardening

`jwt.RemoteKeySet` should accept an injected `*http.Client`, apply a per-fetch
timeout and body limit, throttle refreshes for unknown `kid`s, and support a
TTL-based background refresh (XPKI-070).

## PKCS#11 session management

Redesign `crypto11` session handling: bounded session count with proper
close on return, per-key slot usage, pool creation on demand, and a correct
`Close()` that finalizes once per process (XPKI-001..005). Support
`rsa.PSSSaltLengthAuto` and `*rsa.PKCS1v15DecryptOptions` (XPKI-009,
XPKI-015). Consider dropping the remaining cgo `unsafe` helpers in
`common.go` in favor of `encoding/binary`.

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
