# xpki v0.29 release notes

v0.29 closes most of the 2026-09-20 audit (`FINDINGS.md`). This release
fixes a CSR extension bypass in `authority`, deadlocks, data races and panics
in `authority`, `crypto11`, `cryptoprov`, `certutil`, `jwt` and the KMS
providers, and adds opt-in hardening in `jwt/dpop` and `jwt`. Finding IDs
(`XPKI-NNN`) refer to the audit; their full records are in git history before
this release.

## Major fixes

### Security

- **authority** (XPKI-049, 050): `Issuer.Sign` no longer copies CSR
  extensions into the certificate. SKI, KU, SAN, BasicConstraints, AKI, EKU
  and OCSP no-check are always dropped from a CSR. Any other CSR extension
  must be listed in `allowed_extensions`; an empty list allows none. Each
  certificate has one extension per OID: profile `extensions` win over the
  `SignRequest`, and the `SignRequest` wins over the CSR.
- **authority** (XPKI-054): `SignRequest.NotBefore/NotAfter` must be inside
  the profile expiry and the backdate window, and an inverted range is
  rejected.
- **authority** (XPKI-057): a populated `allowed_profiles` now filters every
  profile, not only wildcard ones.
- **certutil** (XPKI-041): the system roots are no longer trusted implicitly
  when no roots are configured.
- **certutil** (XPKI-037, 039): AIA fetches check the status, limit the body
  size, honour a context and fetch each URL at most once per call.
- **certutil** (XPKI-121): `CreateOCSPRequest` checks that the issuer signed
  the certificate, not only that the names match.
- **jwt** (XPKI-070, 071, 072): `RemoteKeySet` has a timeout, a body limit and
  a refresh cooldown. A token without a `kid` is accepted only when one key is
  eligible. `PublicKeys` in the parser config are used.
- **jwt** (XPKI-112): a provider verifies only tokens with its own signing
  algorithm. The HS256 key ring of `NewProvider` no longer accepts HS384 or
  HS512 tokens signed with a ring key, and an RS256 provider no longer
  accepts RS384/RS512 tokens signed with its private key.
- **jwt** (XPKI-109): `Sign` writes `exp`, `iat` and `nbf` as NumericDate
  whatever their Go type, with the new `MapClaims.NormalizeTimeClaims`,
  which `jwt/accesstoken` uses too. Before, a `time.Time` was signed as an
  RFC 3339 string that `ParseToken` could not read, so the check was skipped
  and a token with `nbf` tomorrow was accepted today. `MapClaims.Time` now
  also reads RFC 3339 strings and `NumericDate` values, so such a claim in
  an existing token is validated instead of ignored, and rejects a `uint64`
  above `MaxInt64` instead of wrapping it to a negative time.
- **jwt/dpop** (XPKI-074, 075, 076): all advertised algorithms verify (with
  go-jose). There is an opt-in replay cache, `ath` and `cnf.jkt` binding, a
  trusted `ExternalURL`, and `htu` paths are compared case-sensitively.
- **jwt/dpop** (XPKI-108): the `htm` claim must equal the request method
  exactly, since HTTP methods are case-sensitive (RFC 9110 §9.1); a proof
  for `get` no longer verifies a `GET` request.
- **jwt/accesstoken** (XPKI-078): every new `pat.` token expires.

### Concurrency, deadlocks and panics

- **authority** (XPKI-051, 052, 053): `NewIssuer` no longer deadlocks with
  `aia.delegated_ocsp_profile`. The OCSP responder is published atomically.
  When responder renewal fails, `SignOCSP` keeps using a still-valid responder
  and otherwise returns an error; it never falls back to the CA key.
- **crypto11** (XPKI-001..007, 011): modules are reference-counted per library
  path and finalized on the last `Close`. Session pools are bounded per slot
  and created on demand, and `Init` releases everything on error.
  CK_ULONG decoding is checked. Token selection matches every configured
  selector.
- **cryptoprov** (XPKI-016, 026, 113): the provider registry is synchronized.
  Duplicate and nil providers are errors.
- **cryptoprov/inmemcrypto, testprov, testca** (XPKI-017, 062, 107): key maps
  and counters are synchronized.
- **cryptoprov/awskmscrypto** (XPKI-025, 031..034): `Sign` checks its
  options against the algorithms KMS reports for the key before any RPC, so
  nil options no longer panic. `GenerateRSAKey` rejects encryption keys
  (purpose 2) and unsupported sizes before creating anything, and `GetKey`
  returns an error for an `ENCRYPT_DECRYPT` key or a key pending deletion
  instead of a signer that cannot sign, and a key whose public key cannot
  be fetched after creation is scheduled for deletion. `EnumKeys` applies
  the prefix to the key label (the KMS description), describes keys 8 at a
  time with 1000-key pages, leaves out (and logs) keys the caller may not
  describe, and returns an error instead of a silently incomplete listing
  when a `DescribeKey` is throttled or fails otherwise. `Init` leaves
  credentials to the SDK default chain, which already reads the same
  environment variables first.
- **cryptoprov/gcpkmscrypto** (XPKI-018..025, 116..124): `Close` is safe with
  concurrent calls. Key versions are resolved instead of the hard-coded
  `cryptoKeyVersions/1`. `Sign` enforces the key's KMS algorithm. The
  `Endpoint` attribute is applied. Key ids are sanitized and get a 40-bit
  random suffix. Key generation polls the version state, and the wait ends on
  `Close`.
- **certutil** (XPKI-035, 036, 038, 042, 103, 115): `Bundler` is safe for
  concurrent use. Nil and empty inputs return errors instead of panicking.
  `SortBundlesByExpiration` no longer modifies its input. A wrong PKCS#8
  password is reported as `x509.IncorrectPasswordError`.
- **jwt** (XPKI-066, 104): `NewProviderWithSymmetricKey` verifies its own
  tokens, and `WithHeaders` no longer panics.
- **jwt** (XPKI-073): the JOSE header no longer carries a random `jti`,
  which RFC 7519 defines as a payload claim. `Sign` signs the caller's
  `jti` claim as given and does not generate one.
- **jwt/oauth2client** (XPKI-081): `Provider` is safe for concurrent use.
  `RegisterClient` publishes a registration to the provider, domain and
  email indexes at once, a rejected registration leaves the registry
  unchanged (before, the entries written before the conflict stayed), and
  an `override` removes the previous client of that provider id from every
  index (before, its other domains and emails kept resolving to it).
- **jwt/oauth2client** (XPKI-080): `Client` owns a deep copy of its
  `ClientConfig`, `Config()` returns a copy, and `SetClientSecret`,
  `SetPubKey` and `CreateTokenRequest` are synchronized. The key parsed from
  `PubKey` is returned by the new `PublicKey()`; `PubKey` and `JwksURL` are
  documented as settings for a caller's verifier, since this package verifies
  no tokens. `New(nil)` returns an error instead of panicking.
- **jwt/accesstoken** (XPKI-079): a nil data protection provider returns an
  error instead of panicking.

### Tests and tooling

- Integration tests use `internal/testenv`: they skip when SoftHSM or
  local-kms is unavailable, and fail when `XPKI_INTEGRATION=required`, which
  the Makefile sets. This is done for `authority`, `crypto11`, `jwt`,
  `cryptoprov`, `certutil` and `awskmscrypto`, whose unit tests now run
  against an in-memory fake KMS client.
- The SoftHSM setup script was hardened (XPKI-093). CLI test fixtures are
  isolated per run (XPKI-105).

## New features and behaviour

- `certutil`: `Bundler.BundleContext`, `ChainFromPEMContext`,
  `WithSystemRoots(bool)`, `ErrNoCertificates`, and decryption of
  `ENCRYPTED PRIVATE KEY` (PKCS#8, PBES2 with PBKDF2 and AES-CBC).
- `crypto11`: the `WithMaxSessions(n)` option for `Init`/`ConfigureFromFile`
  (default `DefaultMaxSessions` = 1024).
- `jwt`: `NewRemoteKeySet(url, opts...)` with `WithHTTPClient`,
  `WithRefreshCooldown`, `WithFetchTimeout` and `WithMaxResponseSize`, and
  `AlgorithmKeySet.GetKeyForAlgorithm`.
- `jwt/dpop`: the `VerifyConfig` fields `ReplayCache` (with
  `NewMemoryReplayCache`), `AccessToken`, `ExpectedThumbprint` and
  `ExternalURL`.
- `jwt/accesstoken`: `New(dp, provider, opts...)` with `WithTokenExpiry`,
  `WithAllowNoExpiry`, and the `TokenPrefix` constant.
- `jwt`: `MapClaims.NormalizeTimeClaims()`.
- `jwt/oauth2client`: `Client.PublicKey()`.
- `cryptoprov`: the `ErrNilProvider` and `ErrDuplicateProvider` errors.
- `awskmscrypto`: `Signer.SigningAlgorithms`, and `KeyInfo.Label` is set to
  the key description by `EnumKeys` and `KeyInfo`.
- `gcpkmscrypto`: key ids are `K` or `K/cryptoKeyVersions/N`. A bare id
  resolves to the newest enabled version for signing and lookup. Destroying a
  bare id destroys every enabled or disabled version.
- `certutil.HTTPClient` is deprecated (it was never read); use
  `WithHTTPClient`.

## Breaking changes: what clients must change

| Area | Change | Action |
| --- | --- | --- |
| go-jose | `github.com/go-jose/go-jose/v3` → `v4` (exposed by `jwt.ParserConfig.JWKeySet` and the `jwt/dpop` key functions) | Import `github.com/go-jose/go-jose/v4` |
| `crypto11` | `PKCS11Lib.Close()` returns `error` | Wrap a `func()` use, such as `t.Cleanup(func() { _ = lib.Close() })` |
| `crypto11` | A config with neither `TokenSerial` nor `TokenLabel` fails. When both are set, a token must match both | Set a selector that matches the token |
| `crypto11` | A malformed CKA_KEY_TYPE/CKA_CLASS fails `EnumKeys` | None, unless you relied on partial listings |
| `cryptoprov` | `Load` fails on two token configs with the same manufacturer and model, and on nil providers | Remove the duplicate configs |
| `gcpkmscrypto` | `KmsClientFactory` is `func(endpoint string) (KmsClient, error)` | Update custom factories |
| `gcpkmscrypto` | `Keyring` is required. Encryption keys (purpose 2) are rejected. A `Sign` whose hash or padding does not match the key's algorithm, nil opts, or `PSSSaltLengthAuto` fails before any RPC | Pass the key's hash; use `PSSSaltLengthEqualsHash` |
| `gcpkmscrypto` | Exported URIs carry the version in `id` (`K/cryptoKeyVersions/N`). An old `id=K` URI now resolves to the newest enabled version, not version 1 | Store the new URIs to pin a version |
| `awskmscrypto` | `GenerateRSAKey` purpose 2 and sizes other than 2048/3072/4096 are rejected; `GetKey` of an `ENCRYPT_DECRYPT` key or a key pending deletion fails. A `Sign` with nil opts, an unsupported hash, a wrong digest length, PSS options on an ECDSA key, a PSS salt other than the hash length (`PSSSaltLengthAuto` included), or an algorithm the key does not support fails before any RPC. `NewSigner` needs the key's KMS-reported `SigningAlgorithms`; with none, `Sign` fails | Pass the hash as `crypto.SignerOpts`; use `PSSSaltLengthEqualsHash` for PSS; pass `SigningAlgorithms` from `GetPublicKey` or `DescribeKey` to `NewSigner` |
| `awskmscrypto` | `EnumKeys` returns only the keys whose label starts with `prefix` (before, `prefix` was ignored), needs `kms:DescribeKey` on the listed keys (a key the caller may not describe is left out), and returns an error instead of a partial listing when a key cannot be described for another reason | Pass an empty prefix to list every signing key; treat the error as a failed listing |
| `authority` | A CSR extension that is not in `allowed_extensions` is rejected, or dropped with `omit_disabled_extensions`. `otherName` SANs from a CSR are no longer issued | Add the needed OIDs to the profile's `allowed_extensions` |
| `authority` | A `SignRequest` whose lifetime exceeds the profile expiry, for example `NotAfter = now + expiry` with the default backdate, is rejected | Send `NotAfter ≤ NotBefore + expiry` |
| `authority` | A populated `allowed_profiles` also filters wildcard profiles and must include the `delegated_ocsp_profile` | List every profile the issuer needs |
| `certutil` | `NewBundler(nil, …, WithBundleFlavor(Optimal))` fails without roots | Pass `WithSystemRoots(true)` or explicit roots |
| `certutil` | `Bundle` of an empty list returns `ErrNoCertificates` instead of `(nil, nil)`. `SortBundlesByExpiration` returns a sorted copy | Check the error, and use the return value |
| `jwt` | The error `key not found: <kid>` is now `kid="<kid>": key not found`. A kid-less token against several eligible keys fails. A key published less than 10s after a fetch is refused until the cooldown ends | Match errors with `errors.Is`, not text; tune `WithRefreshCooldown` |
| `jwt` | Constructors reject an `alg` header that differs from the signing algorithm, and HS providers reject a foreign `kid` | Remove conflicting headers |
| `jwt` | `ParseToken` accepts only the provider's own `alg` (`unsupported signing method`). A token from a `NewProvider` ring or a private key that was signed with another hash of the same key fails | Sign every token with the provider, or verify foreign algorithms with `jwt.NewParser` |
| `jwt` | The JOSE header has no `jti`; `Sign` fails on an `exp`, `iat` or `nbf` it cannot parse as a time, or that is a zero time, and signs a `time.Time` as NumericDate | Set the `jti` claim (`CreateClaims`) when a token id is needed; a reader of the header `jti` must read the claim instead |
| `jwt` | A string `exp`/`nbf`/`iat` in RFC 3339 form is validated. An existing token with such an expired `exp` or future `nbf` is now rejected | Reissue such tokens |
| `jwt/dpop` | `htm` must equal the request method exactly; a lowercase `htm` for a `GET` request is rejected | Sign proofs with the method as sent (Go's `http.Request.Method`) |
| `jwt/oauth2client` | `Client.Config()` returns a copy; changing it no longer changes the client, and `New` copies its argument. `New(nil)` is an error. `RegisterClient(cfg, true)` drops the previous client's other domains and emails. `Client` and `Provider` hold locks and must not be copied by value | Use `SetClientSecret`/`SetPubKey`, or register a new client, to change one; keep the pointers `New`/`NewProvider` return |
| `jwt/accesstoken` | `Sign` writes `exp`/`iat`/`nbf` as NumericDate and fails on a value it cannot parse or a zero time, with `invalid <claim> claim: <value>` (in v0.28 a `time.Time` was written as an RFC 3339 string that `ParseToken` did not check, so a zero `exp` never expired) | Pass parsable, non-zero times |
| `jwt/accesstoken` | Signing claims without `exp` fails unless `WithTokenExpiry` is set. Old tokens without `exp` are rejected unless `WithAllowNoExpiry` is set | Set `WithTokenExpiry(d)`; use `WithAllowNoExpiry()` only during migration |
| `jwt/dpop` | An `htu` path that differs only in case is rejected. A server that serves plain HTTP must set `ExternalURL`, since `https` stays the default scheme | Set `VerifyConfig.ExternalURL`; enable `ReplayCache` for replay safety |

## Still open

See [FINDINGS.md](../FINDINGS.md), [PLAN.md](../PLAN.md) and
[ROADMAP.md](../ROADMAP.md). Among the open items: `authority` registry
synchronization (XPKI-055), the 3072-bit RSA hash for GCP KMS
(XPKI-114), and CI lint wiring (XPKI-094, 095).
