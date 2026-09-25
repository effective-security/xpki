# authority package

In-process Certification Authority: configuration and profiles, issuers,
certificate signing (`Issuer.Sign`), OCSP signing and root bootstrap. See
[`Documentation/api/authority.md`](../Documentation/api/authority.md) for the
API and [`Documentation/codemap.md`](../Documentation/codemap.md) for
invariants.

## Configuration flow

```mermaid
flowchart LR
    cfg["ca-config.yaml / .json"] -->|LoadConfig| C[Config]
    C -->|"issuerHasProfile: profile → issuer"| IC["IssuerConfig.Profiles"]
    C -->|Validate| P["CertProfile.Validate: expiry, usages, regexes, extension OIDs"]
    IC -->|"NewAuthority → NewIssuerWithBundles"| I[Issuer]
    I -->|"signer from cryptoprov, chain from certutil"| I
    I -->|"AddIssuer"| A["Authority: by label, profile, SKID, key/name hash"]
    I -->|"CreateDelegatedOCSPSigner"| R[OCSP responder]
```

A profile attaches to an issuer as follows (`issuerHasProfile`):

| Profile `issuer_label` | Issuer `allowed_profiles` empty | Issuer `allowed_profiles` populated |
| ---------------------- | ------------------------------- | ----------------------------------- |
| the issuer's label     | attached                        | attached only if listed             |
| `"*"` (wildcard)       | not attached                    | attached only if listed             |
| another label          | not attached                    | not attached                        |

With a single issuer, profiles without `issuer_label` take that issuer's label.
A populated `allowed_profiles` must include the issuer's
`aia.delegated_ocsp_profile`, otherwise `LoadConfig` fails.

## OCSP responder

Without `aia.delegated_ocsp_profile`, `SignOCSP` signs with the CA key.
With it, the issuer signs responses with a delegated responder: an in-memory
P-256 key and a certificate issued by `Sign` with that profile. The profile
needs the `ocsp signing` usage; `ocsp_no_check` keeps AIA and CRL URLs out of
the certificate.

- The profile must exist, must not be a CA profile, its extended key usage
  must include OCSP signing, and its `expiry` must exceed `aia.ocsp_expiry`
  plus the profile `backdate` (default 5m) plus 1m, because NotBefore is
  backdated from the current minute; otherwise `NewIssuer`/`CreateIssuer`
  fails. A raw EKU in the profile's `extensions`
  overrides `usages`, so it is decoded and must list `id-kp-OCSPSigning`.
  The profile is checked again before each issuance, so replacing it with
  `AddProfile` cannot produce an invalid responder: that renewal fails.
- `NewIssuer` issues the first responder and fails if it cannot.
- A responder is renewed when it expires within `aia.ocsp_expiry`. One
  caller renews; callers that hold a still-valid responder keep using it
  instead of waiting.
- If renewal fails, `SignOCSP` logs the error and keeps using the cached
  responder while it is still valid when the attempt ends, retrying at most
  once a minute after that. With no valid
  responder it returns an error; it never falls back to the CA key. Callers
  that were waiting for a failed attempt share its error instead of retrying
  one after another. `CreateDelegatedOCSPSigner` waits for a renewal in
  progress and returns the last renewal error while renewal is overdue.
- When the CA expires within `aia.ocsp_expiry`, each responder is capped at
  the CA's `NotAfter` and re-issued at most once a minute.
- A delegated response's `NextUpdate` is capped at the responder's
  `NotAfter`, and a `ThisUpdate` at or after it is rejected.

## Signing pipeline

`Issuer.Sign(csr.SignRequest)` treats the **SignRequest** as coming from a
trusted registration authority (RA) and the **CSR** as untrusted.

```mermaid
flowchart TD
    S["SignRequest (trusted RA)"] --> P{"profile lookup (default)"}
    P --> CSR["csr.ParsePEM: verify CSR signature"]
    CSR --> F["copy CSR fields permitted by allowed_fields (nil = subject + all SANs)"]
    F --> N["merge RA Subject; check allowed_names / dns / email / uri regexes"]
    N --> E1["add profile extensions (a repeated OID fails)"]
    E1 --> E2["add RA extensions: allow-list, empty = all; skip OIDs already set"]
    E2 --> E3["filter CSR extensions: drop profile-owned OIDs; others need allow-list"]
    E3 --> SAN["RA SAN, if set, replaces SANs"]
    SAN --> T["fillTemplate: validity window, KU/EKU, CA constraints, SKI, AIA/CRL/OCSP URLs, policies, OCSP no-check"]
    T --> E4["append accepted CSR extensions not already produced"]
    E4 --> X["clip NotAfter to the issuer NotAfter, then x509.CreateCertificate"]
```

`x509.CreateCertificate` lets `ExtraExtensions` override the extensions it
would build from template fields (KU, EKU, basic constraints, SKI/AKI, SAN,
AIA, CRL DP). A kept raw extension for one of those OIDs, whether from the
profile `extensions` or an allow-listed SignRequest, therefore replaces the
value derived from the profile. The CSR rules below exist for that reason.

### Where each extension comes from

| Extension                                             | Profile                                    | SignRequest (trusted)             | CSR (untrusted)                                                   |
| ----------------------------------------------------- | ------------------------------------------ | --------------------------------- | ----------------------------------------------------------------- |
| Key usage `2.5.29.15`, EKU `2.5.29.37`                | `usages` (or raw `extensions`)             | if allow-listed; overrides        | never                                                             |
| Basic constraints `2.5.29.19`                         | `ca_constraint`                            | if allow-listed; overrides        | never (also stripped by `csr.Parse`)                              |
| SKI `2.5.29.14`, AKI `2.5.29.35`                      | computed from the keys                     | if allow-listed; overrides        | never                                                             |
| SAN `2.5.29.17`                                       | built from permitted names                 | `SAN` field or allow-listed raw   | never as raw; names via `allowed_fields` and regexes              |
| OCSP no-check `1.3.6.1.5.5.7.48.1.5`                  | `ocsp_no_check` (wins)                     | if allow-listed                   | never                                                             |
| Certificate policies `2.5.29.32`                      | `policies` (wins)                          | if allow-listed                   | if allow-listed and neither the profile nor the SignRequest sets it |
| AIA `1.3.6.1.5.5.7.1.1`, CRL DP `2.5.29.31`           | issuer `aia` URLs                          | if allow-listed; overrides        | if allow-listed and the issuer generates none                     |
| any other OID                                         | raw `extensions` (wins)                    | if allow-listed                   | if allow-listed                                                   |

- **Allow-list.** `allowed_extensions` empty: all SignRequest extensions are
  allowed and no CSR extensions are. A disallowed extension fails the request.
  With the issuer's `omit_disabled_extensions`, it is dropped instead.
- **Profile-owned OIDs.** "never" rows are dropped silently from the CSR even
  when allow-listed.
- **Precedence per OID.** The issued certificate has exactly one extension per
  OID. Raw extensions are kept in the order profile `extensions`, SignRequest,
  CSR; the first one for an OID wins. Profile `policies` and `ocsp_no_check`
  then replace any raw copy. For the other template-built OIDs a kept raw
  extension overrides the profile-derived value, as the table shows.

### Validity

| Request                  | Result                                                                  |
| ------------------------ | ----------------------------------------------------------------------- |
| no times                 | NotBefore = now (rounded to a minute) − `backdate` (default 5m); NotAfter = NotBefore + `expiry` |
| explicit NotBefore       | must be ≥ now − `backdate`; a future NotBefore is allowed              |
| explicit NotAfter        | must be after NotBefore, and NotAfter − NotBefore ≤ `expiry`            |
| beyond the issuer        | NotAfter is clipped to the issuer NotAfter; fails if nothing remains   |

Invalid windows are rejected, never adjusted. A profile without `expiry`
(only possible when added without `Validate`) needs an explicit NotAfter and
has no lifetime bound.
