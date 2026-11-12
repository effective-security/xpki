# Design documents

High-level design of the library packages: what each package is for, how
its parts fit together, which contracts it relies on and where it can be
extended. These documents answer "why is it built this way"; the
[code map](../codemap.md) answers "where is it" (concept → file → entry
points → invariants) and the generated [API reference](../api) answers
"what is the exact signature". Keep the three consistent: a design change
updates the design document and the code map in the same change.

| Document                               | Package(s)                                                                                                                                                                          |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [cryptoprov.md](cryptoprov.md)         | `cryptoprov` and the provider contract its backends implement                                                                                                                       |
| [crypto11.md](crypto11.md)             | `crypto11` (PKCS#11 provider)                                                                                                                                                       |
| [csr.md](csr.md)                       | `csr` (requests, key requests, CSR create and parse)                                                                                                                                |
| [authority.md](authority.md)           | `authority` (in-process CA)                                                                                                                                                         |
| [dataprotection.md](dataprotection.md) | `dataprotection` (AEAD protection of small payloads)                                                                                                                                |
| [pqc.md](pqc.md)                       | Cross-cutting: post-quantum signatures (ML-DSA, FIPS 204), with the code inventory that the [roadmap](../../ROADMAP.md) item and the [plan](../../PLAN.md) refer to                 |
| [keymanager.md](keymanager.md)         | Cross-cutting: the v2 `KeyManager` and `KeyGenerator` contract, what each provider does for a listing, the move to module `xpki/v2` and decisions K1 to K12 (roadmap item 12, v2.0) |

Conventions:

- Each package document has the same sections: purpose and position in the
  dependency graph, core abstractions, main flows, design decisions and
  their reasons, extension points, testing approach, and a
  "Post-quantum readiness" section that lists the places in the package
  where the key type is assumed. Finding IDs (`XPKI-NNN`) refer to
  [FINDINGS.md](../../FINDINGS.md) or, when fixed, to the release notes.
- Diagrams are Mermaid, as in [`authority/README.md`](../../authority/README.md).
- Facts about toolchains, SDKs and fixtures state the version they were
  checked against and the date, so that a reader can tell when to recheck.
