// Package authority implements an in-process Certification Authority.
//
// LoadConfig reads issuers and certificate profiles from YAML or JSON,
// NewAuthority builds Issuer objects whose signers come from cryptoprov and
// whose chains are verified with certutil, and Issuer.Sign issues X.509
// certificates from PEM CSRs according to a named profile. Issuers also sign
// OCSP responses (directly or through a delegated responder) and NewRoot
// bootstraps a self-signed root.
package authority
