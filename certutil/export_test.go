package certutil

import "crypto/x509"

// MaxAIAResponseSize exposes the AIA response body limit to black-box tests.
const MaxAIAResponseSize = maxAIAResponseSize

// MaxPBKDF2Iterations exposes the encrypted PKCS#8 iteration limit.
const MaxPBKDF2Iterations = maxPBKDF2Iterations

// Learn exposes learn so tests can publish intermediates with a stale base.
func (b *Bundler) Learn(base, pool *x509.CertPool, certs []*x509.Certificate) {
	b.learn(base, pool, certs)
}

// ClearIntermediates clears the intermediate pool and the known issuers of
// b, a state only this package can produce.
func ClearIntermediates(b *Bundler) {
	b.intermediatePool = nil
	b.knownIssuers = nil
}

// ClearRoots clears the trust roots of b, a state only this package can
// produce.
func ClearRoots(b *Bundler) {
	b.rootPool = nil
}
