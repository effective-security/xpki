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
