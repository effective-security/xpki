package testca

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"os"
	"sync"

	"github.com/effective-security/xpki/certutil"
)

// Entity is a certificate and private key.
// An Entity must not be copied after first use.
type Entity struct {
	Issuer      *Entity
	PrivateKey  crypto.Signer
	Certificate *x509.Certificate
	// NextSN is the serial number to allocate on the next IncrementSN call.
	// Read or write it directly only when no IncrementSN or Issue calls,
	// including NewEntity calls using this entity as Issuer, are in flight.
	NextSN int64

	serialMu sync.Mutex
}

// NewEntity creates a new CA.
func NewEntity(opts ...Option) *Entity {
	c := &configuration{}

	for _, opt := range opts {
		option(opt)(c)
	}

	return c.generate()
}

// Issue issues a new Entity with this one as its parent.
// Concurrent calls are safe if the issuer's fields and option data remain
// unchanged and its private key supports concurrent signing.
// The caller's option slice is not modified; this issuer takes precedence
// over any Issuer option in opts.
func (id *Entity) Issue(opts ...Option) *Entity {
	options := make([]Option, len(opts)+1)
	copy(options, opts)
	options[len(opts)] = Issuer(id)
	return NewEntity(options...)
}

// PFX wraps the certificate and private key in an encrypted PKCS#12 packet. The
// provided password must be alphanumeric.
func (id *Entity) PFX(password string) []byte {
	return ToPFX(id.Certificate, id.PrivateKey, password)
}

// Chain builds a slice of *x509.Certificate from this CA and its issuers.
func (id *Entity) Chain() []*x509.Certificate {
	chain := []*x509.Certificate{}
	for this := id; this != nil; this = this.Issuer {
		chain = append(chain, this.Certificate)
	}

	return chain
}

// ChainPool builds an *x509.CertPool from this CA and its issuers.
func (id *Entity) ChainPool() *x509.CertPool {
	chain := x509.NewCertPool()
	for this := id; this != nil; this = this.Issuer {
		chain.AddCert(this.Certificate)
	}

	return chain
}

// IncrementSN returns the current NextSN and increments it atomically with
// respect to other IncrementSN calls on this entity.
func (id *Entity) IncrementSN() int64 {
	id.serialMu.Lock()
	defer id.serialMu.Unlock()

	sn := id.NextSN
	id.NextSN++
	return sn
}

// Root returns root CA for this entity.
func (id *Entity) Root() *x509.Certificate {
	var root *Entity
	for root = id; root.Issuer != nil; root = root.Issuer {
	}

	return root.Certificate
}

// KeyAndCertChain provides PrivateKey and its certificates chain
type KeyAndCertChain struct {
	PrivateKey  crypto.Signer
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
	Root        *x509.Certificate
}

// KeyAndCertChain returns chain for the PrivateKey
func (id *Entity) KeyAndCertChain() *KeyAndCertChain {
	s := &KeyAndCertChain{
		PrivateKey:  id.PrivateKey,
		Certificate: id.Certificate,
		Chain:       []*x509.Certificate{},
		Root:        id.Root(),
	}

	for issuer := id.Issuer; issuer != nil && !bytes.Equal(issuer.Certificate.Raw, s.Root.Raw); issuer = issuer.Issuer {
		s.Chain = append(s.Chain, issuer.Certificate)
	}

	return s
}

// SaveCertAndKey stores the cert and key to provided locations
// withChain specifies to store entire chain up to the root in cert's pem file
func (id *Entity) SaveCertAndKey(certFile string, keyFile string, withChain bool) (err error) {
	if keyFile != "" {
		err = os.WriteFile(keyFile, PrivKeyToPEM(id.PrivateKey), 0600)
		if err != nil {
			return err
		}
	}
	if certFile != "" {
		fcert, err := os.Create(certFile)
		if err != nil {
			return err
		}

		certs := []*x509.Certificate{
			id.Certificate,
		}
		if withChain {
			certs = append(certs, id.KeyAndCertChain().Chain...)
		}

		_ = certutil.EncodeToPEM(fcert, true, certs...)

		_ = fcert.Close()
	}
	return nil
}
